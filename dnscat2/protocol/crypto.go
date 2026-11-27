package protocol

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/sha3"
)

const (
	signatureSize = 6
	nonceSize     = 2
)

var (
	ErrInvalidSignature = errors.New("dnscat2: invalid packet signature")
	ErrNonceReplay      = errors.New("dnscat2: repeated or old packet nonce")
	ErrRekeyRequired    = errors.New("dnscat2: encryption nonce space exhausted")
)

// Encryptor implements the original dnscat2 P-256, SHA3-256 and Salsa20
// construction. A client and a server derive opposite read/write keys.
type Encryptor struct {
	isClient bool
	secret   string

	privateKey *ecdh.PrivateKey
	publicKey  []byte
	peerKey    []byte

	sharedSecret      [32]byte
	writeKey          [32]byte
	writeMACKey       [32]byte
	readKey           [32]byte
	readMACKey        [32]byte
	authenticator     [32]byte
	peerAuthenticator [32]byte

	nextNonce     uint32
	lastReadNonce uint16
	hasReadNonce  bool
}

func NewClientEncryptor(secret string) (*Encryptor, error) {
	return newEncryptor(true, secret)
}

func NewServerEncryptor(secret string) (*Encryptor, error) {
	return newEncryptor(false, secret)
}

func newEncryptor(isClient bool, secret string) (*Encryptor, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("dnscat2: generate P-256 key: %w", err)
	}
	return &Encryptor{
		isClient:   isClient,
		secret:     secret,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey().Bytes()[1:],
	}, nil
}

func (e *Encryptor) PublicKey() []byte {
	return append([]byte(nil), e.publicKey...)
}

func (e *Encryptor) Ready() bool {
	return e.privateKey != nil && len(e.peerKey) == 64
}

func (e *Encryptor) SetPeerPublicKey(peer []byte) error {
	if len(peer) != 64 {
		return errors.New("dnscat2: peer P-256 key must be 64 bytes")
	}
	peer = append([]byte(nil), peer...)
	peerKey, err := ecdh.P256().NewPublicKey(append([]byte{4}, peer...))
	if err != nil {
		return fmt.Errorf("dnscat2: invalid peer P-256 key: %w", err)
	}
	shared, err := e.privateKey.ECDH(peerKey)
	if err != nil {
		return fmt.Errorf("dnscat2: ECDH: %w", err)
	}
	if len(shared) != 32 {
		return errors.New("dnscat2: unexpected ECDH result size")
	}
	copy(e.sharedSecret[:], shared)
	e.peerKey = peer

	clientPublic, serverPublic := e.publicKey, e.peerKey
	if !e.isClient {
		clientPublic, serverPublic = e.peerKey, e.publicKey
	}
	clientWrite := deriveKey(e.sharedSecret, "client_write_key")
	clientMAC := deriveKey(e.sharedSecret, "client_mac_key")
	serverWrite := deriveKey(e.sharedSecret, "server_write_key")
	serverMAC := deriveKey(e.sharedSecret, "server_mac_key")
	if e.isClient {
		e.writeKey, e.writeMACKey = clientWrite, clientMAC
		e.readKey, e.readMACKey = serverWrite, serverMAC
	} else {
		e.writeKey, e.writeMACKey = serverWrite, serverMAC
		e.readKey, e.readMACKey = clientWrite, clientMAC
	}
	e.authenticator = deriveAuthenticator(e.roleName(), e.sharedSecret, clientPublic, serverPublic, e.secret)
	e.peerAuthenticator = deriveAuthenticator(e.peerRoleName(), e.sharedSecret, clientPublic, serverPublic, e.secret)
	e.nextNonce = 0
	e.hasReadNonce = false
	return nil
}

func (e *Encryptor) Authenticator() []byte {
	return append([]byte(nil), e.authenticator[:]...)
}

func (e *Encryptor) VerifyPeerAuthenticator(value []byte) bool {
	return len(value) == 32 && hmac.Equal(value, e.peerAuthenticator[:])
}

func (e *Encryptor) ShouldRenegotiate() bool {
	return e.nextNonce > 0xfff0
}

func (e *Encryptor) Seal(packet []byte) ([]byte, error) {
	if !e.Ready() {
		return nil, errors.New("dnscat2: encryption is not negotiated")
	}
	if len(packet) < PacketHeaderSize {
		return nil, ioShortPacket()
	}
	if e.nextNonce > 0xffff {
		return nil, ErrRekeyRequired
	}
	nonce := uint16(e.nextNonce)
	e.nextNonce++
	var nonceBytes [8]byte
	binary.BigEndian.PutUint16(nonceBytes[6:], nonce)
	encrypted := make([]byte, len(packet)-PacketHeaderSize)
	salsa20.XORKeyStream(encrypted, packet[PacketHeaderSize:], nonceBytes[:], &e.writeKey)

	result := make([]byte, 0, len(packet)+signatureSize+nonceSize)
	result = append(result, packet[:PacketHeaderSize]...)
	result = append(result, 0, 0, 0, 0, 0, 0)
	result = binary.BigEndian.AppendUint16(result, nonce)
	result = append(result, encrypted...)
	signature := packetMAC(e.writeMACKey, result[:PacketHeaderSize], result[PacketHeaderSize+signatureSize:])
	copy(result[PacketHeaderSize:PacketHeaderSize+signatureSize], signature)
	return result, nil
}

func (e *Encryptor) Open(packet []byte) ([]byte, error) {
	if !e.Ready() {
		return nil, errors.New("dnscat2: encryption is not negotiated")
	}
	if len(packet) < PacketHeaderSize+signatureSize+nonceSize {
		return nil, ioShortPacket()
	}
	header := packet[:PacketHeaderSize]
	signature := packet[PacketHeaderSize : PacketHeaderSize+signatureSize]
	signedBody := packet[PacketHeaderSize+signatureSize:]
	expected := packetMAC(e.readMACKey, header, signedBody)
	if !hmac.Equal(signature, expected) {
		return nil, ErrInvalidSignature
	}
	nonce := binary.BigEndian.Uint16(packet[PacketHeaderSize+signatureSize : PacketHeaderSize+signatureSize+nonceSize])
	if e.hasReadNonce && nonce <= e.lastReadNonce {
		return nil, ErrNonceReplay
	}
	var nonceBytes [8]byte
	binary.BigEndian.PutUint16(nonceBytes[6:], nonce)
	encrypted := packet[PacketHeaderSize+signatureSize+nonceSize:]
	decrypted := make([]byte, len(encrypted))
	salsa20.XORKeyStream(decrypted, encrypted, nonceBytes[:], &e.readKey)
	result := make([]byte, 0, PacketHeaderSize+len(decrypted))
	result = append(result, header...)
	result = append(result, decrypted...)
	e.lastReadNonce = nonce
	e.hasReadNonce = true
	return result, nil
}

func (e *Encryptor) roleName() string {
	if e.isClient {
		return "client"
	}
	return "server"
}

func (e *Encryptor) peerRoleName() string {
	if e.isClient {
		return "server"
	}
	return "client"
}

func deriveKey(shared [32]byte, name string) [32]byte {
	hash := sha3.New256()
	hash.Write(shared[:])
	hash.Write([]byte(name))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func deriveAuthenticator(role string, shared [32]byte, clientPublic, serverPublic []byte, secret string) [32]byte {
	hash := sha3.New256()
	hash.Write([]byte(role))
	hash.Write(shared[:])
	hash.Write(clientPublic)
	hash.Write(serverPublic)
	hash.Write([]byte(secret))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func packetMAC(key [32]byte, header, body []byte) []byte {
	hash := sha3.New256()
	hash.Write(key[:])
	hash.Write(header)
	hash.Write(body)
	return hash.Sum(nil)[:signatureSize]
}

func ioShortPacket() error {
	return errors.New("dnscat2: short encrypted packet")
}
