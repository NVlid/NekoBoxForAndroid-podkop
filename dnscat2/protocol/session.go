package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var ErrPacketDiscarded = errors.New("dnscat2: packet discarded")

type sessionRole bool

const (
	roleClient sessionRole = true
	roleServer sessionRole = false
)

type sessionState uint8

const (
	stateBeforeInit sessionState = iota
	stateBeforeAuth
	stateNew
	stateEstablished
	stateClosed
)

type ReceiveResult struct {
	// Response is set for a server and must be returned in the DNS answer.
	Response []byte
	// Incoming is ordered application data from a validated MSG packet.
	Incoming []byte
	// Immediate asks a client to send the next poll without the idle delay.
	Immediate bool
}

type Session struct {
	mu sync.Mutex

	role        sessionRole
	id          uint16
	state       sessionState
	secret      string
	mySeq       uint16
	theirSeq    uint16
	options     uint16
	closing     bool
	closeReason string

	encryptor     *Encryptor
	pending       *Encryptor
	previous      *Encryptor
	packetID      uint32
	authenticated bool
	outgoing      []byte
	synRequest    *SYN
}

func NewClientSession(secret string) (*Session, error) {
	id, err := randomUint16()
	if err != nil {
		return nil, err
	}
	sequence, err := randomUint16()
	if err != nil {
		return nil, err
	}
	encryptor, err := NewClientEncryptor(secret)
	if err != nil {
		return nil, err
	}
	packetID, err := randomUint16()
	if err != nil {
		return nil, err
	}
	return &Session{
		role: roleClient, id: id, state: stateBeforeInit, secret: secret,
		mySeq: sequence, encryptor: encryptor, packetID: uint32(packetID),
	}, nil
}

func NewServerSession(id uint16, secret string) (*Session, error) {
	sequence, err := randomUint16()
	if err != nil {
		return nil, err
	}
	encryptor, err := NewServerEncryptor(secret)
	if err != nil {
		return nil, err
	}
	packetID, err := randomUint16()
	if err != nil {
		return nil, err
	}
	return &Session{
		role: roleServer, id: id, state: stateNew, secret: secret,
		mySeq: sequence, encryptor: encryptor, packetID: uint32(packetID),
	}, nil
}

func (s *Session) ID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *Session) Established() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateEstablished
}

func (s *Session) Authenticated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authenticated
}

func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateClosed
}

func (s *Session) Buffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outgoing)
}

func (s *Session) Queue(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateClosed {
		s.outgoing = append(s.outgoing, data...)
	}
}

func (s *Session) Close(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateClosed {
		s.closing = true
		s.closeReason = reason
	}
}

func (s *Session) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = stateClosed
	s.outgoing = nil
}

func (s *Session) NextPacket(maxPayload int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stateClosed {
		return nil, errors.New("dnscat2: session is closed")
	}
	if s.role == roleServer && s.state != stateEstablished {
		return nil, nil
	}
	packet, cipher, err := s.nextPacketLocked(maxPayload)
	if err != nil || packet == nil {
		return nil, err
	}
	return marshalAndSeal(packet, cipher)
}

func (s *Session) Receive(data []byte, maxPayload int) (*ReceiveResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stateClosed {
		return nil, ErrPacketDiscarded
	}
	plaintext, cipher, err := s.openLocked(data)
	if err != nil {
		return nil, err
	}
	packet, err := ParsePacket(plaintext)
	if err != nil || packet.SessionID != s.id {
		return nil, ErrPacketDiscarded
	}
	result := &ReceiveResult{}
	if s.role == roleClient {
		result.Immediate, result.Incoming, err = s.receiveClientLocked(packet)
		return result, err
	}
	response, incoming, err := s.receiveServerLocked(packet, maxPayload, cipher)
	if err != nil {
		if errors.Is(err, ErrPacketDiscarded) {
			return nil, err
		}
		s.state = stateClosed
		fin := &Packet{ID: s.nextPacketIDLocked(), Type: PacketFIN, SessionID: s.id, FIN: &FIN{Reason: err.Error()}}
		response, _ = marshalAndSeal(fin, cipher)
		return &ReceiveResult{Response: response}, nil
	}
	result.Response, result.Incoming = response, incoming
	return result, nil
}

func (s *Session) nextPacketLocked(maxPayload int) (*Packet, *Encryptor, error) {
	if s.state == stateBeforeInit {
		return &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
			ENC: &ENC{Subtype: ENCInit, PublicKey: s.encryptor.PublicKey()},
		}, nil, nil
	}
	if s.state == stateBeforeAuth {
		return &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
			ENC: &ENC{Subtype: ENCAuth, Authenticator: s.encryptor.Authenticator()},
		}, s.encryptor, nil
	}
	if s.state == stateNew {
		options := uint16(OptCommand)
		name := "NekoBox"
		return &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketSYN, SessionID: s.id,
			SYN: &SYN{Sequence: s.mySeq, Options: options | OptName, Name: name},
		}, s.encryptor, nil
	}
	if s.state != stateEstablished {
		return nil, nil, ErrPacketDiscarded
	}
	if s.encryptor.ShouldRenegotiate() && s.role == roleClient {
		if s.pending == nil {
			pending, err := NewClientEncryptor(s.secret)
			if err != nil {
				return nil, nil, err
			}
			s.pending = pending
		}
		return &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
			ENC: &ENC{Subtype: ENCInit, PublicKey: s.pending.PublicKey()},
		}, s.encryptor, nil
	}
	return s.nextMessageLocked(maxPayload)
}

func (s *Session) nextMessageLocked(maxPayload int) (*Packet, *Encryptor, error) {
	overhead := 9 // MSG header plus SEQ/ACK.
	if s.encryptor.Ready() {
		overhead += signatureSize + nonceSize
	}
	if maxPayload <= overhead {
		return nil, nil, fmt.Errorf("dnscat2: DNS payload limit %d is too small", maxPayload)
	}
	if s.closing && len(s.outgoing) == 0 {
		reason := s.closeReason
		if reason == "" {
			reason = "Stream closed"
		}
		return &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketFIN, SessionID: s.id,
			FIN: &FIN{Reason: reason},
		}, s.encryptor, nil
	}
	length := min(len(s.outgoing), maxPayload-overhead)
	data := append([]byte(nil), s.outgoing[:length]...)
	return &Packet{
		ID: s.nextPacketIDLocked(), Type: PacketMSG, SessionID: s.id,
		MSG: &MSG{Sequence: s.mySeq, Ack: s.theirSeq, Data: data},
	}, s.encryptor, nil
}

func (s *Session) receiveClientLocked(packet *Packet) (bool, []byte, error) {
	if packet.Type == PacketFIN {
		s.state = stateClosed
		return false, nil, errors.New("dnscat2: server closed session: " + packet.FIN.Reason)
	}
	switch s.state {
	case stateBeforeInit:
		if packet.Type != PacketENC || packet.ENC.Subtype != ENCInit {
			return false, nil, ErrPacketDiscarded
		}
		if err := s.encryptor.SetPeerPublicKey(packet.ENC.PublicKey); err != nil {
			return false, nil, err
		}
		if s.secret == "" {
			s.state = stateNew
		} else {
			s.state = stateBeforeAuth
		}
		return true, nil, nil
	case stateBeforeAuth:
		if packet.Type != PacketENC || packet.ENC.Subtype != ENCAuth || !s.encryptor.VerifyPeerAuthenticator(packet.ENC.Authenticator) {
			return false, nil, errors.New("dnscat2: server authentication failed")
		}
		s.authenticated = true
		s.state = stateNew
		return true, nil, nil
	case stateNew:
		if packet.Type != PacketSYN {
			return false, nil, ErrPacketDiscarded
		}
		s.theirSeq = packet.SYN.Sequence
		s.options = packet.SYN.Options
		s.state = stateEstablished
		return true, nil, nil
	case stateEstablished:
		switch packet.Type {
		case PacketMSG:
			return s.receiveMSGLocked(packet)
		case PacketENC:
			if s.pending == nil || packet.ENC.Subtype != ENCInit {
				return false, nil, ErrPacketDiscarded
			}
			if err := s.pending.SetPeerPublicKey(packet.ENC.PublicKey); err != nil {
				return false, nil, err
			}
			s.encryptor = s.pending
			s.pending = nil
			if s.secret != "" {
				s.authenticated = true
			}
			return true, nil, nil
		case PacketFIN:
			s.state = stateClosed
			return false, nil, errors.New("dnscat2: server closed session: " + packet.FIN.Reason)
		}
	}
	return false, nil, ErrPacketDiscarded
}

func (s *Session) receiveServerLocked(packet *Packet, maxPayload int, cipher *Encryptor) ([]byte, []byte, error) {
	if packet.Type == PacketENC && packet.ENC.Subtype == ENCInit {
		if s.state == stateEstablished {
			if cipher != nil && cipher == s.previous && bytes.Equal(packet.ENC.PublicKey, s.encryptor.peerKey) {
				response := &Packet{
					ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
					ENC: &ENC{Subtype: ENCInit, PublicKey: s.encryptor.PublicKey()},
				}
				encoded, err := marshalAndSeal(response, cipher)
				return encoded, nil, err
			}
			pending, err := NewServerEncryptor(s.secret)
			if err != nil {
				return nil, nil, err
			}
			if err := pending.SetPeerPublicKey(packet.ENC.PublicKey); err != nil {
				return nil, nil, err
			}
			response := &Packet{
				ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
				ENC: &ENC{Subtype: ENCInit, PublicKey: pending.PublicKey()},
			}
			encoded, err := marshalAndSeal(response, cipher)
			if err != nil {
				return nil, nil, err
			}
			s.previous = s.encryptor
			s.pending = nil
			s.encryptor = pending
			return encoded, nil, nil
		}
		if s.encryptor.Ready() {
			if !bytes.Equal(s.encryptor.peerKey, packet.ENC.PublicKey) {
				return nil, nil, ErrPacketDiscarded
			}
		} else {
			if err := s.encryptor.SetPeerPublicKey(packet.ENC.PublicKey); err != nil {
				return nil, nil, err
			}
		}
		response := &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
			ENC: &ENC{Subtype: ENCInit, PublicKey: s.encryptor.PublicKey()},
		}
		encoded, err := marshalAndSeal(response, nil)
		return encoded, nil, err
	}
	if s.secret != "" && !s.authenticated && !(packet.Type == PacketENC && packet.ENC.Subtype == ENCAuth) {
		return nil, nil, errors.New("dnscat2: authenticated session required")
	}
	if packet.Type == PacketENC && packet.ENC.Subtype == ENCAuth {
		if s.state != stateNew || !s.encryptor.VerifyPeerAuthenticator(packet.ENC.Authenticator) {
			return nil, nil, errors.New("dnscat2: client authentication failed")
		}
		s.authenticated = true
		response := &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketENC, SessionID: s.id,
			ENC: &ENC{Subtype: ENCAuth, Authenticator: s.encryptor.Authenticator()},
		}
		encoded, err := marshalAndSeal(response, cipher)
		return encoded, nil, err
	}
	switch packet.Type {
	case PacketSYN:
		if s.state == stateEstablished && s.synRequest != nil && *packet.SYN == *s.synRequest {
			response := &Packet{ID: s.nextPacketIDLocked(), Type: PacketSYN, SessionID: s.id, SYN: &SYN{Sequence: s.mySeq}}
			encoded, err := marshalAndSeal(response, cipher)
			return encoded, nil, err
		}
		if s.state != stateNew {
			return nil, nil, ErrPacketDiscarded
		}
		if packet.SYN.Options&OptCommand == 0 {
			return nil, nil, errors.New("dnscat2: companion requires a command session")
		}
		s.theirSeq = packet.SYN.Sequence
		request := *packet.SYN
		s.synRequest = &request
		s.options = 0 // Match the upstream server response.
		s.state = stateEstablished
		response := &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketSYN, SessionID: s.id,
			SYN: &SYN{Sequence: s.mySeq},
		}
		encoded, err := marshalAndSeal(response, cipher)
		return encoded, nil, err
	case PacketMSG:
		if s.state != stateEstablished {
			return nil, nil, ErrPacketDiscarded
		}
		_, incoming, err := s.receiveMSGLocked(packet)
		s.synRequest = nil
		if err != nil && !errors.Is(err, ErrPacketDiscarded) {
			return nil, nil, err
		}
		response, _, err := s.nextMessageLocked(maxPayload)
		if err != nil {
			return nil, nil, err
		}
		encoded, err := marshalAndSeal(response, cipher)
		return encoded, incoming, err
	case PacketFIN:
		s.state = stateClosed
		response := &Packet{
			ID: s.nextPacketIDLocked(), Type: PacketFIN, SessionID: s.id,
			FIN: &FIN{Reason: "Session closed"},
		}
		encoded, err := marshalAndSeal(response, cipher)
		return encoded, nil, err
	}
	return nil, nil, ErrPacketDiscarded
}

func (s *Session) receiveMSGLocked(packet *Packet) (bool, []byte, error) {
	if packet.MSG.Sequence != s.theirSeq {
		return false, nil, ErrPacketDiscarded
	}
	acknowledged := uint16(packet.MSG.Ack - s.mySeq)
	if int(acknowledged) > len(s.outgoing) {
		return false, nil, ErrPacketDiscarded
	}
	if acknowledged > 0 {
		s.outgoing = append([]byte(nil), s.outgoing[acknowledged:]...)
		s.mySeq += acknowledged
	}
	incoming := append([]byte(nil), packet.MSG.Data...)
	s.theirSeq += uint16(len(packet.MSG.Data))
	return len(incoming) > 0 || acknowledged > 0, incoming, nil
}

func (s *Session) openLocked(data []byte) ([]byte, *Encryptor, error) {
	if s.role == roleClient && s.state == stateBeforeInit {
		return data, nil, nil
	}
	if s.role == roleServer && s.state == stateNew && isPlaintextENCInit(data) {
		return data, nil, nil
	}
	if !s.encryptor.Ready() {
		return nil, nil, ErrPacketDiscarded
	}
	plaintext, err := s.encryptor.Open(data)
	if err == nil {
		if s.role == roleServer && s.previous != nil {
			s.previous = nil
		}
		return plaintext, s.encryptor, nil
	}
	if s.role == roleServer && s.previous != nil && errors.Is(err, ErrInvalidSignature) {
		plaintext, oldErr := s.previous.Open(data)
		if oldErr == nil {
			return plaintext, s.previous, nil
		}
	}
	return nil, nil, ErrPacketDiscarded
}

func isPlaintextENCInit(data []byte) bool {
	return len(data) == 73 && data[2] == PacketENC && binary.BigEndian.Uint16(data[5:7]) == ENCInit
}

func (s *Session) nextPacketIDLocked() uint16 {
	s.packetID++
	return uint16(s.packetID)
}

func marshalAndSeal(packet *Packet, cipher *Encryptor) ([]byte, error) {
	encoded, err := packet.MarshalBinary()
	if err != nil || cipher == nil {
		return encoded, err
	}
	return cipher.Seal(encoded)
}

func randomUint16() (uint16, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value[:]), nil
}
