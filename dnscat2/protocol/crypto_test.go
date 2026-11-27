package protocol

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestOfficialECDHAndKeyVectors(t *testing.T) {
	alicePrivate, err := ecdh.P256().NewPrivateKey(mustHex(t, "7997cdc9af9690c78e58468c6a5f273b4c22a8a6e6a0e4be32e81d17c78a3f8b"))
	if err != nil {
		t.Fatal(err)
	}
	bobPrivate, err := ecdh.P256().NewPrivateKey(mustHex(t, "612b7bb5b84cdb200e4108d6ca52bc4fad94cd04fa8711227e17a268d16a7b85"))
	if err != nil {
		t.Fatal(err)
	}
	alice := &Encryptor{isClient: true, privateKey: alicePrivate, publicKey: alicePrivate.PublicKey().Bytes()[1:]}
	bob := &Encryptor{privateKey: bobPrivate, publicKey: bobPrivate.PublicKey().Bytes()[1:]}
	if got := hex.EncodeToString(alice.publicKey[:32]); got != "a651dedcb8833d574628bbb7b2fa2e63f3ac528aca48d38901955b6c76515c80" {
		t.Fatalf("Alice public X: %s", got)
	}
	if err := alice.SetPeerPublicKey(bob.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := bob.SetPeerPublicKey(alice.publicKey); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(alice.sharedSecret[:]); got != "6db2c22f7b0fd8921a15cf22bcbecfe84da0a852075f2707b2a24e19d9f4a6cf" {
		t.Fatalf("shared secret: %s", got)
	}
	for name, test := range map[string]struct {
		actual [32]byte
		want   string
	}{
		"client write": {alice.writeKey, "95f786ebf2f4bd460a4031f6b097f54635c27fb8df4c53cfd225c6d9d7ef3abc"},
		"client MAC":   {alice.writeMACKey, "726505b9481b72f123fa40aef9f6e777c0070b3cc016f097a8e9569ef4200810"},
		"server write": {alice.readKey, "a795d45bd0baee7bdef64c7053f1f63b9a2edc0c3c876abe45282dd2dc777d53"},
		"server MAC":   {alice.readMACKey, "40cb251330c07f2cfd084c841a707aa66e81e1d70775d45bcbc6a6ec72f97e91"},
	} {
		if got := hex.EncodeToString(test.actual[:]); got != test.want {
			t.Errorf("%s: got %s, want %s", name, got, test.want)
		}
	}
	if alice.writeKey != bob.readKey || alice.readKey != bob.writeKey || alice.writeMACKey != bob.readMACKey || alice.readMACKey != bob.writeMACKey {
		t.Fatal("client/server directional keys do not match")
	}
}

func TestEncryptionAuthenticationAndTamperDetection(t *testing.T) {
	client, err := NewClientEncryptor("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerEncryptor("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetPeerPublicKey(server.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := server.SetPeerPublicKey(client.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if !client.VerifyPeerAuthenticator(server.Authenticator()) || !server.VerifyPeerAuthenticator(client.Authenticator()) {
		t.Fatal("authenticators do not match")
	}
	plaintext := mustHex(t, "00010000020003002161626300")
	sealed, err := client.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("got %x, want %x", opened, plaintext)
	}
	if _, err := server.Open(sealed); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("replayed packet: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := server.Open(tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered packet: %v", err)
	}
}

func TestAuthenticationRejectsWrongSecret(t *testing.T) {
	client, _ := NewClientEncryptor("one")
	server, _ := NewServerEncryptor("two")
	_ = client.SetPeerPublicKey(server.PublicKey())
	_ = server.SetPeerPublicKey(client.PublicKey())
	if client.VerifyPeerAuthenticator(server.Authenticator()) {
		t.Fatal("different secrets authenticated")
	}
}
