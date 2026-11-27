package protocol

import (
	"bytes"
	"testing"
)

const testPayloadLimit = 160

func establishSessions(t *testing.T, secret string) (*Session, *Session) {
	t.Helper()
	client, err := NewClientSession(secret)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSession(client.ID(), secret)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 8 && (!client.Established() || !server.Established()); step++ {
		query, err := client.NextPacket(testPayloadLimit)
		if err != nil {
			t.Fatal(err)
		}
		serverResult, err := server.Receive(query, testPayloadLimit)
		if err != nil {
			t.Fatal(err)
		}
		if len(serverResult.Response) == 0 {
			t.Fatal("empty server response")
		}
		if _, err := client.Receive(serverResult.Response, testPayloadLimit); err != nil {
			t.Fatal(err)
		}
	}
	if !client.Established() || !server.Established() {
		t.Fatal("session did not establish")
	}
	return client, server
}

func exchangeClientPacket(t *testing.T, client, server *Session) (clientResult, serverResult *ReceiveResult) {
	t.Helper()
	query, err := client.NextPacket(testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	serverResult, err = server.Receive(query, testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err = client.Receive(serverResult.Response, testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	return clientResult, serverResult
}

func TestSessionHandshakeAndReliableData(t *testing.T) {
	client, server := establishSessions(t, "shared secret")
	if !client.Authenticated() || !server.Authenticated() {
		t.Fatal("session was not authenticated")
	}
	client.Queue([]byte("request"))
	_, serverResult := exchangeClientPacket(t, client, server)
	if !bytes.Equal(serverResult.Incoming, []byte("request")) {
		t.Fatalf("server incoming: %q", serverResult.Incoming)
	}
	if client.Buffered() != 0 {
		t.Fatalf("request was not acknowledged: %d", client.Buffered())
	}
	server.Queue([]byte("response"))
	clientResult, _ := exchangeClientPacket(t, client, server)
	if !bytes.Equal(clientResult.Incoming, []byte("response")) {
		t.Fatalf("client incoming: %q", clientResult.Incoming)
	}
	// The server learns that the client received its data on the next poll.
	_, _ = exchangeClientPacket(t, client, server)
	if server.Buffered() != 0 {
		t.Fatalf("response was not acknowledged: %d", server.Buffered())
	}
}

func TestSessionRetransmitUntilAcknowledged(t *testing.T) {
	client, server := establishSessions(t, "secret")
	client.Queue([]byte("unacknowledged"))
	if _, err := client.NextPacket(testPayloadLimit); err != nil {
		t.Fatal(err)
	}
	second, err := client.NextPacket(testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if client.Buffered() != len("unacknowledged") {
		t.Fatal("data consumed before ACK")
	}
	serverResult, err := server.Receive(second, testPayloadLimit)
	if err != nil || !bytes.Equal(serverResult.Incoming, []byte("unacknowledged")) {
		t.Fatalf("server receive: %q %v", serverResult.Incoming, err)
	}
	if _, err := client.Receive(serverResult.Response, testPayloadLimit); err != nil {
		t.Fatal(err)
	}
	if client.Buffered() != 0 {
		t.Fatal("ACK did not consume data")
	}
}

func TestSessionRekeyAndLostResponseRetransmission(t *testing.T) {
	client, server := establishSessions(t, "secret")
	oldClientKey := client.encryptor.writeKey
	client.encryptor.nextNonce = 0xfff1
	firstQuery, err := client.NextPacket(testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	firstResponse, err := server.Receive(firstQuery, testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if server.previous == nil {
		t.Fatal("server did not retain old keys")
	}
	// A new DNS request can carry a fresh packet ID/nonce with the same pending
	// public key when the first rekey response is lost.
	secondQuery, err := client.NextPacket(testPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	secondResponse, err := server.Receive(secondQuery, testPayloadLimit)
	if err != nil || len(secondResponse.Response) == 0 {
		t.Fatalf("rekey retransmission: %v", err)
	}
	if server.previous == nil {
		t.Fatal("old key fallback was discarded too early")
	}
	if _, err := client.Receive(firstResponse.Response, testPayloadLimit); err != nil {
		t.Fatal(err)
	}
	if client.pending != nil || client.encryptor.writeKey == oldClientKey {
		t.Fatal("client did not switch keys")
	}
	client.Queue([]byte("after rekey"))
	_, serverResult := exchangeClientPacket(t, client, server)
	if !bytes.Equal(serverResult.Incoming, []byte("after rekey")) || server.previous != nil {
		t.Fatal("new-key traffic did not complete renegotiation")
	}
}

func TestSequenceWraparound(t *testing.T) {
	client, server := establishSessions(t, "secret")
	client.mySeq = 0xfffe
	client.outgoing = []byte("abcd")
	server.theirSeq = 0xfffe
	serverResult, err := server.Receive(mustClientMSG(t, client), testPayloadLimit)
	if err != nil || !bytes.Equal(serverResult.Incoming, []byte("ab")) {
		t.Fatalf("wrapped receive: %q %v", serverResult.Incoming, err)
	}
	if server.theirSeq != 0 {
		t.Fatalf("server sequence: %#x", server.theirSeq)
	}
	if _, err := client.Receive(serverResult.Response, testPayloadLimit); err != nil {
		t.Fatal(err)
	}
	if client.mySeq != 0 || client.Buffered() != 2 {
		t.Fatalf("client sequence/buffer: %#x %d", client.mySeq, client.Buffered())
	}
}

func TestLostHandshakeResponses(t *testing.T) {
	client, _ := NewClientSession("secret")
	server, _ := NewServerSession(client.ID(), "secret")
	for !client.Established() {
		query, err := client.NextPacket(testPayloadLimit)
		if err != nil {
			t.Fatal(err)
		}
		// Discard the response, then retry with a fresh packet ID/nonce.
		if _, err = server.Receive(query, testPayloadLimit); err != nil {
			t.Fatal(err)
		}
		query, err = client.NextPacket(testPayloadLimit)
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Receive(query, testPayloadLimit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Receive(response.Response, testPayloadLimit); err != nil {
			t.Fatal(err)
		}
	}
	client.Queue([]byte("still alive"))
	_, response := exchangeClientPacket(t, client, server)
	if string(response.Incoming) != "still alive" {
		t.Fatal("handshake retries lost session")
	}
}

func mustClientMSG(t *testing.T, client *Session) []byte {
	t.Helper()
	packet := &Packet{ID: 1, Type: PacketMSG, SessionID: client.id, MSG: &MSG{
		Sequence: client.mySeq, Ack: client.theirSeq, Data: []byte("ab"),
	}}
	encoded, err := marshalAndSeal(packet, client.encryptor)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
