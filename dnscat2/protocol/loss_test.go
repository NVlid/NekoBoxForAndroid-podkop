package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestBidirectionalPacketLossAndDuplicates(t *testing.T) {
	client, server := establishSessions(t, "public-test-secret")
	payload := bytes.Repeat([]byte("ordered bytes over unreliable DNS"), 8192)
	var sentClient, sentServer int
	var receivedClient, receivedServer []byte
	for iteration := 1; iteration <= 50000; iteration++ {
		if sentClient < len(payload) && client.Buffered() < 8192 {
			n := min(4096, len(payload)-sentClient)
			client.Queue(payload[sentClient : sentClient+n])
			sentClient += n
		}
		if sentServer < len(payload) && server.Buffered() < 8192 {
			n := min(4096, len(payload)-sentServer)
			server.Queue(payload[sentServer : sentServer+n])
			sentServer += n
		}
		query, err := client.NextPacket(113)
		if err != nil {
			t.Fatal(err)
		}
		if iteration%11 == 0 {
			continue
		} // Lost DNS query.
		response, err := server.Receive(query, 113)
		if err != nil {
			t.Fatal(err)
		}
		receivedServer = append(receivedServer, response.Incoming...)
		if iteration%13 == 0 {
			if _, err := server.Receive(query, 113); !errors.Is(err, ErrPacketDiscarded) {
				t.Fatal("replayed nonce accepted")
			}
		}
		if iteration%7 == 0 {
			continue
		} // Lost DNS response.
		result, err := client.Receive(response.Response, 113)
		if errors.Is(err, ErrPacketDiscarded) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		receivedClient = append(receivedClient, result.Incoming...)
		if len(receivedClient) == len(payload) && len(receivedServer) == len(payload) {
			if !bytes.Equal(receivedClient, payload) || !bytes.Equal(receivedServer, payload) {
				t.Fatal("loss/duplicates corrupted ordered data")
			}
			return
		}
	}
	t.Fatalf("did not recover from loss: client=%d server=%d want=%d", len(receivedClient), len(receivedServer), len(payload))
}
