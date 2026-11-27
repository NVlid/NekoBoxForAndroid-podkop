package protocol

import (
	"bytes"
	"testing"
)

func TestCommandStreamReassembly(t *testing.T) {
	connect, err := NewTunnelConnect(42, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	connectBytes, err := connect.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	data := NewTunnelData(43, 99, []byte("payload"))
	dataBytes, err := data.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	stream := append(connectBytes, dataBytes...)
	decoder := &CommandDecoder{}
	var commands []Command
	for _, value := range stream {
		parsed, err := decoder.Feed([]byte{value})
		if err != nil {
			t.Fatal(err)
		}
		commands = append(commands, parsed...)
	}
	if len(commands) != 2 {
		t.Fatalf("got %d commands", len(commands))
	}
	host, port, err := ParseTunnelConnect(commands[0])
	if err != nil || host != "example.com" || port != 443 {
		t.Fatalf("connect: %q %d %v", host, port, err)
	}
	tunnelID, payload, err := ParseTunnelData(commands[1])
	if err != nil || tunnelID != 99 || !bytes.Equal(payload, []byte("payload")) {
		t.Fatalf("data: %d %q %v", tunnelID, payload, err)
	}
}

func TestCommandHelpers(t *testing.T) {
	response := NewTunnelConnectResponse(12, 34)
	encoded, err := response.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoder := &CommandDecoder{}
	commands, err := decoder.Feed(encoded)
	if err != nil || len(commands) != 1 {
		t.Fatalf("decode: %v %#v", err, commands)
	}
	tunnelID, err := ParseTunnelConnectResponse(commands[0])
	if err != nil || tunnelID != 34 {
		t.Fatalf("response: %d %v", tunnelID, err)
	}
	closeCommand := NewTunnelClose(1, 34, "closed")
	encoded, _ = closeCommand.MarshalBinary()
	commands, err = decoder.Feed(encoded)
	if err != nil || len(commands) != 1 {
		t.Fatalf("close decode: %v", err)
	}
	_, reason, err := ParseTunnelClose(commands[0])
	if err != nil || reason != "closed" {
		t.Fatalf("close: %q %v", reason, err)
	}
}

func TestCommandDecoderRejectsInvalidLength(t *testing.T) {
	decoder := &CommandDecoder{}
	if _, err := decoder.Feed([]byte{0, 0, 0, 3}); err == nil {
		t.Fatal("short command accepted")
	}
}
