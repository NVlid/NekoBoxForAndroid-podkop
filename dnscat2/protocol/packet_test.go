package protocol

import (
	"encoding/hex"
	"testing"
)

func TestPacketVectors(t *testing.T) {
	tests := []struct {
		name   string
		hex    string
		packet *Packet
	}{
		{
			name: "SYN with name and command",
			hex:  "00010000020003002161626300",
			packet: &Packet{ID: 1, Type: PacketSYN, SessionID: 2, SYN: &SYN{
				Sequence: 3, Options: OptCommand | OptName, Name: "abc",
			}},
		},
		{
			name: "MSG",
			hex:  "0102010003000400057061796c6f6164",
			packet: &Packet{ID: 0x0102, Type: PacketMSG, SessionID: 3, MSG: &MSG{
				Sequence: 4, Ack: 5, Data: []byte("payload"),
			}},
		},
		{
			name:   "FIN",
			hex:    "000202000a646f6e6500",
			packet: &Packet{ID: 2, Type: PacketFIN, SessionID: 10, FIN: &FIN{Reason: "done"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected, err := hex.DecodeString(test.hex)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := test.packet.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != string(expected) {
				t.Fatalf("encoding: got %x, want %x", actual, expected)
			}
			parsed, err := ParsePacket(expected)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if string(roundTrip) != string(expected) {
				t.Fatalf("round trip: got %x, want %x", roundTrip, expected)
			}
		})
	}
}

func TestPacketRejectsMalformedInput(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0, 0, 0, 0},
		{0, 1, PacketSYN, 0, 1, 0},
		{0, 1, PacketFIN, 0, 1, 'n', 'o'},
		{0, 1, 0x7f, 0, 1},
	} {
		if _, err := ParsePacket(data); err == nil {
			t.Fatalf("ParsePacket(%x) unexpectedly succeeded", data)
		}
	}
}
