// Package protocol implements the dnscat2 wire and command protocols.
package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	PacketHeaderSize = 5
	MaxPacketSize    = 4096

	PacketSYN  uint8 = 0x00
	PacketMSG  uint8 = 0x01
	PacketFIN  uint8 = 0x02
	PacketENC  uint8 = 0x03
	PacketPING uint8 = 0xff

	ENCInit uint16 = 0x0000
	ENCAuth uint16 = 0x0001

	OptName    uint16 = 0x0001
	OptCommand uint16 = 0x0020
)

type SYN struct {
	Sequence uint16
	Options  uint16
	Name     string
}

type MSG struct {
	Sequence uint16
	Ack      uint16
	Data     []byte
}

type FIN struct {
	Reason string
}

type ENC struct {
	Subtype       uint16
	Flags         uint16
	PublicKey     []byte
	Authenticator []byte
}

type Packet struct {
	ID        uint16
	Type      uint8
	SessionID uint16
	SYN       *SYN
	MSG       *MSG
	FIN       *FIN
	ENC       *ENC
	Ping      string
}

func (p *Packet) MarshalBinary() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	_ = binary.Write(buffer, binary.BigEndian, p.ID)
	buffer.WriteByte(p.Type)
	_ = binary.Write(buffer, binary.BigEndian, p.SessionID)

	switch p.Type {
	case PacketSYN:
		if p.SYN == nil {
			return nil, errors.New("dnscat2: missing SYN body")
		}
		_ = binary.Write(buffer, binary.BigEndian, p.SYN.Sequence)
		_ = binary.Write(buffer, binary.BigEndian, p.SYN.Options)
		if p.SYN.Options&OptName != 0 {
			if err := writeNTString(buffer, p.SYN.Name); err != nil {
				return nil, err
			}
		}
	case PacketMSG:
		if p.MSG == nil {
			return nil, errors.New("dnscat2: missing MSG body")
		}
		_ = binary.Write(buffer, binary.BigEndian, p.MSG.Sequence)
		_ = binary.Write(buffer, binary.BigEndian, p.MSG.Ack)
		buffer.Write(p.MSG.Data)
	case PacketFIN:
		if p.FIN == nil {
			return nil, errors.New("dnscat2: missing FIN body")
		}
		if err := writeNTString(buffer, p.FIN.Reason); err != nil {
			return nil, err
		}
	case PacketENC:
		if p.ENC == nil {
			return nil, errors.New("dnscat2: missing ENC body")
		}
		_ = binary.Write(buffer, binary.BigEndian, p.ENC.Subtype)
		_ = binary.Write(buffer, binary.BigEndian, p.ENC.Flags)
		switch p.ENC.Subtype {
		case ENCInit:
			if len(p.ENC.PublicKey) != 64 {
				return nil, errors.New("dnscat2: ENC public key must be 64 bytes")
			}
			buffer.Write(p.ENC.PublicKey)
		case ENCAuth:
			if len(p.ENC.Authenticator) != 32 {
				return nil, errors.New("dnscat2: ENC authenticator must be 32 bytes")
			}
			buffer.Write(p.ENC.Authenticator)
		default:
			return nil, fmt.Errorf("dnscat2: unknown ENC subtype %#x", p.ENC.Subtype)
		}
	case PacketPING:
		if err := writeNTString(buffer, p.Ping); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("dnscat2: unknown packet type %#x", p.Type)
	}
	if buffer.Len() > MaxPacketSize {
		return nil, fmt.Errorf("dnscat2: packet is too large: %d", buffer.Len())
	}
	return buffer.Bytes(), nil
}

func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < PacketHeaderSize {
		return nil, io.ErrUnexpectedEOF
	}
	if len(data) > MaxPacketSize {
		return nil, errors.New("dnscat2: oversized packet")
	}
	reader := bytes.NewReader(data)
	p := &Packet{}
	_ = binary.Read(reader, binary.BigEndian, &p.ID)
	p.Type, _ = reader.ReadByte()
	_ = binary.Read(reader, binary.BigEndian, &p.SessionID)

	switch p.Type {
	case PacketSYN:
		body := &SYN{}
		if err := binary.Read(reader, binary.BigEndian, &body.Sequence); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &body.Options); err != nil {
			return nil, err
		}
		if body.Options&OptName != 0 {
			name, err := readNTString(reader)
			if err != nil {
				return nil, err
			}
			body.Name = name
		}
		p.SYN = body
	case PacketMSG:
		body := &MSG{}
		if err := binary.Read(reader, binary.BigEndian, &body.Sequence); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &body.Ack); err != nil {
			return nil, err
		}
		body.Data = append([]byte(nil), data[len(data)-reader.Len():]...)
		reader.Seek(0, io.SeekEnd)
		p.MSG = body
	case PacketFIN:
		reason, err := readNTString(reader)
		if err != nil {
			return nil, err
		}
		p.FIN = &FIN{Reason: reason}
	case PacketENC:
		body := &ENC{}
		if err := binary.Read(reader, binary.BigEndian, &body.Subtype); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &body.Flags); err != nil {
			return nil, err
		}
		switch body.Subtype {
		case ENCInit:
			body.PublicKey = make([]byte, 64)
			if _, err := io.ReadFull(reader, body.PublicKey); err != nil {
				return nil, err
			}
		case ENCAuth:
			body.Authenticator = make([]byte, 32)
			if _, err := io.ReadFull(reader, body.Authenticator); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("dnscat2: unknown ENC subtype %#x", body.Subtype)
		}
		p.ENC = body
	case PacketPING:
		value, err := readNTString(reader)
		if err != nil {
			return nil, err
		}
		p.Ping = value
	default:
		return nil, fmt.Errorf("dnscat2: unknown packet type %#x", p.Type)
	}
	if p.Type != PacketMSG && reader.Len() != 0 {
		return nil, errors.New("dnscat2: trailing packet data")
	}
	return p, nil
}

func PeekSessionID(data []byte) (uint16, error) {
	if len(data) < PacketHeaderSize {
		return 0, io.ErrUnexpectedEOF
	}
	return binary.BigEndian.Uint16(data[3:5]), nil
}

func readNTString(reader *bytes.Reader) (string, error) {
	var value []byte
	for {
		current, err := reader.ReadByte()
		if err != nil {
			return "", io.ErrUnexpectedEOF
		}
		if current == 0 {
			return string(value), nil
		}
		value = append(value, current)
	}
}

func writeNTString(buffer *bytes.Buffer, value string) error {
	if bytes.IndexByte([]byte(value), 0) >= 0 {
		return errors.New("dnscat2: NUL in a null-terminated string")
	}
	buffer.WriteString(value)
	buffer.WriteByte(0)
	return nil
}
