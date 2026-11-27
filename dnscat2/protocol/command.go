package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	CommandPing     uint16 = 0x0000
	CommandShell    uint16 = 0x0001
	CommandExec     uint16 = 0x0002
	CommandDownload uint16 = 0x0003
	CommandUpload   uint16 = 0x0004
	CommandShutdown uint16 = 0x0005
	CommandDelay    uint16 = 0x0006

	TunnelConnect uint16 = 0x1000
	TunnelData    uint16 = 0x1001
	TunnelClose   uint16 = 0x1002
	// NekoBox companion extension: half-close, without dropping reverse data.
	TunnelEOF    uint16 = 0x1003
	CommandError uint16 = 0xffff

	MaxCommandSize = 32 * 1024
)

type Command struct {
	RequestID uint16
	Type      uint16
	Response  bool
	Payload   []byte
}

func (c Command) MarshalBinary() ([]byte, error) {
	if c.RequestID > 0x7fff {
		return nil, errors.New("dnscat2: command request ID exceeds 15 bits")
	}
	length := uint32(4 + len(c.Payload))
	if length > MaxCommandSize {
		return nil, errors.New("dnscat2: oversized command")
	}
	result := make([]byte, 0, length+4)
	result = binary.BigEndian.AppendUint32(result, length)
	packedID := c.RequestID
	if c.Response {
		packedID |= 0x8000
	}
	result = binary.BigEndian.AppendUint16(result, packedID)
	result = binary.BigEndian.AppendUint16(result, c.Type)
	result = append(result, c.Payload...)
	return result, nil
}

// CommandDecoder reassembles the command stream carried by reliable MSG data.
type CommandDecoder struct {
	buffer bytes.Buffer
}

func (d *CommandDecoder) Feed(data []byte) ([]Command, error) {
	if d.buffer.Len()+len(data) > MaxCommandSize+4 {
		return nil, errors.New("dnscat2: command decoder limit exceeded")
	}
	d.buffer.Write(data)
	var commands []Command
	for {
		if d.buffer.Len() < 4 {
			return commands, nil
		}
		length := binary.BigEndian.Uint32(d.buffer.Bytes()[:4])
		if length < 4 || length > MaxCommandSize {
			d.buffer.Reset()
			return nil, fmt.Errorf("dnscat2: invalid command length %d", length)
		}
		if uint64(d.buffer.Len()) < uint64(length)+4 {
			return commands, nil
		}
		frame := d.buffer.Next(int(length) + 4)[4:]
		packedID := binary.BigEndian.Uint16(frame[:2])
		commands = append(commands, Command{
			RequestID: packedID & 0x7fff,
			Response:  packedID&0x8000 != 0,
			Type:      binary.BigEndian.Uint16(frame[2:4]),
			Payload:   append([]byte(nil), frame[4:]...),
		})
	}
}

func NewTunnelConnect(requestID uint16, host string, port uint16) (Command, error) {
	if host == "" || port == 0 || bytes.IndexByte([]byte(host), 0) >= 0 {
		return Command{}, errors.New("dnscat2: invalid tunnel destination")
	}
	payload := binary.BigEndian.AppendUint32(nil, 0)
	payload = append(payload, host...)
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint16(payload, port)
	return Command{RequestID: requestID, Type: TunnelConnect, Payload: payload}, nil
}

func ParseTunnelConnect(command Command) (host string, port uint16, err error) {
	if command.Type != TunnelConnect || command.Response || len(command.Payload) < 7 {
		return "", 0, errors.New("dnscat2: invalid TUNNEL_CONNECT request")
	}
	reader := bytes.NewReader(command.Payload[4:])
	host, err = readNTString(reader)
	if err != nil || host == "" {
		return "", 0, errors.New("dnscat2: invalid TUNNEL_CONNECT host")
	}
	if err = binary.Read(reader, binary.BigEndian, &port); err != nil || port == 0 || reader.Len() != 0 {
		return "", 0, errors.New("dnscat2: invalid TUNNEL_CONNECT port")
	}
	return host, port, nil
}

func NewTunnelConnectResponse(requestID uint16, tunnelID uint32) Command {
	return Command{
		RequestID: requestID,
		Type:      TunnelConnect,
		Response:  true,
		Payload:   binary.BigEndian.AppendUint32(nil, tunnelID),
	}
}

func ParseTunnelConnectResponse(command Command) (uint32, error) {
	if command.Type != TunnelConnect || !command.Response || len(command.Payload) != 4 {
		return 0, errors.New("dnscat2: invalid TUNNEL_CONNECT response")
	}
	return binary.BigEndian.Uint32(command.Payload), nil
}

func NewTunnelData(requestID uint16, tunnelID uint32, data []byte) Command {
	payload := binary.BigEndian.AppendUint32(nil, tunnelID)
	payload = append(payload, data...)
	return Command{RequestID: requestID, Type: TunnelData, Payload: payload}
}

func ParseTunnelData(command Command) (uint32, []byte, error) {
	if command.Type != TunnelData || command.Response || len(command.Payload) < 4 {
		return 0, nil, errors.New("dnscat2: invalid TUNNEL_DATA request")
	}
	return binary.BigEndian.Uint32(command.Payload[:4]), command.Payload[4:], nil
}

func NewTunnelClose(requestID uint16, tunnelID uint32, reason string) Command {
	payload := binary.BigEndian.AppendUint32(nil, tunnelID)
	payload = append(payload, reason...)
	payload = append(payload, 0)
	return Command{RequestID: requestID, Type: TunnelClose, Payload: payload}
}

func NewTunnelEOF(requestID uint16, tunnelID uint32) Command {
	return Command{RequestID: requestID, Type: TunnelEOF, Payload: binary.BigEndian.AppendUint32(nil, tunnelID)}
}

func ParseTunnelEOF(command Command) (uint32, error) {
	if command.Type != TunnelEOF || command.Response || len(command.Payload) != 4 {
		return 0, errors.New("dnscat2: invalid TUNNEL_EOF")
	}
	return binary.BigEndian.Uint32(command.Payload), nil
}

func ParseTunnelClose(command Command) (uint32, string, error) {
	if command.Type != TunnelClose || command.Response || len(command.Payload) < 5 {
		return 0, "", errors.New("dnscat2: invalid TUNNEL_CLOSE request")
	}
	reader := bytes.NewReader(command.Payload[4:])
	reason, err := readNTString(reader)
	if err != nil || reader.Len() != 0 {
		return 0, "", errors.New("dnscat2: invalid TUNNEL_CLOSE reason")
	}
	return binary.BigEndian.Uint32(command.Payload[:4]), reason, nil
}

func NewPing(requestID uint16, response bool, data string) (Command, error) {
	if bytes.IndexByte([]byte(data), 0) >= 0 {
		return Command{}, errors.New("dnscat2: NUL in ping data")
	}
	return Command{RequestID: requestID, Type: CommandPing, Response: response, Payload: append([]byte(data), 0)}, nil
}

func ParsePing(command Command) (string, error) {
	if command.Type != CommandPing || len(command.Payload) == 0 || command.Payload[len(command.Payload)-1] != 0 || bytes.IndexByte(command.Payload[:len(command.Payload)-1], 0) >= 0 {
		return "", errors.New("dnscat2: invalid COMMAND_PING")
	}
	return string(command.Payload[:len(command.Payload)-1]), nil
}

func NewCommandError(requestID uint16, status uint16, reason string) Command {
	payload := binary.BigEndian.AppendUint16(nil, status)
	payload = append(payload, reason...)
	payload = append(payload, 0)
	return Command{RequestID: requestID, Type: CommandError, Response: true, Payload: payload}
}

func ParseCommandError(command Command) (uint16, string, error) {
	if command.Type != CommandError || !command.Response || len(command.Payload) < 3 {
		return 0, "", errors.New("dnscat2: invalid COMMAND_ERROR")
	}
	reader := bytes.NewReader(command.Payload[2:])
	reason, err := readNTString(reader)
	if err != nil || reader.Len() != 0 {
		return 0, "", errors.New("dnscat2: invalid COMMAND_ERROR reason")
	}
	return binary.BigEndian.Uint16(command.Payload[:2]), reason, nil
}
