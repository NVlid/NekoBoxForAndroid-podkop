package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type UDPClient struct {
	codec       *Codec
	server      string
	recordTypes []uint16
	timeout     time.Duration
	dial        DialFunc

	mu       sync.Mutex
	conn     net.Conn
	nextType int
}

func NewUDPClient(codec *Codec, server string, port uint16, recordTypes []uint16, timeout time.Duration, dial DialFunc) (*UDPClient, error) {
	if codec == nil || server == "" || port == 0 || len(recordTypes) == 0 {
		return nil, errors.New("dnscat2: incomplete UDP transport configuration")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	return &UDPClient{
		codec: codec, server: net.JoinHostPort(server, strconv.Itoa(int(port))),
		recordTypes: append([]uint16(nil), recordTypes...), timeout: timeout, dial: dial,
	}, nil
}

func (c *UDPClient) MaxPayload() int {
	return c.codec.MaxPayload()
}

// Exchange performs one DNS request. Retransmission belongs to the session
// loop, which creates a fresh dnscat2 packet ID and encryption nonce per try.
func (c *UDPClient) Exchange(ctx context.Context, payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	recordType := c.recordTypes[c.nextType%len(c.recordTypes)]
	c.nextType++
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	query, err := c.codec.BuildQuery(id, recordType, payload)
	if err != nil {
		return nil, err
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}
	if c.conn == nil {
		c.conn, err = c.dial(ctx, "udp", c.server)
		if err != nil {
			return nil, err
		}
	}
	conn := c.conn
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		if !stopCancel() {
			_ = conn.Close()
			c.conn = nil
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		c.closeConn()
		return nil, err
	}
	if _, err := conn.Write(packed); err != nil {
		c.closeConn()
		return nil, err
	}
	buffer := make([]byte, 65535)
	for {
		length, err := conn.Read(buffer)
		if err != nil {
			c.closeConn()
			return nil, err
		}
		response := new(dns.Msg)
		if err := response.Unpack(buffer[:length]); err != nil || response.Id != id {
			continue
		}
		decoded, err := c.codec.DecodeResponse(response, id, recordType)
		if err != nil {
			c.closeConn()
			return nil, err
		}
		return decoded, nil
	}
}

func (c *UDPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeConn()
}

func (c *UDPClient) closeConn() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func randomID() (uint16, error) {
	var data [2]byte
	if _, err := rand.Read(data[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data[:]), nil
}
