// Package sshuttle implements sshuttle 1.3.2's SS multiplexing protocol.
// It does not use SSH direct-tcpip / dynamic port forwarding.
package sshuttle

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/stream"
)

const (
	cmdExit    = 0x4200
	cmdPing    = 0x4201
	cmdPong    = 0x4202
	cmdConnect = 0x4203
	cmdStop    = 0x4204
	cmdEOF     = 0x4205
	cmdData    = 0x4206
	cmdRoutes  = 0x4207
)

// Bootstrap invokes the real, installed upstream server. A fixed version is
// required so its private main() signature cannot change underneath the app.
const Bootstrap = "import importlib.metadata; assert importlib.metadata.version('sshuttle') == '1.3.2', 'sshuttle 1.3.2 required'; from sshuttle.server import main; main(True, 32768, False, None, False)"

type frame struct {
	channel uint16
	command uint16
	data    []byte
}

type Mux struct {
	ctx            context.Context
	cancel         context.CancelFunc
	reader         io.Reader
	writer         io.Writer
	closeTransport func()
	queue          chan frame
	mu             sync.Mutex
	next           uint16
	channels       map[uint16]*stream.Conn
	used           map[uint16]bool
	once           sync.Once
}

// New verifies the upstream synchronization header before accepting channels.
// The caller must close the transport if its handshake context expires.
func New(reader io.Reader, writer io.Writer, closeTransport func()) (*Mux, error) {
	header := make([]byte, len("\x00\x00SSHUTTLE0001"))
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if string(header) != "\x00\x00SSHUTTLE0001" {
		return nil, errors.New("sshuttle: invalid server synchronization header")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Mux{ctx: ctx, cancel: cancel, reader: reader, writer: writer,
		closeTransport: closeTransport, queue: make(chan frame, 64),
		channels: make(map[uint16]*stream.Conn), used: make(map[uint16]bool)}
	go m.writeLoop()
	go m.readLoop()
	return m, nil
}

func (m *Mux) Alive() bool { return m.ctx.Err() == nil }

func (m *Mux) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, err
	}
	// sshuttle 1.3.2 accepts AF_INET=2 or any non-2 value for IPv6.
	family := 2
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		family = 10
	}
	m.mu.Lock()
	var id uint16
	// Do not recycle IDs within a session: delayed EOF/DATA for an old stream
	// must not be delivered to a newly opened stream.
	for attempt := 0; attempt < 65535; attempt++ {
		m.next++
		if m.next == 0 {
			m.next++
		}
		if !m.used[m.next] {
			id = m.next
			m.used[id] = true
			break
		}
	}
	if id == 0 {
		m.mu.Unlock()
		return nil, errors.New("sshuttle: channel IDs exhausted; reconnect")
	}
	conn := stream.New(m.ctx, destination,
		func(ctx context.Context, data []byte) error { return m.send(ctx, frame{id, cmdData, data}) },
		func() {
			m.mu.Lock()
			delete(m.channels, id)
			m.mu.Unlock()
			// Never block the read-loop on local teardown.
			for _, command := range []uint16{cmdEOF, cmdStop} {
				select {
				case m.queue <- frame{channel: id, command: command}:
				default:
					m.Close()
				}
			}
		})
	conn.OnCloseWrite = func() error { return m.send(ctx, frame{channel: id, command: cmdEOF}) }
	m.channels[id] = conn
	m.mu.Unlock()
	if err := m.send(ctx, frame{id, cmdConnect, []byte(fmt.Sprintf("%d,%s,%s", family, host, port))}); err != nil {
		conn.Close()
		return nil, err
	}
	// Like upstream, TCP_CONNECT is asynchronous; EOF/STOP reports a refused
	// destination. A successful URL test still requires a real remote response.
	return conn, nil
}

func (m *Mux) send(ctx context.Context, f frame) error {
	if len(f.data) > 65535 {
		return errors.New("sshuttle: oversized mux frame")
	}
	if m.ctx.Err() != nil {
		return net.ErrClosed
	}
	select {
	case m.queue <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return net.ErrClosed
	}
}

func (m *Mux) writeLoop() {
	defer m.Close()
	for {
		select {
		case f := <-m.queue:
			header := []byte{'S', 'S'}
			header = binary.BigEndian.AppendUint16(header, f.channel)
			header = binary.BigEndian.AppendUint16(header, f.command)
			header = binary.BigEndian.AppendUint16(header, uint16(len(f.data)))
			if err := writeAll(m.writer, append(header, f.data...)); err != nil {
				return
			}
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Mux) readLoop() {
	defer m.Close()
	for {
		var header [8]byte
		if _, err := io.ReadFull(m.reader, header[:]); err != nil {
			return
		}
		if header[0] != 'S' || header[1] != 'S' {
			return
		}
		channel := binary.BigEndian.Uint16(header[2:4])
		command := binary.BigEndian.Uint16(header[4:6])
		data := make([]byte, int(binary.BigEndian.Uint16(header[6:8])))
		if _, err := io.ReadFull(m.reader, data); err != nil {
			return
		}
		switch command {
		case cmdPing:
			if err := m.send(m.ctx, frame{command: cmdPong, data: data}); err != nil {
				return
			}
		case cmdPong, cmdRoutes:
			// Routing belongs to NekoBox; never install remote subnet rules.
		case cmdExit:
			return
		case cmdEOF, cmdStop, cmdData:
			m.mu.Lock()
			conn := m.channels[channel]
			m.mu.Unlock()
			if conn == nil {
				continue
			}
			switch command {
			case cmdEOF:
				conn.EndRead(io.EOF)
			case cmdStop:
				conn.EndWrite()
			case cmdData:
				if !conn.Feed(data) {
					conn.EndRead(errors.New("sshuttle: receive buffer limit exceeded"))
					conn.Close()
				}
			}
		default:
			return
		}
	}
}

func (m *Mux) Close() error {
	m.once.Do(func() {
		m.cancel()
		if m.closeTransport != nil {
			m.closeTransport()
		}
		m.mu.Lock()
		channels := m.channels
		m.channels = make(map[uint16]*stream.Conn)
		m.mu.Unlock()
		for _, conn := range channels {
			conn.EndRead(net.ErrClosed)
			conn.EndWrite()
		}
	})
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
