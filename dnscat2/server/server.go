// Package server implements the NekoBox dnscat2 TCP companion.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/protocol"
	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/transport"
	"github.com/miekg/dns"
)

const (
	defaultMaxSessions   = 128
	maxTunnelsPerSession = 256
	maxSessionQueue      = 32 * 1024
	cacheTTL             = 30 * time.Second
)

type Config struct {
	Domain         string
	Secret         string
	MaxSessions    int
	SessionTimeout time.Duration
	Logger         *log.Logger
}

type Server struct {
	config Config
	codec  *transport.Codec
	conn   net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	sessions  map[uint16]*serverSession
	cache     map[string]cacheEntry
	closeOnce sync.Once
}

type cacheEntry struct {
	packet  []byte
	expires time.Time
}

func New(config Config, conn net.PacketConn) (*Server, error) {
	if config.Secret == "" {
		return nil, errors.New("dnscat2 companion: a pre-shared secret is required")
	}
	if conn == nil {
		return nil, errors.New("dnscat2 companion: nil UDP listener")
	}
	codec, err := transport.NewCodec(config.Domain)
	if err != nil {
		return nil, err
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.SessionTimeout <= 0 {
		config.SessionTimeout = 15 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		config: config, codec: codec, conn: conn, ctx: ctx, cancel: cancel,
		sessions: make(map[uint16]*serverSession), cache: make(map[string]cacheEntry),
	}, nil
}

func Listen(config Config, host string, port uint16) (*Server, error) {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	server, err := New(config, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return server, nil
}

func (s *Server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Server) Serve() error {
	go s.expireLoop()
	buffer := make([]byte, 65535)
	for {
		length, remote, err := s.conn.ReadFrom(buffer)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		packet := append([]byte(nil), buffer[:length]...)
		response, err := s.handlePacket(packet, remote)
		if err != nil {
			s.logf("request from %s failed: %v", remote, err)
			continue
		}
		if len(response) > 0 {
			if _, err := s.conn.WriteTo(response, remote); err != nil && s.ctx.Err() == nil {
				s.logf("response to %s failed: %v", remote, err)
			}
		}
	}
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.conn.Close()
		s.mu.Lock()
		sessions := s.sessions
		s.sessions = make(map[uint16]*serverSession)
		s.mu.Unlock()
		for _, session := range sessions {
			session.close()
		}
	})
	return err
}

func (s *Server) handlePacket(data []byte, remote net.Addr) ([]byte, error) {
	query := new(dns.Msg)
	if err := query.Unpack(data); err != nil || len(query.Question) != 1 {
		return nil, errors.New("invalid DNS query")
	}
	key := remote.String() + "|" + strconv.Itoa(int(query.Id)) + "|" + query.Question[0].Name + "|" + strconv.Itoa(int(query.Question[0].Qtype))
	now := time.Now()
	s.mu.Lock()
	for cacheKey, entry := range s.cache {
		if now.After(entry.expires) {
			delete(s.cache, cacheKey)
		}
	}
	cached, found := s.cache[key]
	s.mu.Unlock()
	if found && now.Before(cached.expires) {
		return cached.packet, nil
	}

	payload, err := s.codec.DecodeQuery(query)
	if err != nil {
		response := new(dns.Msg)
		response.SetRcode(query, dns.RcodeNameError)
		return response.Pack()
	}
	var responsePayload []byte
	if len(payload) >= protocol.PacketHeaderSize && payload[2] == protocol.PacketPING {
		if _, err := protocol.ParsePacket(payload); err != nil {
			return nil, err
		}
		// Upstream responds to a global ping with the same packet.
		responsePayload = payload
	} else {
		sessionID, err := protocol.PeekSessionID(payload)
		if err != nil {
			return nil, err
		}
		session, err := s.getSession(sessionID)
		if err != nil {
			response := new(dns.Msg)
			response.SetRcode(query, dns.RcodeServerFailure)
			return response.Pack()
		}
		result, receiveErr := session.session.Receive(payload, s.codec.MaxPayload())
		session.touch()
		session.queueMu.Lock()
		session.queueCond.Broadcast()
		session.queueMu.Unlock()
		if receiveErr != nil && !errors.Is(receiveErr, protocol.ErrPacketDiscarded) {
			s.removeSession(sessionID, session)
			return nil, receiveErr
		}
		if result != nil {
			responsePayload = result.Response
			if len(result.Incoming) > 0 {
				if err := session.feed(result.Incoming); err != nil {
					s.logf("session %04x command error: %v", sessionID, err)
				}
			}
		}
		if session.session.Closed() {
			s.removeSession(sessionID, session)
		}
	}
	response, err := s.codec.BuildResponse(query, responsePayload)
	if err != nil {
		return nil, err
	}
	packed, err := response.Pack()
	if err == nil {
		s.mu.Lock()
		if len(s.cache) >= 1024 {
			s.cache = make(map[string]cacheEntry)
		}
		s.cache[key] = cacheEntry{packet: packed, expires: now.Add(cacheTTL)}
		s.mu.Unlock()
	}
	return packed, err
}

func (s *Server) getSession(id uint16) (*serverSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.sessions[id]; existing != nil {
		return existing, nil
	}
	if len(s.sessions) >= s.config.MaxSessions {
		return nil, errors.New("too many dnscat2 sessions")
	}
	session, err := newServerSession(s, id)
	if err != nil {
		return nil, err
	}
	s.sessions[id] = session
	return session, nil
}

func (s *Server) removeSession(id uint16, expected *serverSession) {
	s.mu.Lock()
	current := s.sessions[id]
	if current == expected {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if current == expected {
		expected.close()
	}
}

func (s *Server) expireLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-s.config.SessionTimeout).UnixNano()
			s.mu.Lock()
			var expired []*serverSession
			for id, session := range s.sessions {
				if session.lastActive.Load() < cutoff {
					delete(s.sessions, id)
					expired = append(expired, session)
				}
			}
			s.mu.Unlock()
			for _, session := range expired {
				session.close()
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.config.Logger != nil {
		s.config.Logger.Printf(format, args...)
	}
}

type serverSession struct {
	server  *Server
	session *protocol.Session
	decoder protocol.CommandDecoder
	ctx     context.Context
	cancel  context.CancelFunc

	mu         sync.Mutex
	tunnels    map[uint32]*serverTunnel
	pending    map[uint16]bool
	nextID     uint16
	closed     atomic.Bool
	lastActive atomic.Int64
	queueMu    sync.Mutex
	queueCond  *sync.Cond
	closeOnce  sync.Once
}

func newServerSession(server *Server, id uint16) (*serverSession, error) {
	session, err := protocol.NewServerSession(id, server.config.Secret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(server.ctx)
	result := &serverSession{
		server: server, session: session, ctx: ctx, cancel: cancel,
		tunnels: make(map[uint32]*serverTunnel), pending: make(map[uint16]bool),
	}
	result.queueCond = sync.NewCond(&result.queueMu)
	result.touch()
	return result, nil
}

func (s *serverSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *serverSession) feed(data []byte) error {
	commands, err := s.decoder.Feed(data)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := s.handleCommand(command); err != nil {
			return err
		}
	}
	return nil
}

func (s *serverSession) handleCommand(command protocol.Command) error {
	switch command.Type {
	case protocol.TunnelConnect:
		host, port, err := protocol.ParseTunnelConnect(command)
		if err != nil {
			return err
		}
		s.startConnect(command.RequestID, host, port)
	case protocol.TunnelData:
		tunnelID, data, err := protocol.ParseTunnelData(command)
		if err != nil {
			return err
		}
		s.mu.Lock()
		tunnel := s.tunnels[tunnelID]
		s.mu.Unlock()
		if tunnel != nil && len(data) > 0 {
			copyOfData := append([]byte(nil), data...)
			select {
			case tunnel.writes <- copyOfData:
			case <-s.ctx.Done():
			case <-tunnel.done:
			default:
				go s.closeTunnel(tunnelID, true, "Remote write queue limit")
			}
		}
	case protocol.TunnelClose:
		tunnelID, _, err := protocol.ParseTunnelClose(command)
		if err != nil {
			return err
		}
		s.closeTunnel(tunnelID, false, "")
	case protocol.TunnelEOF:
		id, err := protocol.ParseTunnelEOF(command)
		if err != nil {
			return err
		}
		s.mu.Lock()
		tunnel := s.tunnels[id]
		s.mu.Unlock()
		if tunnel != nil {
			select {
			case tunnel.writes <- nil:
			default:
				go s.closeTunnel(id, true, "Write queue limit")
			}
		}
	case protocol.CommandPing:
		value, err := protocol.ParsePing(command)
		if err != nil {
			return err
		}
		if !command.Response {
			response, _ := protocol.NewPing(command.RequestID, true, value)
			encoded, _ := response.MarshalBinary()
			return s.queueControl(encoded)
		}
	case protocol.CommandShell, protocol.CommandExec, protocol.CommandDownload, protocol.CommandUpload, protocol.CommandDelay, protocol.CommandShutdown:
		if !command.Response {
			response := protocol.NewCommandError(command.RequestID, 0x8000, "command is not supported by the NekoBox companion")
			encoded, _ := response.MarshalBinary()
			return s.queueControl(encoded)
		}
	}
	return nil
}

func (s *serverSession) startConnect(requestID uint16, host string, port uint16) {
	tunnelID := uint32(requestID)
	s.mu.Lock()
	if s.closed.Load() || len(s.tunnels)+len(s.pending) >= maxTunnelsPerSession || s.tunnels[tunnelID] != nil || s.pending[requestID] {
		s.mu.Unlock()
		response := protocol.NewCommandError(requestID, 0x8000, "tunnel ID is busy or tunnel limit reached")
		encoded, _ := response.MarshalBinary()
		_ = s.queueControl(encoded)
		return
	}
	s.pending[requestID] = true
	s.mu.Unlock()
	go func() {
		dialer := &net.Dialer{Timeout: 15 * time.Second}
		conn, err := dialer.DialContext(s.ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			s.mu.Lock()
			delete(s.pending, requestID)
			s.mu.Unlock()
			response := protocol.NewCommandError(requestID, 0x8000, "TCP connect failed: "+err.Error())
			encoded, _ := response.MarshalBinary()
			_ = s.queue(encoded)
			return
		}
		tunnel := newServerTunnel(s, tunnelID, conn)
		s.mu.Lock()
		wasPending := s.pending[requestID]
		delete(s.pending, requestID)
		if !wasPending || s.closed.Load() || len(s.tunnels) >= maxTunnelsPerSession || s.tunnels[tunnelID] != nil {
			s.mu.Unlock()
			conn.Close()
			if wasPending && !s.closed.Load() {
				response := protocol.NewCommandError(requestID, 0x8000, "tunnel limit reached")
				encoded, _ := response.MarshalBinary()
				_ = s.queue(encoded)
			}
			return
		}
		s.tunnels[tunnelID] = tunnel
		s.mu.Unlock()
		response := protocol.NewTunnelConnectResponse(requestID, tunnelID)
		encoded, _ := response.MarshalBinary()
		if err := s.queue(encoded); err != nil {
			s.closeTunnel(tunnelID, false, "")
			return
		}
		go tunnel.readRemote()
		go tunnel.writeLocal()
		s.server.logf("session %04x tunnel %d connected", s.session.ID(), tunnelID)
	}()
}

func (s *serverSession) queue(data []byte) error {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	for s.session.Buffered() >= maxSessionQueue && !s.closed.Load() {
		s.queueCond.Wait()
	}
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.session.Queue(data)
	return nil
}

// Protocol control handlers run on the DNS reader: they must never wait for
// that same reader to ACK output and free space.
func (s *serverSession) queueControl(data []byte) error {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	if s.session.Buffered()+len(data) >= 60000 {
		s.session.Abort()
		return errors.New("dnscat2: control buffer limit")
	}
	s.session.Queue(data)
	return nil
}

func (s *serverSession) commandID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	if s.nextID == 0 || s.nextID > 0x7fff {
		s.nextID = 1
	}
	return s.nextID
}

func (s *serverSession) closeTunnel(id uint32, notify bool, reason string) {
	s.mu.Lock()
	tunnel := s.tunnels[id]
	delete(s.tunnels, id)
	delete(s.pending, uint16(id))
	s.mu.Unlock()
	if tunnel == nil {
		return
	}
	tunnel.close()
	if notify {
		command := protocol.NewTunnelClose(s.commandID(), id, reason)
		encoded, _ := command.MarshalBinary()
		_ = s.queue(encoded)
	}
}

func (s *serverSession) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.mu.Lock()
		tunnels := s.tunnels
		s.tunnels = make(map[uint32]*serverTunnel)
		s.pending = make(map[uint16]bool)
		s.mu.Unlock()
		s.cancel()
		s.session.Abort()
		s.queueMu.Lock()
		s.queueCond.Broadcast()
		s.queueMu.Unlock()
		for _, tunnel := range tunnels {
			tunnel.close()
		}
	})
}

type serverTunnel struct {
	session   *serverSession
	id        uint32
	conn      net.Conn
	writes    chan []byte
	done      chan struct{}
	once      sync.Once
	readDone  atomic.Bool
	writeDone atomic.Bool
}

func newServerTunnel(session *serverSession, id uint32, conn net.Conn) *serverTunnel {
	return &serverTunnel{
		session: session, id: id, conn: conn,
		writes: make(chan []byte, 128), done: make(chan struct{}),
	}
}

func (t *serverTunnel) readRemote() {
	buffer := make([]byte, 16*1024)
	for {
		length, err := t.conn.Read(buffer)
		if length > 0 {
			command := protocol.NewTunnelData(t.session.commandID(), t.id, buffer[:length])
			encoded, _ := command.MarshalBinary()
			if t.session.queue(encoded) != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				command := protocol.NewTunnelEOF(t.session.commandID(), t.id)
				encoded, _ := command.MarshalBinary()
				_ = t.session.queue(encoded)
				t.readDone.Store(true)
				t.closeIfDone()
			} else {
				t.session.closeTunnel(t.id, true, "Remote read error")
			}
			return
		}
	}
}

func (t *serverTunnel) writeLocal() {
	for {
		select {
		case data := <-t.writes:
			if data == nil {
				if conn, ok := t.conn.(interface{ CloseWrite() error }); ok {
					_ = conn.CloseWrite()
				}
				t.writeDone.Store(true)
				t.closeIfDone()
				return
			}
			_ = t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			for len(data) > 0 {
				written, err := t.conn.Write(data)
				if err != nil {
					t.session.closeTunnel(t.id, true, "Remote write error")
					return
				}
				data = data[written:]
			}
		case <-t.done:
			return
		case <-t.session.ctx.Done():
			return
		}
	}
}

func (t *serverTunnel) closeIfDone() {
	if t.readDone.Load() && t.writeDone.Load() {
		t.session.closeTunnel(t.id, false, "")
	}
}

func (t *serverTunnel) close() {
	t.once.Do(func() {
		close(t.done)
		_ = t.conn.Close()
	})
}

func (s *Server) String() string {
	return fmt.Sprintf("dnscat2 companion on %s", s.Addr())
}
