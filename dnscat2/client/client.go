// Package client provides a TCP-only dnscat2 tunnel client.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/protocol"
)

const (
	defaultDelay        = time.Second
	maxBufferedCommands = 256
	maxSessionBuffer    = 32 * 1024
)

type Transport interface {
	Exchange(ctx context.Context, payload []byte) ([]byte, error)
	MaxPayload() int
	Close() error
}

type Config struct {
	Secret         string
	Delay          time.Duration
	MaxRetransmits int
}

type Client struct {
	config    Config
	transport Transport

	mu      sync.Mutex
	current *instance
	closed  bool
}

func New(config Config, transport Transport) (*Client, error) {
	if config.Secret == "" {
		return nil, errors.New("dnscat2: pre-shared secret is required")
	}
	if transport == nil || transport.MaxPayload() < 73 {
		return nil, errors.New("dnscat2: invalid or too small transport")
	}
	if config.Delay <= 0 {
		config.Delay = defaultDelay
	}
	if config.Delay < 50*time.Millisecond || config.Delay > time.Minute {
		return nil, errors.New("dnscat2: packet delay must be between 50 ms and 1 minute")
	}
	if config.MaxRetransmits == 0 {
		config.MaxRetransmits = 20
	}
	if config.MaxRetransmits < 0 {
		return nil, errors.New("dnscat2: max retransmits cannot be negative")
	}
	return &Client{config: config, transport: transport}, nil
}

func (c *Client) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, err
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		return nil, errors.New("dnscat2: invalid destination port")
	}
	port := uint16(portValue)
	inst, err := c.getInstance()
	if err != nil {
		return nil, err
	}
	requestID, conn, resultChannel, err := inst.reserve()
	if err != nil {
		return nil, err
	}
	connect, err := protocol.NewTunnelConnect(requestID, host, port)
	if err != nil {
		inst.release(requestID)
		conn.Close()
		return nil, err
	}
	encoded, err := connect.MarshalBinary()
	if err != nil {
		inst.release(requestID)
		conn.Close()
		return nil, err
	}
	if err := inst.enqueue(ctx, encoded); err != nil {
		inst.release(requestID)
		conn.Close()
		return nil, err
	}
	select {
	case result := <-resultChannel:
		if result.err != nil {
			inst.removeTunnel(conn.id)
			inst.release(requestID)
			conn.closeRemote(result.err, "")
			return nil, result.err
		}
		return conn, nil
	case <-ctx.Done():
		_ = conn.Close()
		inst.release(requestID)
		return nil, ctx.Err()
	case <-inst.done:
		_ = conn.Close()
		inst.release(requestID)
		return nil, inst.err()
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.resetLocked()
}

// Reset drops network-bound state but permits a new session on the next dial.
func (c *Client) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resetLocked()
}

func (c *Client) resetLocked() error {
	current := c.current
	c.current = nil
	if current != nil {
		current.cancel()
		<-current.stopped
	}
	return c.transport.Close()
}

func (c *Client) getInstance() (*instance, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.current != nil {
		select {
		case <-c.current.done:
			<-c.current.stopped
		default:
			return c.current, nil
		}
	}
	session, err := protocol.NewClientSession(c.config.Secret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	inst := &instance{
		client: c, ctx: ctx, cancel: cancel, session: session,
		queue: make(chan []byte, maxBufferedCommands), wake: make(chan struct{}, 1),
		done: make(chan struct{}), pending: make(map[uint16]chan connectResult),
		tunnels: make(map[uint32]*Conn),
		stopped: make(chan struct{}), used: make(map[uint16]bool),
	}
	c.current = inst
	go inst.run()
	return inst, nil
}

type connectResult struct {
	err error
}

type instance struct {
	client  *Client
	ctx     context.Context
	cancel  context.CancelFunc
	session *protocol.Session
	queue   chan []byte
	wake    chan struct{}
	done    chan struct{}
	stopped chan struct{}
	used    map[uint16]bool

	mu             sync.Mutex
	nextID         uint16
	pending        map[uint16]chan connectResult
	tunnels        map[uint32]*Conn
	terminal       error
	closeOnce      sync.Once
	commandDecoder protocol.CommandDecoder
}

func (i *instance) run() {
	defer close(i.stopped)
	defer i.shutdown(errors.New("dnscat2: session stopped"))
	failures := 0
	for {
		if i.ctx.Err() != nil {
			return
		}
		i.drainQueue()
		failures++
		if failures > i.client.config.MaxRetransmits {
			i.shutdown(errors.New("dnscat2: valid response timeout"))
			return
		}
		query, err := i.session.NextPacket(i.client.transport.MaxPayload())
		if err != nil {
			i.shutdown(err)
			return
		}
		response, err := i.client.transport.Exchange(i.ctx, query)
		if err != nil {
			if i.ctx.Err() != nil {
				return
			}
			if i.client.config.MaxRetransmits > 0 && failures > i.client.config.MaxRetransmits {
				i.shutdown(fmt.Errorf("dnscat2: no valid response after %d attempts: %w", failures, err))
				return
			}
			if !i.wait(retryDelay(i.client.config.Delay, failures)) {
				return
			}
			continue
		}
		if len(response) == 0 {
			if !i.wait(i.client.config.Delay) {
				return
			}
			continue
		}
		result, err := i.session.Receive(response, i.client.transport.MaxPayload())
		if errors.Is(err, protocol.ErrPacketDiscarded) {
			if !i.wait(i.client.config.Delay) {
				return
			}
			continue
		}
		if err != nil {
			i.shutdown(err)
			return
		}
		failures = 0
		if len(result.Incoming) > 0 {
			if err := i.feed(result.Incoming); err != nil {
				i.shutdown(err)
				return
			}
		}
		i.drainQueue()
		if result.Immediate {
			continue
		}
		if !i.wait(i.client.config.Delay) {
			return
		}
	}
}

func (i *instance) feed(data []byte) error {
	commands, err := i.commandDecoder.Feed(data)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := i.handleCommand(command); err != nil {
			return err
		}
	}
	return nil
}

func (i *instance) handleCommand(command protocol.Command) error {
	switch command.Type {
	case protocol.TunnelConnect:
		if !command.Response {
			return errors.New("dnscat2: companion sent an unexpected connect request")
		}
		tunnelID, err := protocol.ParseTunnelConnectResponse(command)
		if err != nil {
			return err
		}
		if uint32(command.RequestID) != tunnelID {
			return errors.New("dnscat2: companion returned a mismatched tunnel ID")
		}
		i.deliverPending(command.RequestID, nil)
	case protocol.TunnelData:
		tunnelID, data, err := protocol.ParseTunnelData(command)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
		i.mu.Lock()
		conn := i.tunnels[tunnelID]
		i.mu.Unlock()
		if conn != nil {
			conn.feed(data)
		}
	case protocol.TunnelClose:
		tunnelID, reason, err := protocol.ParseTunnelClose(command)
		if err != nil {
			return err
		}
		conn := i.removeTunnel(tunnelID)
		if conn != nil {
			conn.closeRemote(io.EOF, reason)
		}
	case protocol.TunnelEOF:
		id, err := protocol.ParseTunnelEOF(command)
		if err != nil {
			return err
		}
		i.mu.Lock()
		conn := i.tunnels[id]
		i.mu.Unlock()
		if conn != nil {
			conn.EndRead(io.EOF)
		}
	case protocol.CommandPing:
		value, err := protocol.ParsePing(command)
		if err != nil {
			return err
		}
		if !command.Response {
			response, _ := protocol.NewPing(command.RequestID, true, value)
			encoded, _ := response.MarshalBinary()
			i.session.Queue(encoded)
		}
	case protocol.CommandError:
		_, reason, err := protocol.ParseCommandError(command)
		if err != nil {
			return err
		}
		i.deliverPending(command.RequestID, errors.New("dnscat2: companion: "+reason))
	case protocol.CommandShell, protocol.CommandExec, protocol.CommandDownload, protocol.CommandUpload, protocol.CommandDelay:
		if !command.Response {
			errorCommand := protocol.NewCommandError(command.RequestID, 0x8000, "command is not supported by NekoBox")
			encoded, _ := errorCommand.MarshalBinary()
			i.session.Queue(encoded)
		}
	}
	return nil
}

func (i *instance) drainQueue() {
	for i.session.Buffered() < maxSessionBuffer {
		select {
		case command := <-i.queue:
			i.session.Queue(command)
		default:
			return
		}
	}
}

func (i *instance) wait(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-i.wake:
		return true
	case <-i.ctx.Done():
		return false
	}
}

func retryDelay(base time.Duration, failures int) time.Duration {
	if failures > 4 {
		failures = 4
	}
	delay := base * time.Duration(1<<failures)
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func (i *instance) enqueue(ctx context.Context, command []byte) error {
	select {
	case i.queue <- command:
		select {
		case i.wake <- struct{}{}:
		default:
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-i.done:
		return i.err()
	case <-i.ctx.Done():
		return net.ErrClosed
	}
}

func (i *instance) commandID() uint16 {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.nextID++
	if i.nextID == 0 || i.nextID > 0x7fff {
		i.nextID = 1
	}
	return i.nextID
}

func (i *instance) reserve() (uint16, *Conn, chan connectResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for range 32768 {
		i.nextID++
		if i.nextID == 0 || i.nextID > 0x7fff {
			i.nextID = 1
		}
		if i.used[i.nextID] {
			continue
		}
		if i.ctx.Err() != nil {
			return 0, nil, nil, net.ErrClosed
		}
		i.used[i.nextID] = true
		result := make(chan connectResult, 1)
		conn := newConn(i, uint32(i.nextID))
		i.pending[i.nextID] = result
		i.tunnels[conn.id] = conn
		return i.nextID, conn, result, nil
	}
	return 0, nil, nil, errors.New("dnscat2: tunnel IDs exhausted; reconnect")
}

func (i *instance) release(id uint16) {
	i.mu.Lock()
	delete(i.pending, id)
	i.mu.Unlock()
}

func (i *instance) deliverPending(id uint16, err error) {
	i.mu.Lock()
	channel := i.pending[id]
	delete(i.pending, id)
	i.mu.Unlock()
	if channel != nil {
		channel <- connectResult{err: err}
	}
}

func (i *instance) removeTunnel(id uint32) *Conn {
	i.mu.Lock()
	conn := i.tunnels[id]
	delete(i.tunnels, id)
	i.mu.Unlock()
	return conn
}

func (i *instance) shutdown(err error) {
	i.closeOnce.Do(func() {
		i.mu.Lock()
		i.terminal = err
		pending := i.pending
		tunnels := i.tunnels
		i.pending = make(map[uint16]chan connectResult)
		i.tunnels = make(map[uint32]*Conn)
		i.mu.Unlock()
		i.cancel()
		close(i.done)
		for _, channel := range pending {
			channel <- connectResult{err: err}
		}
		for _, conn := range tunnels {
			conn.closeRemote(net.ErrClosed, err.Error())
		}
		_ = i.client.transport.Close()
	})
}

func (i *instance) err() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal == nil {
		return net.ErrClosed
	}
	return i.terminal
}
