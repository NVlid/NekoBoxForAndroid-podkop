// Package stream implements bounded, deadline-aware multiplexed TCP streams.
package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const MaxReceiveBuffer = 256 * 1024

type Conn struct {
	Send         func(context.Context, []byte) error
	OnClose      func()
	OnCloseWrite func() error
	Address      string
	Parent       context.Context

	readMu        sync.Mutex
	writeMu       sync.Mutex
	mu            sync.Mutex
	buffer        bytes.Buffer
	notify        chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	readErr       error
	writeClosed   bool
	once          sync.Once
}

func New(ctx context.Context, address string, send func(context.Context, []byte) error, close func()) *Conn {
	return &Conn{Parent: ctx, Address: address, Send: send, OnClose: close, notify: make(chan struct{})}
}

func (c *Conn) signalLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

// Feed never blocks the multiplexer's reader on a stalled consumer.
func (c *Conn) Feed(data []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.readErr != nil {
		return false
	}
	if c.buffer.Len()+len(data) > MaxReceiveBuffer {
		return false
	}
	c.buffer.Write(data)
	c.signalLocked()
	return true
}

func (c *Conn) EndRead(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	c.readErr = err
	c.signalLocked()
	c.mu.Unlock()
}

func (c *Conn) EndWrite() {
	c.mu.Lock()
	c.writeClosed = true
	c.signalLocked()
	c.mu.Unlock()
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if c.buffer.Len() > 0 {
			n, err := c.buffer.Read(p)
			c.mu.Unlock()
			return n, err
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		notify, deadline := c.notify, c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case <-notify:
		case <-timerC:
		case <-c.Parent.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		if c.closed || c.writeClosed {
			c.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		deadline, notify := c.writeDeadline, c.notify
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return written, os.ErrDeadlineExceeded
		}
		ctx, cancel := context.WithCancel(c.Parent)
		if !deadline.IsZero() {
			cancel()
			ctx, cancel = context.WithDeadline(c.Parent, deadline)
		}
		// Wake a pending queue send when Close/SetWriteDeadline is called.
		done := make(chan struct{})
		go func() {
			select {
			case <-notify:
				cancel()
			case <-done:
			case <-ctx.Done():
			}
		}()
		n := min(len(p), 16*1024)
		err := c.Send(ctx, append([]byte(nil), p[:n]...))
		close(done)
		cancel()
		if err != nil {
			c.mu.Lock()
			closed := c.closed || c.writeClosed
			expired := !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline)
			c.mu.Unlock()
			if closed {
				return written, io.ErrClosedPipe
			}
			if expired {
				return written, os.ErrDeadlineExceeded
			}
			if c.Parent.Err() != nil {
				return written, net.ErrClosed
			}
			// A deadline update or inbound data woke the sender; try again.
			if err == context.Canceled || err == context.DeadlineExceeded {
				continue
			}
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *Conn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.buffer.Reset()
		c.signalLocked()
		c.mu.Unlock()
		if c.OnClose != nil {
			c.OnClose()
		}
	})
	return nil
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.writeClosed || c.closed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.signalLocked()
	c.mu.Unlock()
	if c.OnCloseWrite != nil {
		return c.OnCloseWrite()
	}
	return c.Close()
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	c.signalLocked()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.signalLocked()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	c.signalLocked()
	return nil
}
func (c *Conn) LocalAddr() net.Addr  { return addr("local") }
func (c *Conn) RemoteAddr() net.Addr { return addr(c.Address) }

type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }
