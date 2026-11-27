package stream

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestChangeReadDeadlineWhileBlocked(t *testing.T) {
	c := New(context.Background(), "test", nil, nil)
	defer c.Close()
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked reader ignored deadline change")
	}
}

func TestCloseCancelsBlockedWrite(t *testing.T) {
	start := make(chan struct{})
	c := New(context.Background(), "test", func(ctx context.Context, _ []byte) error {
		close(start)
		<-ctx.Done()
		return ctx.Err()
	}, nil)
	result := make(chan error, 1)
	go func() { _, err := c.Write([]byte("data")); result <- err }()
	<-start
	c.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("write succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock write")
	}
}

func TestBoundedBufferAndClose(t *testing.T) {
	c := New(context.Background(), "test", nil, nil)
	if !c.Feed(make([]byte, MaxReceiveBuffer)) {
		t.Fatal("valid buffer refused")
	}
	if c.Feed([]byte{1}) {
		t.Fatal("unbounded buffer")
	}
	c.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
