package server

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestOriginalCClientHandshake(t *testing.T) {
	binary := os.Getenv("DNSCAT2_C_CLIENT")
	if binary == "" {
		t.Skip("set DNSCAT2_C_CLIENT to the compiled upstream client")
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Secret: "public-test-secret"}, listener)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-q", "-q", "-q", "--dns", "server=127.0.0.1,port="+strconv.Itoa(port), "--secret", "public-test-secret")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() { cancel(); <-exited }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("original C client did not complete encrypted/authenticated handshake")
		case <-ticker.C:
			s.mu.Lock()
			ok := false
			for _, session := range s.sessions {
				if session.session.Established() && session.session.Authenticated() {
					ok = true
				}
			}
			s.mu.Unlock()
			if ok {
				return
			}
		}
	}
}
