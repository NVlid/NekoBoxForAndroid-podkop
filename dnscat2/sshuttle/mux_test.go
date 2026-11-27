package sshuttle

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This test runs the actual upstream Python server, not a Go peer that could
// share the same protocol bug. CI installs the pinned sshuttle wheel.
func TestUpstreamPythonServer(t *testing.T) {
	python := os.Getenv("SSHUTTLE_TEST_PYTHON")
	if python == "" {
		t.Skip("set SSHUTTLE_TEST_PYTHON with sshuttle==1.3.2 installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", Bootstrap)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	w, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	m, err := New(r, w, func() { w.Close(); cmd.Process.Kill() })
	if err != nil {
		t.Fatalf("startup: %v; stderr: %s", err, stderr.String())
	}
	defer m.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Force a half-close: no response until the upstream stream EOF.
				data, _ := io.ReadAll(conn)
				conn.Write(data)
			}()
		}
	}()
	for iteration := 0; iteration < 3; iteration++ {
		conn, err := m.DialContext(ctx, listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		data := bytes.Repeat([]byte{byte(iteration), 0, 255, 4}, 32768)
		if _, err = conn.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, response) {
			t.Fatalf("payload mismatch: got %d want %d", len(response), len(data))
		}
		conn.Close()
	}
}
