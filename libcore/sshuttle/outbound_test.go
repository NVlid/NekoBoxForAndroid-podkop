package sshuttle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	mux "github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/sshuttle"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/ssh"
)

func sshTestServer(t *testing.T, python string) (string, ssh.Signer) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if c.User() != "test" || string(password) != "public-test-password" {
			return nil, errors.New("auth failed")
		}
		return nil, nil
	}}
	config.AddHostKey(key)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						channel.Reject(ssh.UnknownChannelType, "exec only")
						continue
					}
					ch, reqs, err := channel.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range reqs {
							var command struct{ Command string }
							if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "'python3' -c '"+escape(mux.Bootstrap)+"'" {
								req.Reply(false, nil)
								continue
							}
							cmd := exec.Command(python, "-c", mux.Bootstrap)
							cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
							if err := cmd.Start(); err != nil {
								req.Reply(false, nil)
								return
							}
							req.Reply(true, nil)
							cmd.Wait()
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), key
}

func TestSSHHostKeyMismatch(t *testing.T) {
	address, _ := sshTestServer(t, "")
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	untrusted, _ := ssh.NewSignerFromKey(private)
	host, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	created, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", Options{
		ServerOptions: option.ServerOptions{Server: host, ServerPort: uint16(port)},
		User:          "test", Password: "public-test-password", HostKey: string(ssh.MarshalAuthorizedKey(untrusted.PublicKey())),
	})
	if err != nil {
		t.Fatal(err)
	}
	o := created.(*Outbound)
	defer o.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := o.connect(ctx); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("untrusted SSH server was not rejected: %v", err)
	}
}

func TestSSHExecUpstreamEndToEnd(t *testing.T) {
	python := os.Getenv("SSHUTTLE_TEST_PYTHON")
	if python == "" {
		t.Skip("set SSHUTTLE_TEST_PYTHON to exercise Python over actual SSH exec")
	}
	address, key := sshTestServer(t, python)
	host, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	created, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", Options{
		ServerOptions: option.ServerOptions{Server: host, ServerPort: uint16(port)},
		User:          "test", Password: "public-test-password", HostKey: string(ssh.MarshalAuthorizedKey(key.PublicKey())),
	})
	if err != nil {
		t.Fatal(err)
	}
	o := created.(*Outbound)
	defer func() { o.cancel(); o.InterfaceUpdated(context.Background()) }()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		conn.Write(data)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("sshuttle over real SSH exec")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "sshuttle over real SSH exec" {
		t.Fatalf("echo: %q %v", data, err)
	}
}
