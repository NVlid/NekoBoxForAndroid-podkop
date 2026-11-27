package sshuttle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	mux "github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/sshuttle"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"
)

type Options struct {
	option.DialerOptions
	option.ServerOptions
	User                 string `json:"user"`
	Password             string `json:"password,omitempty"`
	PrivateKey           string `json:"private_key,omitempty"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitempty"`
	HostKey              string `json:"host_key"`
	Python               string `json:"python,omitempty"`
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[Options](registry, "sshuttle", NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	dialer     N.Dialer
	server     M.Socksaddr
	config     *ssh.ClientConfig
	python     string
	connectMu  sync.Mutex
	mu         sync.Mutex
	current    *mux.Mux
	generation uint64
	lifetime   context.Context
	cancel     context.CancelFunc
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	if options.Server == "" || options.User == "" || options.HostKey == "" {
		return nil, errors.New("sshuttle: server, user and trusted SSH host public key are required")
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(options.HostKey))
	if err != nil {
		return nil, errors.New("sshuttle: invalid SSH host public key")
	}
	auth := []ssh.AuthMethod{}
	if options.Password != "" {
		auth = append(auth, ssh.Password(options.Password))
	}
	if options.PrivateKey != "" {
		var signer ssh.Signer
		if options.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(options.PrivateKey), []byte(options.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(options.PrivateKey))
		}
		if err != nil {
			return nil, errors.New("sshuttle: invalid private key or passphrase")
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, errors.New("sshuttle: password or private key is required")
	}
	if options.Python == "" {
		options.Python = "python3"
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`).MatchString(options.Python) {
		return nil, errors.New("sshuttle: python must be an executable path, not a shell command")
	}
	d, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	server := options.ServerOptions.Build()
	if server.Port == 0 {
		server.Port = 22
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions("sshuttle", tag, []string{N.NetworkTCP}, options.DialerOptions),
		dialer:  d, server: server, python: options.Python, lifetime: lifetime, cancel: cancel,
		config: &ssh.ClientConfig{User: options.User, Auth: auth, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), hostKey.Marshal()) {
				return errors.New("sshuttle: SSH host key mismatch")
			}
			return nil
		}},
	}, nil
}

func (o *Outbound) connect(ctx context.Context) (*mux.Mux, error) {
	o.connectMu.Lock()
	defer o.connectMu.Unlock()
	o.mu.Lock()
	current := o.current
	generation := o.generation
	o.mu.Unlock()
	if current != nil && current.Alive() {
		return current, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(o.lifetime, cancel)
	defer stopLifetime()
	conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.server)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	cc, channels, requests, err := ssh.NewClientConn(conn, o.server.String(), o.config)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(cc, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	r, err := session.StdoutPipe()
	if err != nil {
		client.Close()
		return nil, err
	}
	w, err := session.StdinPipe()
	if err != nil {
		client.Close()
		return nil, err
	}
	// Do not leak remote messages/credentials into Android logs.
	session.Stderr = io.Discard
	command := "'" + o.python + "' -c '" + escape(mux.Bootstrap) + "'"
	if err := session.Start(command); err != nil {
		client.Close()
		return nil, err
	}
	m, err := mux.New(r, w, func() { session.Close(); client.Close(); conn.Close() })
	if err != nil {
		session.Close()
		client.Close()
		return nil, errors.New("sshuttle: server startup failed; install Python 3 and sshuttle 1.3.2 and check SSH exec permission")
	}
	// Stop the handshake timeout callback before publishing a live mux.
	if !stop() || ctx.Err() != nil || o.lifetime.Err() != nil {
		m.Close()
		return nil, context.Canceled
	}
	_ = conn.SetDeadline(time.Time{})
	o.mu.Lock()
	if generation != o.generation || o.lifetime.Err() != nil {
		o.mu.Unlock()
		m.Close()
		return nil, errors.New("sshuttle: network changed during connection establishment")
	}
	o.current = m
	o.mu.Unlock()
	succeeded = true
	return m, nil
}

func escape(s string) string {
	var result []byte
	for _, b := range []byte(s) {
		if b == '\'' {
			result = append(result, []byte("'\"'\"'")...)
		} else {
			result = append(result, b)
		}
	}
	return string(result)
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { o.cancel(); o.InterfaceUpdated(context.Background()); return nil })
	}
	return nil
}
func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	o.mu.Lock()
	o.generation++
	current := o.current
	o.current = nil
	o.mu.Unlock()
	if current != nil {
		current.Close()
	}
}
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, errors.New("sshuttle: only TCP is supported")
	}
	m, err := o.connect(ctx)
	if err != nil {
		return nil, err
	}
	return m.DialContext(ctx, destination.String())
}
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

var _ adapter.Outbound = (*Outbound)(nil)
var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)
