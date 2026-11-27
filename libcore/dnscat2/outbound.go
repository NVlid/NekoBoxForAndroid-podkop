// Package dnscat2 registers the embedded NekoBox dnscat2 outbound.
package dnscat2

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/client"
	dnscat2transport "github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/transport"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const Type = "dnscat2"

type OutboundOptions struct {
	option.DialerOptions
	Server         string `json:"server,omitempty"`
	ServerPort     uint16 `json:"server_port,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Secret         string `json:"secret"`
	RecordTypes    string `json:"record_types,omitempty"`
	Delay          uint32 `json:"delay,omitempty"`
	RequestTimeout uint32 `json:"request_timeout,omitempty"`
	MaxRetransmits int    `json:"max_retransmits,omitempty"`
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	client *client.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" {
		return nil, E.New("dnscat2: DNS server is required")
	}
	if options.Secret == "" {
		return nil, E.New("dnscat2: a pre-shared secret is required")
	}
	if options.ServerPort == 0 {
		options.ServerPort = 53
	}
	if options.Delay == 0 {
		options.Delay = 1000
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = 3000
	}
	codec, err := dnscat2transport.NewCodec(options.Domain)
	if err != nil {
		return nil, err
	}
	recordTypes, err := dnscat2transport.ParseRecordTypes(options.RecordTypes)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, net.ParseIP(options.Server) == nil)
	if err != nil {
		return nil, err
	}
	transport, err := dnscat2transport.NewUDPClient(
		codec, options.Server, options.ServerPort, recordTypes,
		time.Duration(options.RequestTimeout)*time.Millisecond,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			return outboundDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
	)
	if err != nil {
		return nil, err
	}
	tunnelClient, err := client.New(client.Config{
		Secret:         options.Secret,
		Delay:          time.Duration(options.Delay) * time.Millisecond,
		MaxRetransmits: options.MaxRetransmits,
	}, transport)
	if err != nil {
		transport.Close()
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP}, options.DialerOptions),
		client:  tunnelClient,
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(o.client.Close)
	}
	return nil
}

func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	_ = o.client.Reset()
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("dnscat2: only TCP is supported")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	return o.client.DialContext(ctx, destination.String())
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)
