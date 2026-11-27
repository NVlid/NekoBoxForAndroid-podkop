package client

import (
	"context"
	"errors"
	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/protocol"
	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/stream"
	"io"
)

type Conn struct {
	*stream.Conn
	id uint32
}

func newConn(i *instance, id uint32) *Conn {
	conn := stream.New(i.ctx, "dnscat2 tunnel",
		func(ctx context.Context, data []byte) error {
			command := protocol.NewTunnelData(i.commandID(), id, data)
			encoded, err := command.MarshalBinary()
			if err != nil {
				return err
			}
			return i.enqueue(ctx, encoded)
		}, func() {
			i.removeTunnel(id)
			command := protocol.NewTunnelClose(i.commandID(), id, "Connection closed")
			encoded, _ := command.MarshalBinary()
			// Close cannot stall a mux read-loop. If the control queue is full,
			// terminate the session instead of dropping its teardown message.
			select {
			case <-i.ctx.Done():
			case i.queue <- encoded:
				select {
				case i.wake <- struct{}{}:
				default:
				}
			default:
				i.cancel()
			}
		})
	conn.OnCloseWrite = func() error {
		command := protocol.NewTunnelEOF(i.commandID(), id)
		encoded, _ := command.MarshalBinary()
		return i.enqueue(i.ctx, encoded)
	}
	return &Conn{Conn: conn, id: id}
}

func (c *Conn) closeRemote(err error, _ string) {
	if err == nil {
		err = io.EOF
	}
	c.EndRead(err)
	c.EndWrite()
}

func (c *Conn) feed(data []byte) {
	if !c.Feed(data) {
		c.EndRead(errors.New("dnscat2: receive buffer limit exceeded"))
		c.Close()
	}
}
