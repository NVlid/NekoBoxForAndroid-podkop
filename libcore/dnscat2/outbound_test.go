package dnscat2

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/server"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

func TestOutboundToCompanion(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(server.Config{Secret: "public-test-secret"}, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()
	created, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", OutboundOptions{
		Server: "127.0.0.1", ServerPort: uint16(udp.LocalAddr().(*net.UDPAddr).Port),
		Secret: "public-test-secret", Delay: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	o := created.(*Outbound)
	defer o.client.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("native outbound")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("native outbound"))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "native outbound" {
		t.Fatal("echo mismatch")
	}
	if _, err := o.DialContext(ctx, "udp", M.ParseSocksaddr(echo.Addr().String())); err == nil {
		t.Fatal("UDP must be rejected")
	}
}
