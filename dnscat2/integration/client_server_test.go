package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/client"
	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/server"
	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/transport"
	"github.com/miekg/dns"
)

func TestClientCompanionTCPEndToEnd(t *testing.T) {
	for _,record:=range []uint16{dns.TypeTXT,dns.TypeCNAME,dns.TypeMX,dns.TypeA,dns.TypeAAAA} {
		t.Run(dns.TypeToString[record],func(t *testing.T) { testClientCompanion(t,record) })
	}
}

func testClientCompanion(t *testing.T, record uint16) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	companion, err := server.New(server.Config{Secret: "integration secret",Domain:"tunnel.example.test"}, udpListener)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = companion.Serve() }()
	defer companion.Close()

	_, portText, _ := net.SplitHostPort(companion.Addr().String())
	port64, _ := strconv.ParseUint(portText, 10, 16)
	codec, _ := transport.NewCodec("tunnel.example.test")
	udpClient, err := transport.NewUDPClient(codec, "127.0.0.1", uint16(port64), []uint16{record}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnelClient, err := client.New(client.Config{
		Secret: "integration secret", Delay: 50 * time.Millisecond, MaxRetransmits: 5,
	}, udpClient)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelClient.Close()

	const tunnelCount = 3
	var wait sync.WaitGroup
	errorsChannel := make(chan error, tunnelCount)
	for tunnel := 0; tunnel < tunnelCount; tunnel++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := tunnelClient.DialContext(ctx, echoListener.Addr().String())
			if err != nil {
				errorsChannel <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			payload := make([]byte, 8192+tunnel)
			for index := range payload {
				payload[index] = byte(index + tunnel)
			}
			if _, err := conn.Write(payload); err != nil {
				errorsChannel <- err
				return
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(response, payload) {
				errorsChannel <- fmt.Errorf("echo payload mismatch on tunnel %d", tunnel)
				return
			}
			errorsChannel <- nil
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Reset must finish the old transport loop before a new one can use it.
	if err:=tunnelClient.Reset(); err!=nil { t.Fatal(err) }
	half,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	defer half.Close()
	go func(){
		conn,err:=half.Accept()
		if err!=nil { return }
		defer conn.Close()
		data,_:=io.ReadAll(conn)
		conn.Write(data)
	}()
	ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
	defer cancel()
	conn,err:=tunnelClient.DialContext(ctx,half.Addr().String())
	if err!=nil { t.Fatal(err) }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15*time.Second))
	payload:=bytes.Repeat([]byte("half-close"),4096)
	if _,err=conn.Write(payload); err!=nil { t.Fatal(err) }
	if err=conn.(interface{CloseWrite() error}).CloseWrite(); err!=nil { t.Fatal(err) }
	response,err:=io.ReadAll(conn)
	if err!=nil || !bytes.Equal(payload,response) { t.Fatalf("half-close echo: %d bytes, %v",len(response),err) }
}
