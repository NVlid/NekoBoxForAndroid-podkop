package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NVlid/NekoBoxForAndroid-podkop/dnscat2/server"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:5353", "UDP listen address (an unprivileged port needs no root)")
	domain := flag.String("domain", "", "authoritative tunnel domain; empty enables direct dnscat. mode")
	secretFile := flag.String("secret-file", "", "file containing the PSK (otherwise DNSCAT2_SECRET is used)")
	maxSessions := flag.Int("max-sessions", 128, "maximum concurrent dnscat2 sessions")
	sessionTimeout := flag.Duration("session-timeout", 15*time.Minute, "idle session timeout")
	flag.Parse()

	secret := os.Getenv("DNSCAT2_SECRET")
	if *secretFile != "" {
		content, err := os.ReadFile(*secretFile)
		if err != nil {
			log.Fatalf("read secret file: %v", err)
		}
		secret = strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r")
	}
	if secret == "" {
		log.Fatal("set DNSCAT2_SECRET or -secret-file; never put the PSK in a process argument")
	}
	host, portText, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("invalid -listen address: %v", err)
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		log.Fatal("invalid -listen port")
	}
	logger := log.New(os.Stderr, "dnscat2-companion: ", log.LstdFlags|log.LUTC)
	companion, err := server.Listen(server.Config{
		Domain: *domain, Secret: secret, MaxSessions: *maxSessions,
		SessionTimeout: *sessionTimeout, Logger: logger,
	}, host, uint16(portValue))
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer companion.Close()
	if *domain == "" {
		logger.Printf("listening on %s in direct dnscat. mode", companion.Addr())
	} else {
		logger.Printf("listening on %s for authoritative domain %s", companion.Addr(), *domain)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		_ = companion.Close()
	}()
	if err := companion.Serve(); err != nil {
		logger.Fatal(err)
	}
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
}
