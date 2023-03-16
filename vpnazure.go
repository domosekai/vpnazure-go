package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"vpnazure-go/internal/logger"
)

var listenAddr = flag.String("b", "", "Listening address and port")
var suffixFile = flag.String("suffix", "", "File that contains DNS suffixes of the service")
var authFile = flag.String("auth", "", "File that contains server credentials")
var logFile = flag.String("log", "", "Path to the log file")
var version = "unknown"
var build = "unknown"

// Global variables are thread-safe
var (
	lg       logger.Logger
	suffixes suffixList
	auths    authList
	sessions sessionList
)

func main() {
	flag.Parse()
	if flag.NArg() > 0 || len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "vpnazure-go version %s (build %s) usage:\n", version, build)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Open log file or write to stdout
	lg.Open(*logFile, true)
	defer lg.Close()

	// Read DNS suffix from file
	if n := suffixes.read(*suffixFile); n > 0 {
		lg.Printf("Loaded %d suffixes", n)
	} else {
		log.Fatalf("At least 1 DNS suffix is needed")
	}

	// Read server credentials
	if n := auths.read(*authFile); n > 0 {
		lg.Printf("Loaded %d server credentials", n)
	} else {
		log.Fatalf("At least 1 server credential is needed")
	}

	go listenSignal()

	// Start listener
	config := &tls.Config{GetConfigForClient: getConfigForClient}
	listener, err := tls.Listen("tcp", *listenAddr, config)
	if err != nil {
		log.Fatalln(err)
	}

	// Print session status with ticker
	go func() {
		ticker := time.Tick(15 * time.Minute)
		for range ticker {
			sessions.printStatus()
		}
	}()

	sessions.servers = make(map[string]serverSession)
	sessions.relaying = make(map[uint64]relayingSession)
	sessions.pending = make(map[uint64]pendingSession)

	// connection counter
	var num uint64

	for {
		conn, err := listener.Accept()
		if err != nil {
			lg.Println(err)
			continue
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			num++
			go func(num uint64) {
				defer conn.Close()
				if err := tlsConn.Handshake(); err != nil {
					lg.PrintSessionf("TLS handshake failed: %s", num, ' ', 0, err)
					return
				}
				state := tlsConn.ConnectionState()
				hostname, suffix, server, ok := suffixes.parse(state.ServerName)
				if !ok {
					lg.PrintSessionf("SNI %s does not match any suffix", num, ' ', 0, state.ServerName)
					return
				}
				if server {
					handleServer(num, tlsConn, suffix)
				} else {
					handleClient(num, tlsConn, hostname)
				}
			}(num)
		} else {
			conn.Close()
		}
	}

}
