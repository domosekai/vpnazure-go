// Handle VPN client connections

package main

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

type clientCommand struct {
	num  uint64
	conn net.Conn
}

// Handle new client connection
func handleClient(num uint64, conn *tls.Conn, hostname string, suffix *suffix) {
	lg.Printf("C %5d: New client connection from %s for %s", num, conn.RemoteAddr(), hostname)

	// Find server control session
	// buffered because channel might never be read
	ch := make(chan clientCommand, 1)
	if err := sessions.clientRequest(num, hostname, conn, ch); err != nil {
		lg.Printf("C %5d: Connection closed: %s", num, err)
		return
	}
	lg.Printf("C %5d: Waiting for server to connect", num)

	// Wait for server to connect
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case s := <-ch:
		lg.Printf("C %5d: Relaying data from server session %d", num, s.num)
		n, _ := io.CopyBuffer(conn, s.conn, nil)
		lg.Printf("C %5d: Client session closed: relayed %d bytes from server to client", num, n)
	case <-timer.C:
		// Timeout
		lg.Printf("C %5d: Connection closed: server did not respond", num)
		sessions.delRequest(num)
	}
}
