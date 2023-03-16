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
func handleClient(num uint64, conn *tls.Conn, hostname string) {
	lg.PrintSessionf("New client connection from %s for %s", num, 'C', 1, conn.RemoteAddr(), hostname)

	// Find server control session
	// buffered because channel might never be read
	ch := make(chan clientCommand, 1)
	if err := sessions.clientRequest(num, hostname, conn, ch); err != nil {
		lg.PrintSessionf("Connection closed: %s", num, 'C', 3, err)
		return
	}
	lg.PrintSessionf("Waiting for server to connect", num, 'C', 2)

	// Wait for server to connect
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case s := <-ch:
		lg.PrintSessionf("Relaying data from server session %d", num, 'C', 2, s.num)
		n, _ := io.Copy(conn, s.conn)
		lg.PrintSessionf("Client session closed: relayed %d bytes from server to client", num, 'C', 3, n)
	case <-timer.C:
		// Timeout
		lg.PrintSessionf("Connection closed: server did not respond", num, 'C', 3)
		sessions.delRequest(num)
	}
}
