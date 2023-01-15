// Handle VPN server (azure client) connections

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

type serverOperation string

const (
	serverRelay serverOperation = "relay"
)

type serverCommand struct {
	op         serverOperation
	num        uint64
	hostname   string
	sessionID  []byte
	clientIP   net.IP
	clientPort int
}

// Handle new server connection
func handleServer(num uint64, conn *tls.Conn, suffix *suffix) {
	lg.PrintSessionf("New server connection from %s", num, ' ', 0, conn.RemoteAddr())
	b := make([]byte, 24)
	n, err := io.ReadAtLeast(conn, b, 4)
	if err != nil {
		lg.PrintSessionf("Invalid server connection", num, ' ', 0)
		return
	}

	if bytes.Equal(b[:4], []byte("ACTL")) {
		lg.PrintSessionf("Starting server control session from %s for suffix %s", num, 'L', 1, conn.RemoteAddr(), suffix.suffix)
		handleServerControl(num, conn, suffix)
		return
	}

	if n < 24 {
		if _, err := io.ReadFull(conn, b[n:]); err != nil {
			lg.PrintSessionf("Invalid server connection", num, ' ', 0)
			return
		}
	}

	if bytes.Equal(b, []byte("AZURE_CONNECT_SIGNATURE!")) {
		lg.PrintSessionf("Starting server data session from %s for suffix %s", num, 'S', 1, conn.RemoteAddr(), suffix.suffix)
		handleServerData(num, conn, suffix)
		return
	}

	lg.PrintSessionf("Invalid server connection", num, ' ', 0)
}

// Handle azure control session.
// conn automatically closes on return, do not fork.
func handleServerControl(num uint64, conn *tls.Conn, suffix *suffix) {
	random := make([]byte, 20)
	if _, err := rand.Read(random); err != nil {
		lg.PrintSessionf("Failed to generate a random", num, 'L', 3)
		return
	}
	// Send control pack to client
	p := pack{elements: map[string]packElement{
		"ControlKeepAlive": newPackElementInt(40000),
		"ControlTimeout":   newPackElementInt(60000),
		"DataTimeout":      newPackElementInt(40000),
		"SslTimeout":       newPackElementInt(5000),
		"Random":           newPackElementData(random),
	}}
	if _, err := p.send(conn, true); err != nil {
		lg.PrintSessionf("Session aborted: %s", num, 'L', 3, err)
		return
	}

	// Receive pack from client
	p, err := recvPack(conn, true)
	if err != nil {
		lg.PrintSessionf("Session aborted: %s", num, 'L', 3, err)
		return
	}

	// Authenticate
	var hostname string
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		var ok bool
		hostname, ok = p.getString("CurrentHostName", true)
		if !ok {
			lg.PrintSessionf("Session aborted: no hostname provided by peer", num, 'L', 3)
			return
		}
		clientInfo, ok := auths.find(hostname, suffix.suffix)
		if !ok {
			lg.PrintSessionf("Session aborted: hostname %s is invalid", num, 'L', 3, hostname)
			return
		}
		switch clientInfo.method {
		case authNone:
			lg.PrintSessionf("Authentication completed anonymously", num, 'L', 2)
		case authPassword:
			if hash, ok := p.getData("PasswordHash"); ok && clientInfo.checkPassword(hostname, random, hash) {
				lg.PrintSessionf("Authentication completed with password", num, 'L', 2)
			} else {
				lg.PrintSessionf("Session aborted: incorrect password", num, 'L', 3)
				return
			}
		case authCert:
			// Peer should but didn't provide certificate during TLS handshake
			lg.PrintSessionf("Session aborted: authentication failed with certificate", num, 'L', 3)
			return
		default:
			lg.PrintSessionf("Session aborted: unsupported authentication method", num, 'L', 3)
			return
		}
	} else {
		// Already authenticated by TLS
		hostname = strings.ToLower(state.PeerCertificates[0].Subject.CommonName)
		lg.PrintSessionf("Authentication completed with certificate", num, 'L', 2)
	}
	lg.PrintSessionf("Authenticated as %s", num, 'L', 2, hostname)

	// Add session
	if _, err := conn.Write([]byte{1}); err != nil {
		lg.PrintSessionf("Session aborted: %s", num, 'L', 3, err)
		return
	}
	if err := serverKeepAlive(conn); err != nil {
		lg.PrintSessionf("Session aborted: %s", num, 'L', 3, err)
		return
	}
	// non-buffered is ok but may block more often as sending signal to server takes time
	ch := make(chan serverCommand, 50)
	// channel operations other than receiving must be done in sessions to avoid race
	sessions.addServer(num, hostname, conn, ch)

	// Session starts
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				lg.PrintSessionf("Session closed", num, 'L', 3)
				return
			}
			switch c.op {
			case serverRelay:
				// send signal to server
				// In this implemention, relay server is the control server though they can differ
				remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
				localAddr := conn.LocalAddr().(*net.TCPAddr)
				p := pack{elements: map[string]packElement{
					"opcode":        newPackElementString(string(c.op)),
					"hostname":      newPackElementString(c.hostname),
					"session_id":    newPackElementData(c.sessionID),
					"client_port":   newPackElementInt(uint32(c.clientPort)),
					"server_port":   newPackElementInt(uint32(remoteAddr.Port)),
					"relay_address": newPackElementString(suffix.control),
					"relay_port":    newPackElementInt(uint32(localAddr.Port)),
					"cert_hash":     newPackElementData(suffix.certHash[:]),
				}}
				p.addIP("client_ip", c.clientIP)
				p.addIP("server_ip", remoteAddr.IP)
				_, err := conn.Write([]byte{1})
				if err == nil {
					_, err = p.send(conn, true)
				}
				if err == nil {
					lg.PrintSessionf("Signal sent to the server for client session %d", num, 'L', 2, c.num)
					b := make([]byte, 1)
					_, err = conn.Read(b)
				} else {
					lg.PrintSessionf("Failed to send signal to server: %s", num, 'L', 2, err)
				}
				if err != nil {
					go sessions.delServer(num, hostname)
				}
			}
		case <-ticker.C:
			if err := serverKeepAlive(conn); err != nil {
				// launch goroutine to avoid deadlock with sending to channel
				go sessions.delServer(num, hostname)
			}
		}
	}
}

func serverKeepAlive(conn *tls.Conn) error {
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	b := make([]byte, 1)
	if _, err := conn.Read(b); err != nil {
		return err
	}
	if b[0] != 0 {
		return errors.New("invalid response from server")
	}
	return nil
}

// Handle azure data session.
// conn automatically closes on return, do not fork.
func handleServerData(num uint64, conn *tls.Conn, suffix *suffix) {
	// Receive pack from client
	p, err := recvPack(conn, true)
	if err != nil {
		lg.PrintSessionf("Session aborted: %s", num, 'S', 3, err)
		return
	}

	hostname, ok := p.getString("hostname", false)
	if !ok {
		lg.PrintSessionf("Session aborted: no hostname provided by peer", num, 'S', 3)
		return
	}

	sessionID, ok := p.getData("session_id")
	if !ok || len(sessionID) != 20 {
		lg.PrintSessionf("Session aborted: failed to get session ID from server", num, 'S', 3)
		return
	}

	// Get client connection
	if cnum, c := sessions.serverRespond(num, conn, hostname, sessionID); c != nil {
		defer sessions.delRelay(cnum)
		if _, err := conn.Write([]byte{1}); err != nil {
			lg.PrintSessionf("Session aborted: %s", num, 'S', 3, err)
			return
		}
		lg.PrintSessionf("Relaying data from client session %d", num, 'S', 2, cnum)
		n, _ := io.Copy(conn, c)
		lg.PrintSessionf("Server session closed: relayed %d bytes from client to server", num, 'S', 3, n)
	} else {
		lg.PrintSessionf("Session aborted: can't find the client session", num, 'S', 3)
	}
}
