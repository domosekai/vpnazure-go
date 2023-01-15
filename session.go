package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"sync"
)

type pendingSession struct {
	conn      net.Conn             // client connection
	ch        chan<- clientCommand // channel to notify client of server connection
	hostname  string               // server FQDN
	sessionID []byte               // 20-byte session ID
}

type relayingSession struct {
	client net.Addr
	server net.Addr
}

type serverSession struct {
	num  uint64               // server control session number
	conn net.Conn             // server control connection
	ch   chan<- serverCommand // channel to send server command
}

type sessionList struct {
	pending  map[uint64]pendingSession
	relaying map[uint64]relayingSession
	servers  map[string]serverSession
	c, s     sync.Mutex
}

// Register a new server
func (sl *sessionList) addServer(num uint64, hostname string, conn *tls.Conn, ch chan serverCommand) {
	sl.s.Lock()
	defer sl.s.Unlock()

	// Replace existing session if any
	if s, ok := sl.servers[hostname]; ok {
		close(s.ch)
	}
	sl.servers[hostname] = serverSession{num: num, conn: conn, ch: ch}
}

// Remove a server
func (sl *sessionList) delServer(num uint64, hostname string) {
	sl.s.Lock()
	defer sl.s.Unlock()

	if s, ok := sl.servers[hostname]; ok && s.num == num {
		delete(sl.servers, hostname)
		close(s.ch)
	}
}

// Send client request to a server control session
func (sl *sessionList) clientRequest(num uint64, hostname string, conn net.Conn, ch chan clientCommand) error {
	// only locking for reading will lead to race when checking channel buffer simultaneously
	sl.s.Lock()
	defer sl.s.Unlock()

	// Find server session
	s, ok := sl.servers[hostname]
	if !ok {
		return errors.New("server is offline")
	}

	// sending may block when buffer is full (remove if unbuffered)
	if len(s.ch) == cap(s.ch) {
		return errors.New("server is busy")
	}

	// generate a secure session ID
	id := make([]byte, 20)
	if _, err := rand.Read(id); err != nil {
		return errors.New("failed to generate a session ID")
	}

	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("failed to get client address")
	}

	// Save client session
	sl.c.Lock()
	defer sl.c.Unlock()
	sl.pending[num] = pendingSession{conn: conn, ch: ch, hostname: hostname, sessionID: id}

	// Send connection info to server
	command := serverCommand{op: serverRelay, num: num, hostname: hostname, sessionID: id, clientIP: addr.IP, clientPort: addr.Port}
	s.ch <- command

	return nil
}

// Client cancels a request
func (sl *sessionList) delRequest(num uint64) {
	sl.c.Lock()
	defer sl.c.Unlock()

	delete(sl.pending, num)
}

// Server responds and gets the pending client connection
func (sl *sessionList) serverRespond(num uint64, conn net.Conn, hostname string, sessionID []byte) (uint64, net.Conn) {
	sl.c.Lock()
	defer sl.c.Unlock()

	for cnum, c := range sl.pending {
		if c.hostname == hostname && bytes.Equal(c.sessionID, sessionID) {
			delete(sl.pending, cnum)
			sl.relaying[cnum] = relayingSession{client: c.conn.RemoteAddr(), server: conn.RemoteAddr()}
			// This channel will be sent to at most once and will never block
			c.ch <- clientCommand{num: num, conn: conn}
			return cnum, c.conn
		}
	}

	return 0, nil
}

// Remove a relay session
func (sl *sessionList) delRelay(num uint64) {
	sl.c.Lock()
	defer sl.c.Unlock()

	delete(sl.relaying, num)
}

// Print session statistics
func (sl *sessionList) printStatus() {
	sl.s.Lock()
	sl.c.Lock()
	lg.Printf("Status: %d online servers, %d connected clients, %d connecting", len(sl.servers), len(sl.relaying), len(sl.pending))
	sl.c.Unlock()
	sl.s.Unlock()
}
