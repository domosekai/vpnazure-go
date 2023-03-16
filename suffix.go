// Managing DNS suffixes

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"strings"
	"sync"
)

type suffix struct {
	suffix   string          // azure suffix (e.g. .myazure.net)
	control  string          // server FQDN (e.g. control.myazure.net)
	certs    tls.Certificate // server cert chain
	certHash [20]byte
}

// DNS suffix list with mutex
type suffixList struct {
	list []suffix
	rw   sync.RWMutex
}

// Read or update DNS suffix list
func (su *suffixList) read(file string) int {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	su.rw.Lock()
	defer su.rw.Unlock()

	su.list = nil
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		// Format: DNS suffix[TAB]control address[TAB]certificate chain file[TAB]private key file
		line := strings.Split(scanner.Text(), "	")

		if len(line) < 4 {
			continue
		}

		if strings.HasPrefix(line[0], "/") || strings.HasPrefix(line[0], "#") {
			continue
		}

		// A suffix must start with "."
		if strings.HasPrefix(line[0], ".") {
			if certs, err := tls.LoadX509KeyPair(line[2], line[3]); err == nil {
				certs.Leaf, _ = x509.ParseCertificate(certs.Certificate[0])
				hash := sha1.Sum(certs.Certificate[0])
				su.list = append(su.list, suffix{suffix: strings.ToLower(line[0]), control: strings.ToLower(line[1]), certs: certs, certHash: hash})
			} else {
				lg.Printf("suffix: error loading certificates for suffix %s: %s", line[0], err)
			}
		}
	}

	return len(su.list)
}

// Look up suffix or server based on SNI.
// Parsed hostname is in lower case (e.g. vpn1234.myazure.net).
func (su *suffixList) parse(sni string) (hostname string, suffix *suffix, server bool, ok bool) {
	su.rw.RLock()
	defer su.rw.RUnlock()

	// Remove trailing NAT-T hint for softether clients
	serverName, _, _ := strings.Cut(strings.ToLower(sni), "/")

	for i := range su.list {
		// Match VPN server (azure client)
		if serverName == su.list[i].control {
			return "", &su.list[i], true, true
		}

		// Match VPN client
		trimmed := strings.TrimSuffix(serverName, su.list[i].suffix)
		if trimmed != "" && trimmed != serverName {
			return serverName, &su.list[i], false, true
		}
	}

	return "", nil, false, false
}

// Get suffix by exact suffix string
func (su *suffixList) get(suffix string) *suffix {
	su.rw.RLock()
	defer su.rw.RUnlock()

	for i := range su.list {
		if su.list[i].suffix == suffix {
			return &su.list[i]
		}
	}

	return nil
}
