// Server (azure client) authentication

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
)

type authType string

const (
	authNone     authType = "none"
	authPassword authType = "password"
	authCert     authType = "cert"
)

// Server credential with wildcard support
type authInfo struct {
	hostname *regexp.Regexp
	suffix   *regexp.Regexp
	method   authType
	password string
	cert     *x509.Certificate
}

// Server credential list
type authList struct {
	list []authInfo
	rw   sync.RWMutex
}

// Read or update server authentication list
func (al *authList) read(file string) int {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	al.rw.Lock()
	defer al.rw.Unlock()

	al.list = nil
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		// Format: hostname[TAB]suffix[TAB]authentication method[TAB]secret
		line := strings.Split(scanner.Text(), "	")

		if len(line) < 3 {
			continue
		}

		if strings.HasPrefix(line[0], "/") || strings.HasPrefix(line[0], "#") {
			continue
		}

		host, err := regexp.Compile(wildCardToRegexp(strings.ToLower(line[0])))
		if err != nil {
			continue
		}

		suffix, err := regexp.Compile(wildCardToRegexp(strings.ToLower(line[1])))
		if err != nil {
			continue
		}

		switch strings.ToLower(line[2]) {
		case string(authNone):
			al.list = append(al.list, authInfo{hostname: host, suffix: suffix, method: authNone})
		case string(authPassword):
			if len(line) < 4 {
				continue
			}
			al.list = append(al.list, authInfo{hostname: host, suffix: suffix, method: authPassword, password: line[3]})
		case string(authCert):
			if len(line) < 4 {
				continue
			}
			if bytes, err := os.ReadFile(line[3]); err == nil {
				block, _ := pem.Decode(bytes)
				if block == nil {
					lg.Printf("auth: error parsing certificate for hostname %s of suffix %s: not a valid PEM file", line[0], line[1])
					continue
				}
				if x509, err := x509.ParseCertificate(block.Bytes); err == nil {
					al.list = append(al.list, authInfo{hostname: host, suffix: suffix, method: authCert, cert: x509})
				} else {
					lg.Printf("auth: error parsing certificate for hostname %s of suffix %s: %s", line[0], line[1], err)
				}
			} else {
				lg.Printf("auth: error reading certificate for hostname %s of suffix %s: %s", line[0], line[1], err)
			}
		}
	}

	return len(al.list)
}

// Look up hostname and suffix in the list.
// Input strings are in lower case.
func (al *authList) find(fqdn string, suffix string) (*authInfo, bool) {
	al.rw.RLock()
	defer al.rw.RUnlock()
	hostname := strings.TrimSuffix(fqdn, suffix)
	if hostname == "" || hostname == fqdn {
		return nil, false
	}
	for i := range al.list {
		if al.list[i].match(hostname, suffix) {
			return &al.list[i], true
		}
	}
	return nil, false
}

// Match hostname and suffix with wildcard support
func (ai *authInfo) match(hostname string, suffix string) bool {
	return ai.hostname.MatchString(hostname) && ai.suffix.MatchString(suffix)
}

// Check password
func (ai *authInfo) checkPassword(hostname string, random, hash []byte) bool {
	hash1 := sha1.Sum(append([]byte(ai.password), []byte(strings.ToUpper(hostname))...))
	hash2 := sha1.Sum(append(hash1[:], random...))
	return bytes.Equal(hash2[:], hash)
}

// wildCardToRegexp converts a wildcard pattern to a regular expression pattern.
//
// https://stackoverflow.com/questions/64509506/golang-determine-if-string-contains-a-string-with-wildcards
func wildCardToRegexp(pattern string) string {
	var result strings.Builder
	for i, literal := range strings.Split(pattern, "*") {

		// Replace * with .*
		if i > 0 {
			result.WriteString(".*")
		}

		// Quote any regular expression meta characters in the
		// literal text.
		result.WriteString(regexp.QuoteMeta(literal))
	}
	return "^" + result.String() + "$"
}
