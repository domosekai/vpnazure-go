// TLS config and verification

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// Get TLS configuration based on SNI
func getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello.ServerName == "" {
		return nil, errors.New("SNI is empty")
	}

	_, suffix, server, ok := suffixes.parse(hello.ServerName)
	if !ok {
		return nil, fmt.Errorf("SNI %s does not match any suffix", hello.ServerName)
	}

	config := &tls.Config{Certificates: []tls.Certificate{suffix.certs}}

	// Request client certificate from azure clients
	if server {
		config.ClientAuth = tls.RequestClientCert
		config.VerifyConnection = verifyClientCertificate
	}

	return config, nil
}

// Verify azure client certificate if presented
func verifyClientCertificate(cs tls.ConnectionState) error {
	_, suffix, server, ok := suffixes.parse(cs.ServerName)
	if !ok || !server {
		// rare
		return fmt.Errorf("SNI %s does not match any control server", cs.ServerName)
	}

	// Authenticate by other methods
	if len(cs.PeerCertificates) == 0 {
		return nil
	}

	// Use CN as hostname
	hostname := strings.ToLower(cs.PeerCertificates[0].Subject.CommonName)
	clientInfo, ok := auths.find(hostname, suffix.suffix)
	if !ok {
		return fmt.Errorf("CN %s is not a valid hostname", hostname)
	}
	if clientInfo.method != authCert {
		return fmt.Errorf("client certificate received but %s does not authenticate by certificate", hostname)
	}

	// Verify client certificate
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	opts.Roots.AddCert(clientInfo.cert)
	_, err := cs.PeerCertificates[0].Verify(opts)

	return err
}
