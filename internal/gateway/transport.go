package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadServerTLS loads the gateway identity and the CA certificates authorized to
// authenticate its clients. Client certificate verification is mandatory.
// Reload this configuration when rotating certificates or trust roots.
func LoadServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway server identity: %w", err)
	}
	clientCAs, err := loadCertificateAuthorities(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway client CA: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

// LoadClientTLS loads the controller identity and the CA certificates trusted
// for gateway servers. ServerName overrides the hostname used for verification;
// when empty, an HTTP transport derives it from the request URL.
func LoadClientTLS(certFile, keyFile, rootCAFile, serverName string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway client identity: %w", err)
	}
	roots, err := loadCertificateAuthorities(rootCAFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway server CA: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   serverName,
	}, nil
}

// Parse every PEM block instead of AppendCertsFromPEM, which silently skips
// malformed entries in a bundle that also contains a valid certificate.
func loadCertificateAuthorities(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("CA bundle must contain only PEM certificates")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(data, endMarker)
		if end < 0 {
			return nil, fmt.Errorf("invalid CA certificate PEM")
		}
		end += len(endMarker)
		// Bound Decode to the first block: it otherwise skips a malformed
		// block and can return a subsequent valid certificate.
		block, rest := pem.Decode(data[:end])
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid CA certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid CA certificate: %w", err)
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, fmt.Errorf("CA bundle contains a certificate that is not a certificate authority")
		}
		pool.AddCert(certificate)
		count++
		data = data[end:]
	}
	if count == 0 {
		return nil, fmt.Errorf("CA bundle contains no certificates")
	}
	return pool, nil
}
