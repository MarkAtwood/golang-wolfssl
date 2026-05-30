// tls_client.go: minimal TLS client for interop testing.
// Dials addr (default localhost:8443), completes TLS handshake,
// sends "GET / HTTP/1.0\r\n\r\n", reads response, exits 0 on success.

//go:build ignore

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "server address")
	ca := flag.String("ca", "rsa_cert.pem", "CA certificate PEM (for server verification)")
	minVer := flag.Uint("minver", tls.VersionTLS12, "minimum TLS version")
	maxVer := flag.Uint("maxver", tls.VersionTLS13, "maximum TLS version")
	serverName := flag.String("servername", "test", "TLS server name")
	flag.Parse()

	caData, err := os.ReadFile(*ca)
	if err != nil {
		log.Fatalf("ReadFile(%s): %v", *ca, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		log.Fatalf("failed to parse CA cert from %s", *ca)
	}

	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: *serverName,
		MinVersion: uint16(*minVer),
		MaxVersion: uint16(*maxVer),
	}

	conn, err := tls.Dial("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	fmt.Fprintf(os.Stderr, "negotiated TLS %#x cipher %#04x\n",
		cs.Version, cs.CipherSuite)

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", *serverName)
	if err != nil {
		log.Fatalf("Write: %v", err)
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("ReadAll: %v", err)
	}
	fmt.Fprintf(os.Stderr, "response: %q\n", string(body))

	if len(body) == 0 {
		log.Fatal("empty response")
	}
	fmt.Fprintln(os.Stderr, "client done")
}
