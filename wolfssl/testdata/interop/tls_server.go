// tls_server.go: minimal TLS server for interop testing.
// Listens on addr (default :8443), handles one connection:
//   - completes TLS handshake
//   - reads up to 4096 bytes of request
//   - writes "HTTP/1.0 200 OK\r\n\r\nOK\n"
//   - exits 0

//go:build ignore

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	cert := flag.String("cert", "rsa_cert.pem", "TLS certificate PEM")
	key := flag.String("key", "rsa_key.pem", "TLS key PEM")
	minVer := flag.Uint("minver", tls.VersionTLS12, "minimum TLS version")
	maxVer := flag.Uint("maxver", tls.VersionTLS13, "maximum TLS version")
	flag.Parse()

	certificate, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("LoadX509KeyPair: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   uint16(*minVer),
		MaxVersion:   uint16(*maxVer),
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", ln.Addr())

	conn, err := ln.Accept()
	if err != nil {
		log.Fatalf("Accept: %v", err)
	}
	ln.Close()

	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("Handshake: %v", err)
	}

	cs := tlsConn.ConnectionState()
	fmt.Fprintf(os.Stderr, "negotiated TLS %#x cipher %#04x\n",
		cs.Version, cs.CipherSuite)

	// Read request with deadline (OpenSSL s_client doesn't send EOF)
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	tlsConn.Read(buf)

	_, err = tlsConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\nOK\n"))
	if err != nil {
		log.Fatalf("Write: %v", err)
	}
	tlsConn.Close()
	fmt.Fprintln(os.Stderr, "server done")
}
