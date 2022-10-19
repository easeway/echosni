package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"time"
)

func serve(conn *tls.Conn) {
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		log.Printf("Handshake error: %v", err)
		return
	}
	serverName := conn.ConnectionState().ServerName
	log.Printf("ServerName: %s", serverName)
	fmt.Fprintln(conn, serverName)
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Generate keypair: %v", err)
	}

	caTemplate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(8640 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, key.Public(), key)
	if err != nil {
		log.Fatalf("Create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Parse certificate: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: cert},
		},
		NextProtos: []string{"h2"},
	}
	ln, err := tls.Listen("tcp", ":8443", tlsConf)
	if err != nil {
		log.Fatalf("Create TLS listener: %v", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go serve(conn.(*tls.Conn))
	}
}
