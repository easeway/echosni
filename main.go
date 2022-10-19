package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"time"
)

var (
	listenAddr = flag.String("l", ":8443", "Listening address.")
	certFile   = flag.String("cert-file", "", "Certificate file in PEM.")
	keyFile    = flag.String("key-file", "", "Private key file in PEM.")
	caCert     = flag.Bool("ca", false, "Set CA=true in self-signed certificate.")
	commonName = flag.String("cn", "", "Common name in self-signed certificate.")
	dnsList    = flag.String("dns", "", "DNS names to be added self-signed SAN, comma-separated.")
	alpnList   = flag.String("alpn", "", "Explicity specify ALPN for negotiation, comma-separated.")
)

func selfSignedCert() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Generate keypair: %v", err)
	}

	caTemplate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  *caCert,
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(8640 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	for _, name := range strings.Split(*dnsList, ",") {
		if name != "" {
			caTemplate.DNSNames = append(caTemplate.DNSNames, name)
		}
	}
	if *commonName != "" {
		caTemplate.Subject = pkix.Name{CommonName: *commonName}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, key.Public(), key)
	if err != nil {
		log.Fatalf("Create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Parse certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: cert}
}

func serve(conn *tls.Conn) {
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		if errors.Is(err, io.EOF) {
			// Probably health-check connection.
			return
		}
		log.Printf("Handshake error: %v", err)
		return
	}
	serverName := conn.ConnectionState().ServerName
	log.Printf("ServerName: %s", serverName)
	fmt.Fprintln(conn, serverName)
}

func main() {
	flag.Parse()

	var cert tls.Certificate
	var err error
	if *certFile != "" && *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Load cert/keypair: %v", err)
		}
	} else {
		cert = selfSignedCert()
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}
	for _, alpn := range strings.Split(*alpnList, ",") {
		if alpn != "" {
			tlsConf.NextProtos = append(tlsConf.NextProtos, alpn)
		}
	}
	ln, err := tls.Listen("tcp", *listenAddr, tlsConf)
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
