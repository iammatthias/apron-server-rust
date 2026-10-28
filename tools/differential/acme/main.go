// Command acme prints golang.org/x/crypto/acme's values for a fixed
// account key, and checks a JWS and a TLS-ALPN-01 certificate the Rust port
// made with that key, so the Rust tests compare against Go's own code.
//
//	go run . vectors <key.pem> <token>
//	go run . verify-jws <key.pem> <jws-file>
//	go run . check-alpn <key.pem> <token> <domain> <cert.der>
//	go run . write-cache <key.pem> <dir> <domain>
//	go run . read-cache <key.pem> <dir> <domain>
//	go run . dial <key.pem> <addr> <server-name> <alpn>
//
// write-cache stores a self-signed certificate for domain the way autocert's
// cachePut does; read-cache loads domain's certificate with autocert's
// Manager, offline, and prints its serial number. dial connects as Pebble's
// validator does, without verifying the chain, and prints the negotiated
// protocol and the leaf's serial number.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var idPeACMEIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 1, 31}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func alpnExtension(der []byte) ([]byte, bool, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false, err
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(idPeACMEIdentifier) {
			return ext.Value, ext.Critical, nil
		}
	}
	return nil, false, fmt.Errorf("no acmeIdentifier extension")
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: vectors|verify-jws|check-alpn <key.pem> ...")
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	client := &acme.Client{Key: key}
	switch args[0] {
	case "vectors":
		token := args[2]
		thumb, err := acme.JWKThumbprint(key.Public())
		if err != nil {
			return err
		}
		resp, err := client.HTTP01ChallengeResponse(token)
		if err != nil {
			return err
		}
		cert, err := client.TLSALPN01ChallengeCert(token, "chat.example")
		if err != nil {
			return err
		}
		value, critical, err := alpnExtension(cert.Certificate[0])
		if err != nil {
			return err
		}
		fmt.Printf("thumbprint %s\nhttp01 %s\npath %s\nalpn %s %v\n", thumb, resp,
			client.HTTP01ChallengePath(token), hex.EncodeToString(value), critical)
	case "verify-jws":
		data, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var jws struct{ Protected, Payload, Signature string }
		if err := json.Unmarshal(data, &jws); err != nil {
			return err
		}
		sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
		if err != nil || len(sig) != 64 {
			return fmt.Errorf("signature: %d bytes, %v", len(sig), err)
		}
		digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			return fmt.Errorf("bad signature")
		}
		header, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
		payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
		fmt.Printf("protected %s\npayload %s\n", header, payload)
	case "check-alpn":
		token, domain := args[2], args[3]
		der, err := os.ReadFile(args[4])
		if err != nil {
			return err
		}
		want, err := client.TLSALPN01ChallengeCert(token, domain)
		if err != nil {
			return err
		}
		wantValue, _, err := alpnExtension(want.Certificate[0])
		if err != nil {
			return err
		}
		value, critical, err := alpnExtension(der)
		if err != nil {
			return err
		}
		cert, _ := x509.ParseCertificate(der)
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			return fmt.Errorf("not self-signed: %v", err)
		}
		if err := cert.VerifyHostname(domain); err != nil {
			return err
		}
		if !critical || !bytes.Equal(value, wantValue) {
			return fmt.Errorf("extension %x critical %v, want %x critical", value, critical, wantValue)
		}
		fmt.Println("ok")
	case "write-cache":
		dir, domain := args[2], args[3]
		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(4242),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			DNSNames:     []string{domain},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalECPrivateKey(certKey)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		return autocert.DirCache(dir).Put(context.Background(), domain, buf.Bytes())
	case "read-cache":
		dir, domain := args[2], args[3]
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(dir),
			Client:     &acme.Client{Key: key, DirectoryURL: "http://127.0.0.1:1/unreachable"},
		}
		cert, err := m.GetCertificate(&tls.ClientHelloInfo{
			ServerName:       domain,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		})
		if err != nil {
			return err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		fmt.Printf("serial %s chain %d\n", leaf.SerialNumber, len(cert.Certificate))
	case "dial":
		addr, name, proto := args[2], args[3], args[4]
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, NextProtos: []string{proto}, InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		defer conn.Close()
		state := conn.ConnectionState()
		fmt.Printf("proto %s serial %s\n", state.NegotiatedProtocol, state.PeerCertificates[0].SerialNumber)
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
	return nil
}
