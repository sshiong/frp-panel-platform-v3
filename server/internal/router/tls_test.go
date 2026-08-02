package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCertificateStoreReplacesAndRejectsUnknownSNI(t *testing.T) {
	store := NewCertificateStore()
	certificate := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	store.Replace(map[string]tls.Certificate{"APP.Example.com.": certificate})

	loaded, err := store.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil || loaded == nil || len(loaded.Certificate) != 1 {
		t.Fatalf("known SNI was not served: cert=%#v err=%v", loaded, err)
	}
	if _, err := store.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("unknown SNI must fail closed")
	}

	store.Replace(map[string]tls.Certificate{"new.example.com": certificate})
	if _, err := store.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"}); err == nil {
		t.Fatal("replaced certificate set retained stale SNI")
	}
}

func TestCertificateStoreHotReloadsNewHandshakesWithoutChangingExistingTLSConnection(t *testing.T) {
	first := testCertificate(t, "first.example.com")
	second := testCertificate(t, "second.example.com")
	store := NewCertificateStore()
	store.Replace(map[string]tls.Certificate{"app.example.com": first})

	oldClient, oldServer, oldSubject := handshakeCertificate(t, store.TLSConfig(), "app.example.com")
	defer oldClient.Close()
	defer oldServer.Close()
	if oldSubject != "first.example.com" {
		t.Fatalf("initial SNI certificate=%q", oldSubject)
	}
	store.Replace(map[string]tls.Certificate{"app.example.com": second})

	newClient, newServer, newSubject := handshakeCertificate(t, store.TLSConfig(), "app.example.com")
	defer newClient.Close()
	defer newServer.Close()
	if newSubject != "second.example.com" {
		t.Fatalf("hot-reloaded SNI certificate=%q", newSubject)
	}
	if oldClient.ConnectionState().PeerCertificates[0].Subject.CommonName != "first.example.com" {
		t.Fatal("existing TLS connection changed certificate after hot reload")
	}
	if _, err := store.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("unknown SNI must fail closed after hot reload")
	}
}

func handshakeCertificate(t *testing.T, config *tls.Config, serverName string) (*tls.Conn, *tls.Conn, string) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	serverTLS := tls.Server(serverConn, config)
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	clientTLS := tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err != nil {
		_ = serverTLS.Close()
		_ = clientTLS.Close()
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		_ = serverTLS.Close()
		_ = clientTLS.Close()
		t.Fatal(err)
	}
	state := clientTLS.ConnectionState()
	if len(state.PeerCertificates) != 1 {
		_ = serverTLS.Close()
		_ = clientTLS.Close()
		t.Fatalf("peer certificate count=%d", len(state.PeerCertificates))
	}
	return clientTLS, serverTLS, state.PeerCertificates[0].Subject.CommonName
}

func testCertificate(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign}, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
