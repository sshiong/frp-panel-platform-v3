package router

import (
	"crypto/tls"
	"testing"
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
