package healthcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
)

func TestCheckTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()
	if err := Check(context.Background(), "tcp", "127.0.0.1", listener.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
}

func TestCheckValidationAndProtocols(t *testing.T) {
	for _, input := range []struct {
		proxyType string
		host      string
		port      int
	}{
		{proxyType: "tcp", host: "", port: 80},
		{proxyType: "tcp", host: "127.0.0.1", port: 0},
		{proxyType: "sctp", host: "127.0.0.1", port: 80},
	} {
		if err := Check(context.Background(), input.proxyType, input.host, input.port); err == nil {
			t.Fatalf("invalid health check was accepted: %#v", input)
		}
	}
	if err := Check(context.Background(), "tcp", "127.0.0.1", 1); err == nil {
		t.Fatal("closed TCP service was reported healthy")
	}

	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	udpPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	defer udpListener.Close()
	if err := Check(context.Background(), "udp", "127.0.0.1", udpPort); err != nil {
		t.Fatalf("UDP health check failed: %v", err)
	}

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(tcpListener) }()
	if err := Check(context.Background(), "http", "127.0.0.1", tcpListener.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		// The listener close is not part of the health-check result; accept the
		// normal Serve shutdown path while still surfacing unexpected errors.
		t.Logf("HTTP server shutdown: %v", err)
	}
}
