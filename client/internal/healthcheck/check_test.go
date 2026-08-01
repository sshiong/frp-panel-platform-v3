package healthcheck

import (
	"context"
	"net"
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
