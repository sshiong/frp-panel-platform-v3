package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

func Check(ctx context.Context, proxyType, host string, port int) error {
	if host == "" || port < 1 || port > 65535 {
		return fmt.Errorf("invalid local service address")
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	switch proxyType {
	case "tcp":
		dialer := net.Dialer{Timeout: 3 * time.Second}
		conn, err := dialer.DialContext(checkCtx, "tcp", address)
		if err != nil {
			return err
		}
		return conn.Close()
	case "udp":
		dialer := net.Dialer{Timeout: 3 * time.Second}
		conn, err := dialer.DialContext(checkCtx, "udp", address)
		if err != nil {
			return err
		}
		return conn.Close()
	case "http":
		request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, "http://"+address+"/", nil)
		if err != nil {
			return err
		}
		response, err := (&http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
		if err != nil {
			return err
		}
		return response.Body.Close()
	default:
		return fmt.Errorf("unsupported proxy type %q", proxyType)
	}
}
