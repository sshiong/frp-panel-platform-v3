package security

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func NormalizeServerURL(raw string, development bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("server panel address is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server address must not contain userinfo, path, query or fragment")
	}
	if u.Scheme != "https" && !(development && u.Scheme == "http") {
		return "", fmt.Errorf("only https is allowed outside explicit development mode")
	}
	if u.Hostname() == "" || strings.ContainsAny(u.Hostname(), "[]") {
		return "", fmt.Errorf("server address host is required")
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "%/\\?#@") || strings.IndexFunc(host, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return "", fmt.Errorf("server address host is invalid")
	}
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", fmt.Errorf("server address host is invalid")
		}
		host = ip.String()
	} else if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	portNumber, portErr := strconv.Atoi(port)
	if portErr != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("server address port is invalid")
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return u.Scheme + "://" + formatHost(host), nil
	}
	return u.Scheme + "://" + formatHost(host) + ":" + port, nil
}

func formatHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
