package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

// TestFRPPluginNetworkE2E is opt-in because it needs fixed official FRPS and
// FRPC binaries. It exercises the real Server Plugin HTTP calls emitted by
// FRPS, not a hand-written envelope or a mocked transport.
func TestFRPPluginNetworkE2E(t *testing.T) {
	if os.Getenv("FRP_PLUGIN_E2E") != "1" {
		t.Skip("set FRP_PLUGIN_E2E=1 with FRP_E2E_FRPS_BINARY and FRP_E2E_FRPC_BINARY")
	}
	frpsBinary := strings.TrimSpace(os.Getenv("FRP_E2E_FRPS_BINARY"))
	frpcBinary := strings.TrimSpace(os.Getenv("FRP_E2E_FRPC_BINARY"))
	if frpsBinary == "" || frpcBinary == "" {
		t.Fatal("FRP_E2E_FRPS_BINARY and FRP_E2E_FRPC_BINARY are required")
	}
	for _, binary := range []string{frpsBinary, frpcBinary} {
		if info, err := os.Stat(binary); err != nil || info.Mode()&0o111 == 0 {
			t.Fatalf("fixed FRP binary is not executable: %s", binary)
		}
	}

	root := t.TempDir()
	database, err := db.Open(filepath.Join(root, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	secrets, err := crypto.Load(root, filepath.Join(root, "master.key"), filepath.Join(root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	transportSecret := "network-plugin-transport-secret-2026"
	cfg := config.Config{
		DataDir:              root,
		Environment:          "development",
		AdminPassword:        "Admin-Password-2026!",
		SessionTTLHours:      12,
		PortStart:            6000,
		PortEnd:              6999,
		FRPSPublicHost:       "127.0.0.1",
		FRPSPublicPort:       17000,
		FRPSTransportSecret:  transportSecret,
		FRPSVhostHTTPPort:    18080,
		RouterSnapshotDir:    filepath.Join(root, "router"),
		CloudflareAPIBaseURL: "http://127.0.0.1:1",
	}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "plugin-network-e2e")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, password, err := app.CreateUser(context.Background(), admin, "plugin-e2e-user")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "plugin-e2e-user", password, "client_panel", "127.0.0.1", "plugin-network-e2e")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	remotePort := findFreePortInRange(t, 6500, 6999)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "frp-panel-plugin-network-e2e")
	}))
	t.Cleanup(local.Close)
	localURL, err := url.Parse(local.URL)
	if err != nil {
		t.Fatal(err)
	}
	localHost, localPortText, err := net.SplitHostPort(localURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	localPort, err := strconv.Atoi(localPortText)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := app.CreateMapping(context.Background(), user, service.MappingRequest{Name: "plugin-e2e", ProxyType: "tcp", LocalIP: localHost, LocalPort: localPort, RemotePort: &remotePort}, "plugin-network-mapping-123456")
	if err != nil {
		t.Fatal(err)
	}

	pluginServer := httptest.NewServer(New(app, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(pluginServer.Close)
	pluginURL, err := url.Parse(pluginServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	pluginHost, pluginPort, err := net.SplitHostPort(pluginURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	frpsPort := findFreePort(t, 17000)
	transportPath := filepath.Join(root, "frps-transport.secret")
	if err := os.WriteFile(transportPath, []byte(transportSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpsConfig := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %q

[[httpPlugins]]
name = "frp-panel-platform"
addr = "%s:%s"
path = "/internal/frp/plugin"
ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn", "NewUserConn"]
`, frpsPort, transportPath, pluginHost, pluginPort)
	frpsConfigPath := filepath.Join(root, "frps.toml")
	if err := os.WriteFile(frpsConfigPath, []byte(frpsConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	transportPathClient := filepath.Join(root, "frpc-transport.secret")
	if err := os.WriteFile(transportPathClient, []byte(transportSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpcConfig := fmt.Sprintf(`serverAddr = "127.0.0.1"
serverPort = %d
loginFailExit = false
user = %q
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %q
metadatas = { frp_runtime_credential = %q, session_generation = %q, frp_user_secret = %q }

[[proxies]]
name = %q
type = "tcp"
localIP = %q
localPort = %d
remotePort = %d
metadatas = { mapping_id = %q, mapping_revision = %q }
`, frpsPort, clientLogin.FRPUsername, transportPathClient, clientLogin.RuntimeCredential, strconv.FormatInt(user.Generation, 10), clientLogin.FRPSecret, "mapping-"+mapping.ID, localHost, localPort, remotePort, mapping.ID, strconv.FormatInt(mapping.Revision, 10))
	frpcConfigPath := filepath.Join(root, "frpc.toml")
	if err := os.WriteFile(frpcConfigPath, []byte(frpcConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runFRPVerify(t, frpsBinary, frpsConfigPath)
	runFRPVerify(t, frpcBinary, frpcConfigPath)

	frpsLog := &bytes.Buffer{}
	frps := exec.Command(frpsBinary, "-c", frpsConfigPath)
	frps.Stdout, frps.Stderr = frpsLog, frpsLog
	if err := frps.Start(); err != nil {
		t.Fatal(err)
	}
	stopFRPProcess(t, frps, frpsLog)
	waitForTCP(t, "127.0.0.1", frpsPort)

	frpcLog := &bytes.Buffer{}
	frpc := exec.Command(frpcBinary, "-c", frpcConfigPath)
	frpc.Stdout, frpc.Stderr = frpcLog, frpcLog
	if err := frpc.Start(); err != nil {
		t.Fatal(err)
	}
	stopFRPProcess(t, frpc, frpcLog)

	deadline := time.Now().Add(30 * time.Second)
	remoteURL := fmt.Sprintf("http://127.0.0.1:%d/", remotePort)
	var lastErr error
	for time.Now().Before(deadline) {
		response, requestErr := http.Get(remoteURL)
		if requestErr == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && strings.Contains(string(body), "frp-panel-plugin-network-e2e") {
				return
			}
			lastErr = fmt.Errorf("unexpected proxy response: status=%d body=%q", response.StatusCode, string(body))
		} else {
			lastErr = requestErr
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("FRPS/FRPC Plugin network E2E did not become reachable: %v\nFRPS log:\n%s\nFRPC log:\n%s", lastErr, frpsLog.String(), frpcLog.String())
}

func runFRPVerify(t *testing.T, binary, configPath string) {
	t.Helper()
	command := exec.Command(binary, "verify", "-c", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s verify failed: %v\n%s", binary, err, output)
	}
}

func stopFRPProcess(t *testing.T, command *exec.Cmd, logOutput *bytes.Buffer) {
	t.Helper()
	t.Cleanup(func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = command.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		if logOutput.Len() > 0 {
			t.Logf("FRP process log:\n%s", logOutput.String())
		}
	})
}

func waitForTCP(t *testing.T, host string, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 250*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP listener %s:%d did not become ready", host, port)
}

func findFreePort(t *testing.T, preferred int) int {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(preferred)))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func findFreePortInRange(t *testing.T, start, end int) int {
	t.Helper()
	for port := start; port <= end; port++ {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = listener.Close()
			return port
		}
	}
	t.Fatalf("no free TCP port in %d-%d", start, end)
	return 0
}
