package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

// TestPerformanceBaseline is an opt-in local control-plane gate. It is kept
// out of ordinary unit-test runs because the acceptance profile intentionally
// creates concurrent traffic and should be run on the target-like host with
// FRP_PERF=1.
func TestPerformanceBaseline(t *testing.T) {
	if testing.Short() || os.Getenv("FRP_PERF") != "1" {
		t.Skip("set FRP_PERF=1 to run the acceptance performance profile")
	}
	app, server, token := performanceFixture(t)
	defer server.Close()

	readErrors, readP95 := concurrentRequests(100, func(index int) error {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/dashboard", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusOK {
			return &httpError{status: response.StatusCode}
		}
		return nil
	})
	if readErrors != 0 || readP95 > 300*time.Millisecond {
		t.Fatalf("PERF-001 failed: errors=%d p95=%s threshold=300ms", readErrors, readP95)
	}

	writeErrors, writeP95 := concurrentRequests(20, func(index int) error {
		payload, _ := json.Marshal(map[string]interface{}{"name": "perf-" + stringID(index), "proxy_type": "tcp", "local_ip": "127.0.0.1", "local_port": 10000 + index})
		request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/mappings", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "perf-write-key-"+stringID(index))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusCreated {
			return &httpError{status: response.StatusCode}
		}
		return nil
	})
	if writeErrors != 0 || writeP95 > 800*time.Millisecond {
		t.Fatalf("PERF-002 failed: errors=%d p95=%s threshold=800ms", writeErrors, writeP95)
	}
	_ = app
	t.Logf("PERF-001 reads=100 errors=%d p95=%s; PERF-002 writes=20 errors=%d p95=%s", readErrors, readP95, writeErrors, writeP95)
}

type httpError struct{ status int }

func (e *httpError) Error() string { return "unexpected HTTP status" }

func performanceFixture(t *testing.T) (*service.App, *httptest.Server, string) {
	t.Helper()
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, password, err := app.CreateUser(context.Background(), admin, "perf-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE users SET max_mappings=100,max_pending_mappings=100,max_pending_port_leases=100 WHERE username='perf-user'`); err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "perf-user", password, "client_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), user, password, "Perf-User-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	clientLogin, err = app.Login(context.Background(), "perf-user", "Perf-User-Password-2026!", "client_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	api := New(app, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return app, httptest.NewServer(api.Handler()), clientLogin.Token
}

func concurrentRequests(count int, request func(int) error) (int, time.Duration) {
	start := make(chan struct{})
	durations := make([]time.Duration, count)
	var errorsCount atomic.Int32
	var wg sync.WaitGroup
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			started := time.Now()
			if err := request(index); err != nil {
				errorsCount.Add(1)
			}
			durations[index] = time.Since(started)
		}(index)
	}
	close(start)
	wg.Wait()
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	position := (len(durations)*95 + 99) / 100
	if position < 1 {
		position = 1
	}
	return int(errorsCount.Load()), durations[position-1]
}

func stringID(value int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if value == 0 {
		return "0"
	}
	encoded := ""
	for value > 0 {
		encoded = string(alphabet[value%len(alphabet)]) + encoded
		value /= len(alphabet)
	}
	return encoded
}
