package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// Listener-ownership gate
// =============================================================================
//
// main.go binds the dashboard port synchronously and treats failure as fatal,
// BEFORE it constructs the sync engine. These tests cover the api half of that
// contract: Listen reports the bind, Serve needs it, and Shutdown still works.

func newListenTestServer(t *testing.T, port int) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Init(dir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv, err := NewServer(ServerConfig{
		Port:     port,
		KeyFile:  filepath.Join(dir, "dashboard.key"),
		BindAddr: "127.0.0.1",
		Version:  "test",
	}, st, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// An occupied port must surface as an error from Listen - synchronously, so
// main can refuse to start rather than discovering it minutes later.
func TestListenFailsOnOccupiedPort(t *testing.T) {
	first := newListenTestServer(t, 0)
	l, err := first.Listen()
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	second := newListenTestServer(t, port)
	l2, err := second.Listen()
	if err == nil {
		l2.Close()
		t.Fatalf("second Listen on port %d succeeded; want an address-in-use error", port)
	}
	if !strings.Contains(err.Error(), "cannot bind") || !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Errorf("error = %q; want it to name the address it could not bind", err)
	}
}

// Serve must refuse to run without a Listen: the whole point of the split is
// that ownership of the port is established first.
func TestServeRequiresListen(t *testing.T) {
	srv := newListenTestServer(t, 0)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	if err := srv.Serve(l); err == nil {
		t.Error("Serve without Listen should fail")
	}
}

// The bound listener actually serves, and a graceful Shutdown ends Serve with
// http.ErrServerClosed (which main deliberately does not log as an error).
func TestListenThenServeAndShutdown(t *testing.T) {
	srv := newListenTestServer(t, 0)
	l, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()

	// /api/health needs no auth, which makes it the readiness probe.
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/health"
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		if resp, err = client.Get(url); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d; want 200", resp.StatusCode)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v; want http.ErrServerClosed after Shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return after Shutdown")
	}
}
