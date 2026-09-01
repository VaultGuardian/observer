package watcher

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestWatcher returns a Watcher whose httpClient dials the given test server
// instead of the Docker unix socket. It mirrors the Transport shape from New,
// swapping the unix DialContext for one that dials the server's TCP listener, so
// the http://docker/... URLs in watcher.go resolve to the test server.
func newTestWatcher(srv *httptest.Server) *Watcher {
	addr := srv.Listener.Addr().String()
	return &Watcher{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("tcp", addr)
				},
			},
		},
	}
}

// TestListContainersUsesUnversionedPath verifies the request omits the /v1.43
// prefix so the daemon negotiates its own API version (Docker 29 rejects 1.43).
func TestListContainersUsesUnversionedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("expected path /containers/json, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Container{
			{ID: "abc123", Names: []string{"/web"}, State: "running", Image: "nginx"},
		})
	}))
	defer srv.Close()

	watcher := newTestWatcher(srv)
	containers, err := watcher.listContainers(context.Background())
	if err != nil {
		t.Fatalf("listContainers returned error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	if containers[0].ID != "abc123" {
		t.Errorf("expected container Id abc123, got %q", containers[0].ID)
	}
}

// TestListContainersSurfacesDaemonError verifies a non-200 daemon response is
// returned as the daemon's own message rather than a confusing unmarshal error.
func TestListContainersSurfacesDaemonError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"client version 1.43 is too old. Minimum supported API version is 1.44"}`))
	}))
	defer srv.Close()

	watcher := newTestWatcher(srv)
	_, err := watcher.listContainers(context.Background())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "Minimum supported API version") {
		t.Errorf("expected error to contain daemon message, got %q", err.Error())
	}
}
