// internal/rec/sockleak_test.go
package rec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// countedListener wraps a unix listener and tracks the number of currently-open
// server-side connections (Accepts minus Closes). This is the ground truth for
// the socket-leak test: every connection the client side fails to close stays
// counted here, with no /proc inspection involved.
type countedListener struct {
	net.Listener
	mu   sync.Mutex
	open int
}

func (l *countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.open++
	l.mu.Unlock()
	return &countedConn{Conn: c, l: l}, nil
}

func (l *countedListener) openConns() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open
}

type countedConn struct {
	net.Conn
	l    *countedListener
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.open--
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

// TestReconcile_NoDockerConnLeak reproduces the production socket leak: every
// reconcile cycle queried Docker through throwaway http.Clients
// (fetchRunningContainers + inspectContainerPID, each via newDockerClient), and
// each dropped Transport parked its keep-alive connection in an idle pool that
// nothing could ever reuse or close - one leaked AF_UNIX conn to docker.sock
// per call, forever (the pool's readLoop goroutine pins the conn, so GC never
// reclaims it).
//
// The test serves a fake Docker API on a unix socket, drives the REAL reconcile
// loop body (reconcileOnce with the production fetch/pidFor wiring) for 50
// iterations, and asserts the server-side open-connection count stays bounded.
func TestReconcile_NoDockerConnLeak(t *testing.T) {
	const fullID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	const pid = 4242

	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	counted := &countedListener{Listener: ln}

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"Id":%q,"Names":["/web.1.abc"],"State":"running",`+
			`"Ports":[{"IP":"0.0.0.0","PublicPort":8080,"PrivatePort":80,"Type":"tcp"}]}]`, fullID)
	})
	mux.HandleFunc("/containers/"+fullID+"/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"State":{"Pid":%d}}`, pid)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener.Close() // drop the default TCP listener
	srv.Listener = counted
	srv.Start()
	defer srv.Close()

	// Mirror the production auto-detect wiring from Start(): fetch and pidFor
	// are the real Docker-touching functions pointed at the fake socket; only
	// the namespace-socket openers are faked (no CAP_NET_RAW in tests).
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 16
	lc.config.DockerSocket = sock
	lc.vxlanPort = DefaultVXLANPort
	lc.deps = autoDetectDeps{
		fetch: func() ([]dockerContainer, error) { return fetchRunningContainers(sock) },
		pidFor: func(id, name string) (int, error) {
			info, perr := inspectContainerPID(sock, id, name)
			if perr != nil {
				return 0, perr
			}
			return info.PID, nil
		},
		openerFor: func(pc publicContainer, capture *namespaceCapture) func() (int, error) {
			return func() (int, error) {
				capture.containerID = shortID(pc.ID)
				capture.pid = pid
				return dgramFD(t), nil
			}
		},
		hostOpen: func(capture *namespaceCapture) (int, error) { return dgramFD(t), nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { lc.Close(); cancel() })

	const iterations = 50
	for i := 0; i < iterations; i++ {
		lc.reconcileOnce(ctx)
	}

	// Allow in-flight server-side closes to land, then assert the bound. On the
	// leaking code each iteration strands 2 connections (list + inspect), so
	// this sits near 100; fixed, it stays at most a couple in-flight conns.
	const maxOpen = 2
	deadline := time.Now().Add(2 * time.Second)
	openNow := counted.openConns()
	for openNow > maxOpen && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		openNow = counted.openConns()
	}
	if openNow > maxOpen {
		t.Fatalf("docker.sock connections leaked: %d still open after %d reconcile cycles (want <= %d)",
			openNow, iterations, maxOpen)
	}
}
