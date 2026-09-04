// shutdown_test.go
package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// [A7] Shutdown ordering regression test.
//
// The bug: cancelling the root context on SIGTERM made FindingsWriter.Run take
// its ctx.Done arm and exit while pipeline workers were still alive. Those
// workers kept calling SubmitFinding into a channel nobody consumed, and
// Store.Close's later Stop() returned immediately (done was already closed)
// without re-draining - so every finding produced during shutdown was lost.
//
// The fix is ordering, not new machinery: the writer is started on a context
// the signal does not cancel, and the pipeline is closed and drained BEFORE
// the writer is stopped. This test reproduces the exact window - every
// SubmitFinding here happens after the root context is already dead.
func TestShutdownDrainsFindingsProducedAfterContextCancel(t *testing.T) {
	dataDir := t.TempDir()
	db, err := store.Init(dataDir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Step 0: the writer outlives the root context, exactly as main.go wires it.
	db.StartAsyncWriter(context.Background(), 5000)

	const total = 500
	pipeline := make(chan *store.Finding, total)
	for i := 0; i < total; i++ {
		pipeline <- &store.Finding{
			EventID:        eventID(i),
			Timestamp:      time.Now(),
			SourceType:     "docker",
			SourceName:     "docker:test",
			Verdict:        "malicious",
			Classification: "malicious",
			HTTPMethod:     "GET",
			HTTPPath:       "/.env",
			HTTPStatus:     200,
		}
	}

	// SIGTERM: the root context dies while the pipeline is still full.
	rootCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if rootCtx.Err() == nil {
		t.Fatal("root context should be cancelled")
	}

	var ingestGate sync.RWMutex
	ingestOpen := true

	// Workers start only now, so every submission below happens strictly
	// after the cancel - the window the old code lost findings in.
	var pipelineWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		pipelineWG.Add(1)
		go func() {
			defer pipelineWG.Done()
			for f := range pipeline {
				db.SubmitFinding(f)
			}
		}()
	}

	// A watcher goroutine that has not noticed the cancel yet and keeps
	// producing straight through shutdown. Without the gate this is a
	// send-on-closed-channel panic.
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < 20000; i++ {
			ingestGate.RLock()
			if ingestOpen {
				select {
				case pipeline <- &store.Finding{
					EventID:        "late",
					Timestamp:      time.Now(),
					SourceType:     "docker",
					SourceName:     "docker:test",
					Verdict:        "recon",
					Classification: "recon_failed",
				}:
				default:
				}
			}
			ingestGate.RUnlock()
		}
	}()

	// --- the ordered shutdown, mirroring main.go ---
	ingestGate.Lock()
	ingestOpen = false
	close(pipeline)
	ingestGate.Unlock()

	if !waitTimeout(&pipelineWG, 15*time.Second) {
		t.Fatal("pipeline workers did not drain within 15s")
	}
	<-producerDone

	if err := db.Close(); err != nil {
		t.Fatalf("db close: %v", err)
	}

	// Reopen the same database: every buffered finding must have survived the
	// close, which is only true if the writer drained after the producers.
	reopened, err := store.Init(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	persisted := countPersisted(t, reopened)
	if persisted < total {
		t.Errorf("persisted findings = %d; want at least %d - findings submitted during "+
			"shutdown were dropped", persisted, total)
	}
}

func eventID(i int) string {
	return "evt-" + time.Now().Format("150405") + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func countPersisted(t *testing.T, db *store.Store) int {
	t.Helper()
	var n int
	if err := db.DB().QueryRow("SELECT COUNT(*) FROM findings").Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

// waitTimeout must report failure rather than blocking forever on a wedged
// worker - shutdown stays bounded.
func TestWaitTimeout(t *testing.T) {
	var done sync.WaitGroup
	if !waitTimeout(&done, time.Second) {
		t.Error("waitTimeout on an empty group returned false")
	}

	var stuck sync.WaitGroup
	stuck.Add(1)
	if waitTimeout(&stuck, 50*time.Millisecond) {
		t.Error("waitTimeout returned true for a group that never finished")
	}
	stuck.Done()
}
