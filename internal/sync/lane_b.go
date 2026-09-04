package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// =============================================================================
// LANE B - heartbeat and snapshot
// =============================================================================
//
// Lane B reads the LOCAL dashboard API over in-process HTTP rather than
// re-deriving the same payloads from the store. That is deliberate: the hosted
// mirror then holds byte-identical bodies to what the local dashboard consumed,
// and handler assembly logic (stat aggregation, coverage shaping, pattern
// bucketing) exists in exactly one place. Bodies are opaque json.RawMessage
// here - this package decodes nothing beyond the pattern scope keys it must
// enumerate.
//
// [A10] Heartbeat and snapshot run on separate goroutines so a slow or hanging
// snapshot GET can never delay liveness reporting. Both are fully decoupled
// from lane A: a dead local API leaves findings and decisions syncing normally.

const (
	pathIngestStats     = "/api/ingest/stats"
	pathIngestSnapshot  = "/api/ingest/snapshot"
	pathIngestHeartbeat = "/api/ingest/heartbeat"

	// localBodyLimit bounds a single local API response. The pattern store
	// can be large; this is generous but not unbounded.
	localBodyLimit = 8 << 20
)

// runHeartbeat reports liveness on its own clock.
func (e *Engine) runHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.HeartbeatInterval)
	defer ticker.Stop()

	// Report immediately so a freshly paired instance shows up as live
	// without waiting a full interval.
	e.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sendHeartbeat(ctx)
		}
	}
}

func (e *Engine) sendHeartbeat(ctx context.Context) {
	status, body, err := e.postIngest(ctx, pathIngestHeartbeat, []byte(`{}`))
	switch {
	case err != nil:
		if ctx.Err() != nil {
			return
		}
		e.noteHeartbeat(false, fmt.Sprintf("%v", err))
	case status < 200 || status > 299:
		e.noteHeartbeat(false, fmt.Sprintf("HTTP %d: %s", status, snippet(body)))
	default:
		e.noteHeartbeat(true, "")
	}
}

// noteHeartbeat logs only transitions, so a long hosted outage costs two log
// lines rather than one per minute forever.
func (e *Engine) noteHeartbeat(ok bool, detail string) {
	switch {
	case !ok && !e.heartbeatDown:
		log.Printf("[sync] heartbeat failing: %s", detail)
		e.heartbeatDown = true
	case ok && e.heartbeatDown:
		log.Printf("[sync] heartbeat recovered")
		e.heartbeatDown = false
	}
}

// runSnapshot mirrors the dashboard's own view of this instance.
func (e *Engine) runSnapshot(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.SnapshotInterval)
	defer ticker.Stop()

	// [A10] The first cycle deliberately runs before the local API is
	// guaranteed to be serving (Start is async, and ListenAndServe can fail
	// late). A failure here logs once and retries next cycle.
	e.sendSnapshot(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sendSnapshot(ctx)
		}
	}
}

func (e *Engine) sendSnapshot(ctx context.Context) {
	localOK := true

	// --- stats: its own hosted route, appended with a server-side timestamp
	if stats, err := e.localGet(ctx, "/api/stats"); err != nil {
		localOK = false
		e.noteLocalAPI(ctx, false, fmt.Sprintf("GET /api/stats: %v", err))
	} else {
		body, mErr := json.Marshal(map[string]json.RawMessage{"stats": stats})
		if mErr != nil {
			log.Printf("[sync] snapshot: encoding stats failed: %v", mErr)
		} else if err := e.postSnapshotBody(ctx, pathIngestStats, body); err != nil {
			log.Printf("[sync] snapshot: %v", err)
		}
	}

	// --- merged snapshot: whichever parts we could read locally
	payload := make(map[string]json.RawMessage, 3)

	if patterns, err := e.fetchPatterns(ctx); err != nil {
		localOK = false
		e.noteLocalAPI(ctx, false, fmt.Sprintf("GET /api/patterns: %v", err))
	} else {
		payload["patterns"] = patterns
	}
	if trusted, err := e.localGet(ctx, "/api/trusted-ips"); err != nil {
		localOK = false
		e.noteLocalAPI(ctx, false, fmt.Sprintf("GET /api/trusted-ips: %v", err))
	} else {
		payload["trusted_ips"] = trusted
	}
	if coverage, err := e.localGet(ctx, "/api/rec/coverage"); err != nil {
		localOK = false
		e.noteLocalAPI(ctx, false, fmt.Sprintf("GET /api/rec/coverage: %v", err))
	} else {
		payload["rec_coverage"] = coverage
	}

	if localOK {
		e.noteLocalAPI(ctx, true, "")
	}

	// Nothing readable locally: skip the POST entirely rather than sending an
	// empty object the hosted side would merge as "no change".
	if len(payload) == 0 {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[sync] snapshot: encoding failed: %v", err)
		return
	}
	if err := e.postSnapshotBody(ctx, pathIngestSnapshot, body); err != nil {
		log.Printf("[sync] snapshot: %v", err)
	}
}

// noteLocalAPI logs local-API health transitions once, not per cycle.
// A cancelled context means we are shutting down, not that the local API
// broke - staying quiet there keeps shutdown logs honest.
func (e *Engine) noteLocalAPI(ctx context.Context, ok bool, detail string) {
	if ctx.Err() != nil {
		return
	}
	switch {
	case !ok && !e.laneBDown:
		log.Printf("[sync] local dashboard API unreachable, snapshot degraded: %s "+
			"(lane A is unaffected; retrying next cycle)", detail)
		e.laneBDown = true
	case ok && e.laneBDown:
		log.Printf("[sync] local dashboard API reachable again, snapshot restored")
		e.laneBDown = false
	}
}

// fetchPatterns builds the pattern composite: the scope list verbatim, plus
// each scope's full bucket payload verbatim.
//
// The scope list is the one local body this package decodes, and only far
// enough to read the scope keys. Scope churn between the list call and the
// per-scope calls self-heals on the next cycle - a snapshot is a periodic
// picture, not a transaction.
func (e *Engine) fetchPatterns(ctx context.Context) (json.RawMessage, error) {
	scopes, err := e.localGet(ctx, "/api/patterns")
	if err != nil {
		return nil, err
	}

	var summaries []struct {
		ScopeKey string `json:"scope_key"`
	}
	if err := json.Unmarshal(scopes, &summaries); err != nil {
		return nil, fmt.Errorf("decoding scope list: %w", err)
	}

	byScope := make(map[string]json.RawMessage, len(summaries))
	for _, summary := range summaries {
		if summary.ScopeKey == "" {
			continue
		}
		raw, err := e.localGet(ctx, "/api/patterns?scope="+url.QueryEscape(summary.ScopeKey))
		if err != nil {
			// One unreadable scope must not cost us the whole snapshot.
			log.Printf("[sync] snapshot: skipping scope %q: %v", summary.ScopeKey, err)
			continue
		}
		byScope[summary.ScopeKey] = raw
	}

	return json.Marshal(map[string]any{
		"scopes":   scopes,
		"by_scope": byScope,
	})
}

// postSnapshotBody POSTs a lane B payload. These routes are not batch routes,
// so there is no upserted/skipped contract to validate - a 2xx is the ack.
func (e *Engine) postSnapshotBody(ctx context.Context, path string, body []byte) error {
	status, respBody, err := e.postIngest(ctx, path, body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("POST %s: HTTP %d: %s", path, status, snippet(respBody))
	}
	return nil
}

// localGet reads one local dashboard API endpoint and returns its body
// verbatim, having only checked that it is valid JSON (an invalid body would
// corrupt the snapshot envelope it gets embedded in).
func (e *Engine) localGet(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.LocalBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if e.localToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.localToken)
	}

	resp, err := e.localClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, localBodyLimit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("response is not valid JSON (%s)", snippet(body))
	}
	return json.RawMessage(body), nil
}
