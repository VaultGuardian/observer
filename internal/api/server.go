package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// Dashboard API Server
// =============================================================================
//
// Serves the dashboard API and (in future) the embedded React SPA.
// Auth: bearer token auto-generated to a key file on first run.
//
// DESIGN PRINCIPLE: The API is the control surface for Observer.
// It must live in the same process as the pattern store, SQLite,
// and LLM client — not a separate service.

// ServerConfig holds API server configuration.
type ServerConfig struct {
	// Port to listen on (default 9090)
	Port int

	// Path to the bearer token key file.
	// If the file doesn't exist, a new key is auto-generated.
	KeyFile string

	// Interface address to bind. Default 127.0.0.1 (localhost only — safest).
	// Set to 0.0.0.0 ONLY when fronting with a reverse proxy or VPN, AND
	// firewalling the port to known sources. Bare 0.0.0.0 + open firewall
	// exposes the control plane to the public internet.
	BindAddr string

	// CORS allowlist for browser-origin dashboards. Empty list = no CORS
	// headers set (correct for server-side proxy patterns where the
	// browser never talks to Observer directly). Populated list = echo
	// matched Origin back, set CORS headers only for allowed origins.
	AllowedOrigins []string

	// Version reported by /api/health (set from main.Version at construction).
	Version string
}

// Server is the dashboard API server.
type Server struct {
	config    ServerConfig
	token     string
	store     *store.Store
	patterns  *patternstore.Store
	analyzer  *analyzer.Analyzer
	collector rec.EvidenceCollector

	// v0.52: retained for graceful shutdown. Prior to this, Start() created
	// a local http.Server with no way to call Shutdown() from outside.
	httpServer *http.Server

	// Pre-computed CORS origin lookup for O(1) allowlist checks.
	allowedOrigins map[string]struct{}

	// Human correction callbacks — narrow interfaces to avoid coupling
	// the API package to coordinator/reclassCache internals.
	// Set via SetCorrectionCallbacks() after construction.
	//
	// Section 3 / Landmine A: onSeedCatchAll now also takes responseBytes
	// so the live coordinator entry can participate in the byte-aware
	// Phase 3 fallback. Pre-existing rules with response_bytes=0 in the
	// DB are skipped by the fallback path until re-verified.
	//
	// v1.0 Card 4: onSeedExpectedEndpoint wires the new path-scoped
	// operator-confirmed expected-response tracker. Signature includes
	// http_status because the tracker keys on it (P1 lock-in, May 11
	// 2026). bodyHash here is the REDACTED shape hash (decision.CacheKey),
	// NEVER the raw transport hash. getExpectedEndpointStats exposes
	// tracker counters to /api/stats without coupling the API server type
	// to the tracker type or the coordinator type.
	onInvalidateReclassCache func(bodyHash string)
	onSeedCatchAll           func(host, method string, status int, bodyHash, reason string, responseBytes int64)
	onSeedExpectedEndpoint   func(host, method string, status int, path, bodyHash, reason string)
	getExpectedEndpointStats func() (total int, suppressed int64)

	// getNotifierStats exposes notifier dispatcher counters to /api/stats
	// without coupling the API server type to the notifier package.
	// Returns the cumulative count of alerts dropped because a channel's
	// queue was full, and the number of active notification channels.
	getNotifierStats func() (dropped int64, channels int)
}

// NewServer creates the API server and loads (or generates) the auth token.
func NewServer(
	cfg ServerConfig,
	db *store.Store,
	patterns *patternstore.Store,
	a *analyzer.Analyzer,
	collector rec.EvidenceCollector,
) (*Server, error) {
	token, err := loadOrGenerateToken(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("dashboard auth setup: %w", err)
	}

	// Defense in depth: if the token file existed but was empty/whitespace,
	// loadOrGenerateToken returned an empty string. Refuse to start rather
	// than silently regenerating (which would lock the user out of their
	// existing dashboard) or running with empty token (which would let
	// empty Authorization headers compare-equal and bypass auth).
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("dashboard auth setup: token file %s is empty or whitespace; delete it to regenerate", cfg.KeyFile)
	}

	// Build O(1) origin lookup for CORS middleware.
	originSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		originSet[o] = struct{}{}
	}

	return &Server{
		config:         cfg,
		token:          token,
		store:          db,
		patterns:       patterns,
		analyzer:       a,
		collector:      collector,
		allowedOrigins: originSet,
	}, nil
}

// SetNotifierStatsCallback wires the notifier dispatcher's counter accessors
// to /api/stats. Called from main.go after the dispatcher is constructed.
// Decoupled from the API server type so this package doesn't need to
// import internal/notifier.
func (s *Server) SetNotifierStatsCallback(notifierStats func() (dropped int64, channels int)) {
	s.getNotifierStats = notifierStats
}

// SetCorrectionCallbacks wires the human correction system to the coordinator
// and reclass cache. Called from main.go after both are initialized.
//
// Section 3 / Landmine A: seedCatchAll now takes responseBytes so the
// byte-aware Phase 3 fallback works for human-confirmed catch-alls too.
//
// v1.0 Card 4: seedExpectedEndpoint wires Option 4 ("Expected sensitive
// response") clicks into the live tracker. Signature includes http_status
// (P1 lock-in, May 11 2026). bodyHash here is the REDACTED response-shape
// hash, NEVER the raw transport hash. expectedEndpointStats exposes the
// tracker's counters to /api/stats.
func (s *Server) SetCorrectionCallbacks(
	invalidateCache func(bodyHash string),
	seedCatchAll func(host, method string, status int, bodyHash, reason string, responseBytes int64),
	seedExpectedEndpoint func(host, method string, status int, path, bodyHash, reason string),
	expectedEndpointStats func() (total int, suppressed int64),
) {
	s.onInvalidateReclassCache = invalidateCache
	s.onSeedCatchAll = seedCatchAll
	s.onSeedExpectedEndpoint = seedExpectedEndpoint
	s.getExpectedEndpointStats = expectedEndpointStats
}

// Start begins serving the API. Blocks until the server shuts down.
// Run in a goroutine from main.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// --- Health (no auth) ---
	mux.HandleFunc("/api/health", s.handleHealth)

	// --- Auth-protected API routes ---
	mux.Handle("/api/findings", s.requireAuth(http.HandlerFunc(s.handleFindings)))
	mux.Handle("/api/findings/counts", s.requireAuth(http.HandlerFunc(s.handleFindingCounts)))
	mux.Handle("/api/stats", s.requireAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/patterns", s.requireAuth(http.HandlerFunc(s.handlePatterns)))
	mux.Handle("/api/patterns/delete", s.requireAuth(http.HandlerFunc(s.handleDeletePattern)))
	mux.Handle("/api/decisions", s.requireAuth(http.HandlerFunc(s.handleDecisions)))
	mux.Handle("/api/decisions/counts", s.requireAuth(http.HandlerFunc(s.handleDecisionCounts)))
	mux.Handle("/api/decisions/review", s.requireAuth(http.HandlerFunc(s.handleDecisionReview)))
	mux.Handle("/api/trusted-ips", s.requireAuth(http.HandlerFunc(s.handleTrustedIPs)))
	mux.Handle("/api/trusted-ips/delete", s.requireAuth(http.HandlerFunc(s.handleDeleteTrustedIP)))
	mux.Handle("/api/corrections", s.requireAuth(http.HandlerFunc(s.handleCorrection)))

	// Default bind to localhost if not configured. Defense in depth — if
	// somehow the config arrived without a BindAddr, lock down rather than
	// expose the control plane.
	bindAddr := s.config.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(s.config.Port))

	// Visible startup state — makes "why doesn't my dashboard connect" debuggable.
	log.Printf("[api] Dashboard API listening: bind=%s port=%d cors_origins=%d key_file=%s",
		bindAddr, s.config.Port, len(s.allowedOrigins), s.config.KeyFile)

	// Loud warning when binding to all interfaces. v0.45.0 default is
	// 127.0.0.1; this fires when the operator explicitly opts into public
	// exposure (Vercel-proxied dashboards, hosted setups).
	if bindAddr == "0.0.0.0" {
		log.Printf("[api:warn] Dashboard API is listening on ALL interfaces (0.0.0.0). " +
			"Protect with firewall rules, VPN, or reverse proxy with TLS. " +
			"Bare 0.0.0.0 exposes the control plane to the public internet.")
	}

	// Slowloris/timeout hardening. ReadHeaderTimeout is the most important
	// for slowloris-style attacks; the others bound tail-latency abuse.
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.securityHeadersMiddleware(s.corsMiddleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	s.httpServer = srv
	return srv.ListenAndServe()
}

// Shutdown gracefully stops the API server, allowing in-flight requests
// to complete within the given context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// corsMiddleware sets CORS headers only for explicitly allowed origins.
//
// Empty allowlist = no CORS headers (correct for server-side proxy patterns
// where the browser never directly hits Observer — e.g. Vercel proxy).
//
// Non-empty allowlist = echo matched Origin (not wildcard). Browsers reject
// wildcard + credentials, and our bearer-token API benefits from the same
// stricter posture even though we don't use cookies.
//
// Origin not in allowlist = no CORS headers set. The cross-origin request
// will fail at the browser, which is what we want.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := s.allowedOrigins[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}

		// Preflight — return immediately, don't hit auth.
		// (CORS-non-compliant browsers will fail at the missing CORS headers
		// above; this just avoids wasting auth checks on OPTIONS.)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds defensive headers to every response.
//
// HSTS is intentionally omitted — Observer's API serves HTTP locally and TLS
// is terminated upstream (nginx/Caddy/Vercel proxy). Setting HSTS on a raw
// HTTP response is meaningless and can confuse browsers when behind a proxy
// that already sets it correctly.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Auth Middleware
// =============================================================================

// requireAuth wraps a handler with bearer token verification.
//
// v0.45.0 hardening:
//   - Header-only authentication. Query-param token support removed — bearer
//     tokens leak into shell history, browser history, reverse proxy logs,
//     access logs, and Referer headers. Use curl -H instead for testing.
//   - Length check before ConstantTimeCompare. Go's subtle.ConstantTimeCompare
//     returns 0 immediately for unequal-length slices, leaking length via
//     timing. Token length is fixed (64-char hex), but the cleaner pattern
//     is to reject mismatched-length up front.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, "Missing Authorization: Bearer <token> header", http.StatusUnauthorized)
			return
		}

		provided := strings.TrimPrefix(auth, "Bearer ")
		if len(provided) != len(s.token) {
			jsonError(w, "Invalid token", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			jsonError(w, "Invalid token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Handlers
// =============================================================================

// GET /api/health — No auth, just proves the API is up.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"version": s.config.Version,
	})
}

// GET /api/findings?verdict=alert&limit=50&since=2026-03-30T00:00:00Z
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	verdict := r.URL.Query().Get("verdict")
	ip := r.URL.Query().Get("ip")
	eventID := r.URL.Query().Get("event_id")
	limitStr := r.URL.Query().Get("limit")

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	ctx := r.Context()

	// Single finding by event_id — used by Event Detail Page
	if eventID != "" {
		finding, err := s.store.GetFindingByEventID(ctx, eventID)
		if err != nil {
			jsonError(w, fmt.Sprintf("Finding not found: %v", err), http.StatusNotFound)
			return
		}
		jsonOK(w, []store.Finding{*finding})
		return
	}

	var findings []store.Finding
	var err error

	switch {
	case ip != "":
		findings, err = s.store.QueryByIP(ctx, ip, limit)
	case verdict != "":
		findings, err = s.store.QueryByVerdict(ctx, verdict, limit)
	default:
		findings, err = s.store.QueryRecent(ctx, limit)
	}

	if err != nil {
		jsonError(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, findings)
}

// GET /api/findings/counts?since=2026-03-30T00:00:00Z
func (s *Server) handleFindingCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sinceStr := r.URL.Query().Get("since")
	since := time.Now().Add(-24 * time.Hour) // default: last 24 hours
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	counts, err := s.store.CountByVerdict(r.Context(), since)
	if err != nil {
		jsonError(w, fmt.Sprintf("Count query failed: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, counts)
}

// GET /api/stats — Pipeline stats, pattern store stats, REC telemetry.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	aStats := s.analyzer.GetStats()
	pStats := s.patterns.GetStats()

	result := map[string]interface{}{
		"pipeline": map[string]interface{}{
			"processed":        aStats.TotalProcessed,
			"pattern_hits":     aStats.PatternHits,
			"noise_suppressed": aStats.NoiseSuppressed,
			"llm_calls":        aStats.LLMCalls,
			"llm_errors":       aStats.LLMErrors,
			"patterns_learned": aStats.PatternsLearned,
		},
		"patterns": pStats,
	}

	// v1.0 Card 4: surface ExpectedEndpoint tracker counters. Nil-safe so
	// the API doesn't break if the coordinator/tracker failed to start.
	if s.getExpectedEndpointStats != nil {
		eeTotal, eeSuppressed := s.getExpectedEndpointStats()
		result["expected_endpoints"] = map[string]interface{}{
			"total":      eeTotal,
			"suppressed": eeSuppressed,
		}
	}

	// Notifier dispatcher counters. Nil-safe.
	if s.getNotifierStats != nil {
		nDropped, nChannels := s.getNotifierStats()
		result["notifier"] = map[string]interface{}{
			"channels": nChannels,
			"dropped":  nDropped,
		}
	}

	if s.collector.Enabled() {
		rStats := s.collector.Stats()
		result["rec"] = map[string]interface{}{
			"packets":             rStats.PacketsSeen,
			"http_requests":       rStats.HTTPRequests,
			"http_responses":      rStats.HTTPResponses,
			"pair_misses":         rStats.PairMisses,
			"pair_immediate":      rStats.PairImmediate,
			"orphan_responses":    rStats.OrphanResponses,
			"requests_expired":    rStats.RequestsExpired,
			"inline_requests":     rStats.InlineRequests,
			"inline_seq_dedup":    rStats.InlineDuplicateDrops,
			"inline_body_skip":    rStats.InlineBodySkips,
			"vxlan_unwrapped":     rStats.VXLANUnwrapped,
			"buffer_entries":      rStats.BufferEntries,
			"buffer_bytes":        rStats.BufferBytes,
			"reassembly_active":   rStats.ReassemblyStreamsActive,
			"reassembly_total":    rStats.ReassemblyStreamsTotal,
			"reassembly_timeout":  rStats.ReassemblyStreamsTimedOut,
			"reassembly_drops":    rStats.ReassemblyStreamDrops,
			"reassembly_errors":   rStats.ReassemblyParseErrors,
			"flow_states":         rStats.FlowStates,
			"flow_evictions":      rStats.FlowEvictions,
			"flow_evictions_live": rStats.FlowEvictionsLive,
		}
	}

	jsonOK(w, result)
}

// GET /api/patterns?scope=docker:captain-nginx&verdict=alert
// GET /api/patterns (no params = list scopes)
func (s *Server) handlePatterns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scopeKey := r.URL.Query().Get("scope")
	verdictStr := r.URL.Query().Get("verdict")

	// No params → list all scopes with counts
	if scopeKey == "" {
		jsonOK(w, s.patterns.ListScopes())
		return
	}

	// Scope provided but no verdict → return all four buckets
	if verdictStr == "" {
		result := map[string]interface{}{
			"scope":     scopeKey,
			"allow":     s.patterns.ListPatterns(scopeKey, patternstore.VerdictAllow),
			"malicious": s.patterns.ListPatterns(scopeKey, patternstore.VerdictMalicious),
			"alert":     s.patterns.ListPatterns(scopeKey, patternstore.VerdictAlert),
			"suppress":  s.patterns.ListPatterns(scopeKey, patternstore.VerdictSuppress),
		}
		jsonOK(w, result)
		return
	}

	// Both scope and verdict → return that specific bucket
	verdict := patternstore.Verdict(verdictStr)
	patterns := s.patterns.ListPatterns(scopeKey, verdict)
	if patterns == nil {
		patterns = []patternstore.LearnedPattern{} // empty array not null
	}
	jsonOK(w, map[string]interface{}{
		"scope":    scopeKey,
		"verdict":  verdictStr,
		"patterns": patterns,
	})
}

// POST /api/patterns/delete — Remove a pattern from the store.
// Body: {"scope": "docker:captain-nginx", "verdict": "alert", "value": "abc123..."}
func (s *Server) handleDeletePattern(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Scope   string `json:"scope"`
		Verdict string `json:"verdict"`
		Value   string `json:"value"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Scope == "" || req.Verdict == "" || req.Value == "" {
		jsonError(w, "Missing required fields: scope, verdict, value", http.StatusBadRequest)
		return
	}
	// Validate verdict against the known enum. patternstore.getBucket() defaults
	// unknown verdicts to the allow bucket, so a typo would silently delete from
	// the wrong bucket. Reject explicitly.
	switch req.Verdict {
	case "allow", "malicious", "alert", "suppress":
		// ok
	default:
		jsonError(w, "Invalid verdict. Must be one of: allow, malicious, alert, suppress", http.StatusBadRequest)
		return
	}

	deleted := s.patterns.DeletePattern(req.Scope, patternstore.Verdict(req.Verdict), req.Value)
	if !deleted {
		jsonError(w, "Pattern not found", http.StatusNotFound)
		return
	}

	// Persist changes to disk
	if err := s.patterns.Persist(); err != nil {
		log.Printf("[api] Warning: pattern deleted but persist failed: %v", err)
	}

	log.Printf("[api] Pattern deleted: scope=%s verdict=%s value=%.32s", req.Scope, req.Verdict, req.Value)
	jsonOK(w, map[string]string{"status": "deleted"})
}

// =============================================================================
// Token Management
// =============================================================================

// loadOrGenerateToken reads the auth token from a file, or generates one if
// the file doesn't exist. The token is a 32-byte random hex string.
func loadOrGenerateToken(keyFile string) (string, error) {
	// Ensure directory exists
	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating key directory %s: %w", dir, err)
	}

	// Try to read existing key
	data, err := os.ReadFile(keyFile)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if len(token) >= 32 {
			log.Printf("[api] Dashboard token loaded from %s", keyFile)
			return token, nil
		}
		log.Printf("[api] Key file %s exists but token too short — regenerating", keyFile)
	}

	// Generate new token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Write with restrictive permissions (owner read only)
	if err := os.WriteFile(keyFile, []byte(token+"\n"), 0600); err != nil {
		return "", fmt.Errorf("writing key file %s: %w", keyFile, err)
	}

	log.Printf("[api] Dashboard token generated → %s", keyFile)
	log.Printf("[api] To access the dashboard API, use: Authorization: Bearer <contents of %s>", keyFile)
	return token, nil
}

// =============================================================================
// LLM Decision Audit Trail Endpoints
// =============================================================================

// handleDecisions lists LLM decisions with optional filters.
// GET /api/decisions?tier=classify&classification=malicious&review_status=pending&limit=50
func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := store.LLMDecisionFilter{}

	filter.Tier = r.URL.Query().Get("tier")
	filter.Classification = r.URL.Query().Get("classification")
	filter.ReviewStatus = r.URL.Query().Get("review_status")
	filter.SourceScope = r.URL.Query().Get("source_scope")
	filter.EventID = r.URL.Query().Get("event_id")

	if v := r.URL.Query().Get("min_confidence"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			filter.MinConfidence = f
		}
	}
	if v := r.URL.Query().Get("max_confidence"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			filter.MaxConfidence = f
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			// Clamp to sane bounds: 1..500. strconv.Atoi happily parses negatives,
			// which would either choke the SQL driver or panic on negative slice
			// allocations downstream.
			if n < 1 {
				n = 1
			}
			if n > 500 {
				n = 500
			}
			filter.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 0 {
				n = 0
			}
			filter.Offset = n
		}
	}

	decisions, err := s.store.ListLLMDecisions(r.Context(), filter)
	if err != nil {
		jsonError(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, decisions)
}

// handleDecisionCounts returns summary stats for the decisions dashboard.
// GET /api/decisions/counts
func (s *Server) handleDecisionCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	counts, err := s.store.GetLLMDecisionCounts(r.Context())
	if err != nil {
		jsonError(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, counts)
}

// handleDecisionReview updates the human review on a decision.
// POST /api/decisions/review
// Body: {"id": 42, "status": "corrected", "verdict": "safe", "reason": "...", "pattern_deleted": true}
func (s *Server) handleDecisionReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID     int64           `json:"id"`
		Review store.LLMReview `json:"review"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.ID == 0 {
		jsonError(w, "id is required", http.StatusBadRequest)
		return
	}
	// Validate status against the documented enum. The previous "Status != ''"
	// check let arbitrary strings into the database — confusing dashboards and
	// breaking any future query that filters on status.
	switch req.Review.Status {
	case "confirmed", "corrected", "ignored":
		// ok
	default:
		jsonError(w, "review.status must be one of: confirmed, corrected, ignored", http.StatusBadRequest)
		return
	}

	// Delete-only correction is disabled — use /api/corrections instead.
	// The old path deleted patterns without creating replacements, leaving
	// the line to go back to the LLM naked. That's a half-feature that can
	// reintroduce the same bad classification.
	if req.Review.PatternDeleted && req.Review.Status == "corrected" {
		jsonError(w, "delete-only correction is disabled; use /api/corrections", http.StatusGone)
		return
	}

	if err := s.store.UpdateLLMDecisionReview(r.Context(), req.ID, req.Review); err != nil {
		jsonError(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[api] Decision #%d reviewed: status=%s verdict=%s pattern_deleted=%v",
		req.ID, req.Review.Status, req.Review.Verdict, req.Review.PatternDeleted)

	jsonOK(w, map[string]string{"status": "ok"})
}

// =============================================================================
// Trusted IPs Endpoints (Policy Engine Allowlist)
// =============================================================================

// handleTrustedIPs handles GET (list) and POST (add) for trusted IPs.
// GET /api/trusted-ips — List all trusted IPs/CIDRs
// POST /api/trusted-ips — Add a trusted IP or CIDR range
func (s *Server) handleTrustedIPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listTrustedIPs(w, r)
	case http.MethodPost:
		s.addTrustedIP(w, r)
	default:
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listTrustedIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := s.store.ListTrustedIPs(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ips == nil {
		ips = []store.TrustedIP{} // return [] not null
	}
	jsonOK(w, ips)
}

func (s *Server) addTrustedIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP          string `json:"ip"`
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.IP == "" && req.CIDR == "" {
		jsonError(w, "Either 'ip' or 'cidr' is required", http.StatusBadRequest)
		return
	}
	// Validate IP/CIDR format up front. Without this, "ip": "pancakes" gets
	// happily stored, then crashes whichever consumer (firewall, policy
	// engine) tries to interpret it later.
	if req.IP != "" && net.ParseIP(req.IP) == nil {
		jsonError(w, "Invalid IP address format", http.StatusBadRequest)
		return
	}
	if req.CIDR != "" {
		if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
			jsonError(w, "Invalid CIDR format: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	entry := &store.TrustedIP{
		IPAddress:   req.IP,
		CIDR:        req.CIDR,
		Description: req.Description,
		AddedBy:     "api",
	}

	id, err := s.store.AddTrustedIP(r.Context(), entry)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[api] Trusted IP added: id=%d ip=%s cidr=%s desc=%s", id, req.IP, req.CIDR, req.Description)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "Trusted IP added",
	})
}

// handleDeleteTrustedIP handles POST /api/trusted-ips/delete
// Body: {"id": 1}
func (s *Server) handleDeleteTrustedIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := s.store.RemoveTrustedIP(r.Context(), req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("[api] Trusted IP removed: id=%d", req.ID)
	jsonOK(w, map[string]string{"message": "Trusted IP removed"})
}

// =============================================================================
// Human Correction Endpoint (design consensus)
// =============================================================================
//
// POST /api/corrections
//
// Two correction types, each wired to a different pipeline layer:
//
//   "noise" — Infrastructure noise (healthchecks, admin panel, deployment logs).
//     Safe BY IDENTITY. Creates a hash pattern in the correct bucket so the
//     pattern store catches it deterministically on repeat. The LLM never
//     sees this line again.
//
//   "failed_probe" — Attack that had no observable impact (SQL injection that
//     returned a generic page). Safe BY OUTCOME, not by identity. The request
//     IS dangerous — it just didn't work THIS time. Fingerprints the harmless
//     RESPONSE and seeds it into the catch-all evidence layer. T1 still flags
//     the request as malicious next time, but T2 recognizes the same harmless
//     response body and auto-downgrades. If the response ever changes (attack
//     actually worked), T2 sees a different body and escalates.
//
//   SECURITY INVARIANT: "failed_probe" NEVER creates a request-line pattern.
//   Caught in review: suppressing "UNION SELECT" because it returned a
//   harmless page today would globally whitelist SQL injection forever.
//   (design consensus, April 28 2026.)

func (s *Server) handleCorrection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type          string `json:"type"`           // "noise", "failed_probe", "expected_endpoint", or "confirm"
		EventID       string `json:"event_id"`       // finding lookup key
		DecisionID    int64  `json:"decision_id"`    // LLM decision lookup key (0 = cache hit, no decision)
		TargetVerdict string `json:"target_verdict"` // for noise: "suppress" or "allow"
		Reason        string `json:"reason"`
	}

	if !decodeJSON(w, r, &req) {
		return
	}

	if req.EventID == "" {
		jsonError(w, "event_id is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Look up the finding server-side — never trust frontend-supplied data
	// for a security control plane.
	finding, err := s.store.GetFindingByEventID(ctx, req.EventID)
	if err != nil {
		jsonError(w, "finding not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Look up the LLM decision if one exists
	var decision *store.LLMDecision
	if req.DecisionID > 0 {
		decision, err = s.store.GetLLMDecision(ctx, req.DecisionID)
		if err != nil {
			log.Printf("[correction] Warning: decision %d not found: %v", req.DecisionID, err)
			// Not fatal — cache-hit events have no decision
		}
	}

	// Verify decision belongs to this finding (prevent accidental cross-wiring)
	if decision != nil && decision.EventID != "" && decision.EventID != finding.EventID {
		jsonError(w, "decision does not belong to this event", http.StatusBadRequest)
		return
	}

	sourceScope := finding.SourceType + ":" + finding.SourceName

	switch req.Type {
	case "noise":
		s.handleNoiseCorrection(w, ctx, finding, decision, sourceScope, req.TargetVerdict, req.Reason)
	case "failed_probe":
		s.handleFailedProbeCorrection(w, ctx, finding, decision, req.Reason)
	case "expected_endpoint":
		s.handleExpectedEndpointCorrection(w, ctx, finding, decision, req.Reason)
	case "confirm":
		s.handleConfirmCorrection(w, ctx, finding, decision, sourceScope)
	default:
		jsonError(w, "invalid correction type: must be 'noise', 'failed_probe', 'expected_endpoint', or 'confirm'", http.StatusBadRequest)
	}
}

// handleNoiseCorrection — "This is routine infrastructure noise"
// Creates a deterministic hash pattern in the suppress/allow bucket.
// Deletes the old bad pattern using server-side data (decision or finding).
func (s *Server) handleNoiseCorrection(w http.ResponseWriter, ctx context.Context,
	finding *store.Finding, decision *store.LLMDecision, sourceScope, targetVerdict, reason string) {

	if targetVerdict != "suppress" && targetVerdict != "allow" {
		jsonError(w, "target_verdict must be 'suppress' or 'allow'", http.StatusBadRequest)
		return
	}

	humanReason := "human: " + reason
	if reason == "" {
		humanReason = "human: marked as " + targetVerdict
	}

	// Resolve hash and line — prefer finding, fall back to decision.
	// Empty hash patterns are dirty state waiting to happen.
	hash := finding.NormalizedHash
	line := finding.NormalizedLine
	if hash == "" && decision != nil {
		hash = decision.NormalizedHash
		line = decision.NormalizedLine
	}
	if hash == "" {
		jsonError(w, "cannot create correction: normalized hash missing", http.StatusBadRequest)
		return
	}

	// Step 1: Delete the old bad pattern. Check BOTH decision (LLM-learned
	// patterns) and finding (cache-hit patterns). If a malicious/alert hash
	// was learned by the LLM, it lives on the decision, not the finding.
	// If we only check the finding, the old bad pattern survives and wins
	// on priority (malicious > suppress).
	if decision != nil && decision.PatternLearned && decision.PatternValue != "" {
		bucket := decision.PatternBucket
		if bucket == "" {
			bucket = decision.Action
		}
		scope := decision.SourceScope
		if scope == "" {
			scope = sourceScope
		}
		if deleted := s.patterns.DeletePattern(scope, patternstore.Verdict(bucket), decision.PatternValue); deleted {
			log.Printf("[correction] Deleted LLM-learned pattern: scope=%s bucket=%s value=%.32s", scope, bucket, decision.PatternValue)
		}
	}
	if finding.MatchedPatternValue != "" && finding.MatchedPatternBucket != "" {
		scope := finding.MatchedPatternScope
		if scope == "" {
			scope = sourceScope
		}
		if deleted := s.patterns.DeletePattern(scope, patternstore.Verdict(finding.MatchedPatternBucket), finding.MatchedPatternValue); deleted {
			log.Printf("[correction] Deleted finding-matched pattern: scope=%s bucket=%s value=%.32s",
				scope, finding.MatchedPatternBucket, finding.MatchedPatternValue)
		}
	}

	// Step 2: Create the correct human hash pattern with "human" source
	if err := s.patterns.Learn(sourceScope, patternstore.Verdict(targetVerdict), patternstore.LearnedPattern{
		Type:               patternstore.PatternHash,
		Value:              hash,
		Source:             "human",
		Reason:             humanReason,
		OriginalLine:       line,
		CreatedAt:          time.Now(),
		CreatedFromEventID: finding.EventID,
	}); err != nil {
		jsonError(w, "failed to create pattern: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 3: Persist to disk — hard error for human corrections.
	// The whole point is "permanent fix." If persist fails, the pattern
	// disappears on restart and the user thinks they fixed it.
	if err := s.patterns.Persist(); err != nil {
		jsonError(w, "pattern created in memory but failed to persist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 4: Update the finding verdict
	if err := s.store.UpdateFindingVerdict(ctx, finding.EventID, targetVerdict, humanReason); err != nil {
		log.Printf("[correction] Warning: finding update failed: %v", err)
	}

	// Step 5: Mark LLM decision as corrected (if one exists)
	if decision != nil {
		if err := s.store.UpdateLLMDecisionReview(ctx, decision.ID, store.LLMReview{
			Status:         "corrected",
			ReviewedBy:     "dashboard",
			Verdict:        targetVerdict,
			Reason:         humanReason,
			PatternDeleted: true,
		}); err != nil {
			log.Printf("[correction] Warning: decision review update failed: %v", err)
		}
	}

	log.Printf("[correction:noise] scope=%s verdict=%s hash=%.16s event=%s",
		sourceScope, targetVerdict, hash, finding.EventID)

	jsonOK(w, map[string]string{"status": "ok", "type": "noise", "verdict": targetVerdict})
}

// handleFailedProbeCorrection — "Attack attempt, no observable impact"
// Fingerprints the harmless RESPONSE, not the request. All data built
// server-side from the finding and decision records.
func (s *Server) handleFailedProbeCorrection(w http.ResponseWriter, ctx context.Context,
	finding *store.Finding, decision *store.LLMDecision, reason string) {

	// Build evidence fingerprint from server-side data.
	// Prefer evidence status over access-log status — they can diverge.
	host := finding.DestHost
	method := finding.HTTPMethod
	status := finding.EvidenceStatusCode
	if status == 0 {
		status = finding.HTTPStatus
	}
	bodyHash := finding.EvidenceBodyHash
	contentType := finding.EvidenceContentType

	// Fall back to decision data if finding doesn't have it
	if decision != nil {
		if bodyHash == "" {
			bodyHash = decision.EvidenceHash
		}
		if contentType == "" {
			contentType = decision.EvidenceType
		}
		if status == 0 {
			status = decision.EvidenceStatus
		}
	}

	// HARD GUARD: Cannot mark as failed probe without response evidence.
	//
	if host == "" || method == "" || status == 0 || bodyHash == "" {
		jsonError(w, "Cannot mark as failed probe: no response evidence available for this event", http.StatusBadRequest)
		return
	}

	humanReason := "human: " + reason
	if reason == "" {
		humanReason = "human: marked as failed probe (no observable impact)"
	}

	// Step 1: Save to catchall_verified_v2 (persistent)
	//
	// Section 3 / Landmine A: persist finding.ResponseBytes so the byte-aware
	// Phase 3 fallback can use it. If the finding has no recorded
	// response_bytes (legacy or non-HTTP case), we save 0 — fallback will
	// skip until something re-verifies with a real measurement.
	err := s.store.SaveVerifiedCatchAll(ctx, &store.CatchAllRule{
		Host:                host,
		HTTPMethod:          method,
		HTTPStatus:          status,
		BodyPreviewHash:     bodyHash,
		VerifiedAt:          time.Now(),
		ContentType:         contentType,
		VerificationVerdict: "benign",
		VerificationReason:  humanReason,
		ResponseBytes:       finding.ResponseBytes,
	})
	if err != nil {
		jsonError(w, "failed to save catch-all rule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 2: Seed into live coordinator (active immediately, no restart)
	if s.onSeedCatchAll != nil {
		s.onSeedCatchAll(host, method, status, bodyHash, humanReason, finding.ResponseBytes)
	}

	// Step 3: Invalidate reclass cache.
	// The reclass cache is keyed on the REDACTED body hash (decision.CacheKey),
	// NOT the raw BodyPreviewHash. Invalidate BOTH to be safe.
	if s.onInvalidateReclassCache != nil {
		s.onInvalidateReclassCache(bodyHash) // raw body hash
		if decision != nil && decision.CacheKey != "" {
			s.onInvalidateReclassCache(decision.CacheKey) // redacted body hash (actual reclass cache key)
		}
	}

	// Step 4: Update the finding
	if err := s.store.UpdateFindingVerdict(ctx, finding.EventID, "recon", humanReason); err != nil {
		log.Printf("[correction] Warning: finding update failed: %v", err)
	}

	// Step 5: Mark LLM decision as corrected (if one exists)
	if decision != nil {
		if err := s.store.UpdateLLMDecisionReview(ctx, decision.ID, store.LLMReview{
			Status:     "corrected",
			ReviewedBy: "dashboard",
			Verdict:    "recon",
			Reason:     humanReason,
		}); err != nil {
			log.Printf("[correction] Warning: decision review update failed: %v", err)
		}
	}

	log.Printf("[correction:failed_probe] host=%s method=%s status=%d hash=%.16s event=%s",
		host, method, status, bodyHash, finding.EventID)

	jsonOK(w, map[string]string{"status": "ok", "type": "failed_probe"})
}

// handleExpectedEndpointCorrection — "Expected sensitive response" (Card 4).
//
// Path-scoped operator confirmation that an endpoint is supposed to return
// sensitive-looking data (login/token/reset/OAuth flows). The match is keyed
// on the REDACTED response-shape hash (decision.CacheKey), NOT the raw
// transport body hash. This is critical: auth endpoints return rotating
// tokens, so raw hashes change every login while redacted shape hashes stay
// stable.
//
// SECURITY INVARIANT: This NEVER creates a request-line pattern. The match
// is strictly (host, method, path, status, shape_hash). The endpoint stays
// under inspection — same shape downgrades, novel shape (CVE, data leak,
// misconfig) still escalates correctly. That's the safety net.
//
// Architectural distinction from failed_probe:
//
//	failed_probe         → catchall_verified_v2  — path-agnostic, statistical
//	expected_endpoint    → expected_endpoints    — path-scoped, deterministic
//
// CRITICAL: this handler REQUIRES decision != nil && decision.CacheKey != "".
// The redacted shape hash lives on decision.CacheKey; without it, we can't
// build a stable match key and we can't invalidate the stale reclass cache
// entry that would otherwise re-escalate the next matching response. Findings
// produced from cache-hit classifications don't carry a fresh decision row,
// so they get rejected with an operator-readable explanation pointing them
// to the right correction path.
func (s *Server) handleExpectedEndpointCorrection(w http.ResponseWriter, ctx context.Context,
	finding *store.Finding, decision *store.LLMDecision, reason string) {

	// FIX (code review, May 15 2026): The frontend sends the
	// Tier-1 decision ID because that's all it knows. But Card 4 needs the
	// Tier-2 reclassify decision (which has the redacted response-shape hash
	// in CacheKey). Look it up by EventID before hitting the guard.
	if decision == nil || decision.Tier != "reclassify" {
		reclassDecisions, err := s.store.ListLLMDecisions(ctx, store.LLMDecisionFilter{
			EventID: finding.EventID,
			Tier:    "reclassify",
			Limit:   1,
		})
		if err == nil && len(reclassDecisions) > 0 {
			decision = &reclassDecisions[0]
		}
	}

	// Build the shape hash from the best available source.
	//
	// Priority order:
	//   1. decision.CacheKey from a reclassify decision — this is the REDACTED
	//      response-shape hash (tokens → [REDACTED] before hashing). Stable
	//      across rotating JWT tokens. This is what makes Card 4 work.
	//   2. finding.EvidenceBodyHash — the RAW wire hash. Only useful as fallback
	//      when the response body didn't need redaction (no tokens/secrets).
	shapeHash := ""
	if decision != nil && decision.Tier == "reclassify" && isHexHash64(decision.CacheKey) {
		shapeHash = decision.CacheKey
	} else if isHexHash64(finding.EvidenceBodyHash) {
		shapeHash = finding.EvidenceBodyHash
	}

	// Evidence status: prefer evidence layer, fall back to finding
	evidenceStatus := 0
	if decision != nil && decision.EvidenceStatus > 0 {
		evidenceStatus = decision.EvidenceStatus
	} else if finding.EvidenceStatusCode > 0 {
		evidenceStatus = finding.EvidenceStatusCode
	} else if finding.HTTPStatus > 0 {
		evidenceStatus = finding.HTTPStatus
	}

	if shapeHash == "" || evidenceStatus == 0 {
		jsonError(w,
			"Expected endpoint corrections require captured response evidence with a redacted response-shape hash. This finding does not have the required evidence available.",
			http.StatusBadRequest)
		return
	}

	// Sanity check: rec.HashBody returns a 64-char lowercase hex SHA-256 digest.
	if !isHexHash64(shapeHash) {
		jsonError(w,
			"Expected endpoint correction has an invalid response-shape fingerprint (expected 64-character hex hash).",
			http.StatusBadRequest)
		return
	}

	// Build fingerprint from server-side data only — never trust frontend.
	host := finding.DestHost
	rawMethod := finding.HTTPMethod
	rawPath := finding.HTTPPath
	status := evidenceStatus

	// Normalize method/path to match the tracker's canonical key shape
	method, path := coordinator.NormalizeMethodPath(rawMethod, rawPath)

	// HARD GUARD: all five fingerprint components must be present.
	if host == "" || method == "" || path == "" || status == 0 {
		jsonError(w, "Cannot mark as expected endpoint: finding is missing required fingerprint fields (host/method/path/status)", http.StatusBadRequest)
		return
	}

	humanReason := "human: " + reason
	if reason == "" {
		humanReason = "human: endpoint expected to return sensitive-looking response by design"
	}

	// =========================================================================
	// Step 1: Delete the stale Tier-1 request pattern.
	//
	// design fix (May 15 2026): without this step, Card 4 leaves
	// a landmine. When the LLM originally classified the login event, it
	// learned an "auto" pattern keyed on the request's normalized hash with
	// bucket=malicious/alert. That pattern lives in the Tier-1 pattern store
	// and fires on every subsequent matching request, BEFORE the evidence
	// callback runs. Result: new logins instantly re-escalate via cache hit,
	// the ExpectedEndpoint tracker (which lives at the evidence layer) never
	// gets a turn, and the operator sees the same "MALICIOUS Cache Hit →
	// ESCALATED" bug that motivated Card 4 in the first place.
	//
	// Architectural principle (Drew lock-in): policy is identity, not
	// inference. Card 4 is the deterministic response-shape policy. The
	// stale auto-pattern is request-level inference. When operator-explicit
	// policy is set, the inference-level pattern must yield. Same logic
	// handleNoiseCorrection already applies — we just forgot it here.
	//
	// Distinction from failed_probe: failed probes ARE attacks; we keep
	// the malicious pattern so the Bouncer flags them, and let T2 downgrade
	// on the 4xx evidence. Expected endpoints are NOT attacks — keeping a
	// malicious tag on a legitimate API call is a lie to the DB.
	// =========================================================================
	correctionScope := finding.SourceType + ":" + finding.SourceName
	if decision != nil && decision.PatternLearned && decision.PatternValue != "" {
		bucket := decision.PatternBucket
		if bucket == "" {
			bucket = decision.Action
		}
		scope := decision.SourceScope
		if scope == "" {
			scope = correctionScope
		}
		if deleted := s.patterns.DeletePattern(scope, patternstore.Verdict(bucket), decision.PatternValue); deleted {
			log.Printf("[correction:expected_endpoint] Deleted LLM-learned stale pattern: scope=%s bucket=%s value=%.32s",
				scope, bucket, decision.PatternValue)
		}
	}
	if finding.MatchedPatternValue != "" && finding.MatchedPatternBucket != "" {
		scope := finding.MatchedPatternScope
		if scope == "" {
			scope = correctionScope
		}
		if deleted := s.patterns.DeletePattern(scope, patternstore.Verdict(finding.MatchedPatternBucket), finding.MatchedPatternValue); deleted {
			log.Printf("[correction:expected_endpoint] Deleted finding-matched stale pattern: scope=%s bucket=%s value=%.32s",
				scope, finding.MatchedPatternBucket, finding.MatchedPatternValue)
		}
	}
	if err := s.patterns.Persist(); err != nil {
		log.Printf("[correction:expected_endpoint] Warning: pattern store persist failed after delete: %v — stale pattern may return on Observer restart", err)
	}

	// Step 2: Persist expected endpoint (UPSERT on full key tuple — idempotent re-click).
	// Normalized fields go to DB so rows match runtime tracker keys 1:1.
	err := s.store.SaveExpectedEndpoint(ctx, &store.ExpectedEndpoint{
		Host:             host,
		HTTPMethod:       method,
		HTTPPath:         path,
		HTTPStatus:       status,
		BodyPreviewHash:  shapeHash,
		CreatedAt:        time.Now(),
		CreatedByEventID: finding.EventID,
		Description:      humanReason,
	})
	if err != nil {
		jsonError(w, "failed to save expected endpoint: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 3: Seed into live tracker (active immediately, no restart needed)
	if s.onSeedExpectedEndpoint != nil {
		s.onSeedExpectedEndpoint(host, method, status, path, shapeHash, humanReason)
	}

	// Step 4: Invalidate the reclass cache. The reclass cache is keyed on the
	// REDACTED shape hash (rec.HashBody(SafeBodyPreview), which is exactly
	// what we have in decision.CacheKey). Without this invalidation, a stale
	// "malicious" verdict could re-fire on the next matching request before
	// the new ExpectedEndpoint rule gets a turn. (code review answer:
	// the only cache key that matters is the redacted shape hash.)
	if s.onInvalidateReclassCache != nil {
		s.onInvalidateReclassCache(shapeHash)
	}

	// Step 5: Update finding verdict to "allow" — semantically distinct from
	// failed_probe's "recon". The request was LEGITIMATE (not a hostile probe
	// that happened to fail).
	if err := s.store.UpdateFindingVerdict(ctx, finding.EventID, "allow", humanReason); err != nil {
		log.Printf("[correction] Warning: finding update failed: %v", err)
	}

	// Step 6: Mark LLM decision as corrected (if we have one)
	if decision != nil {
		if err := s.store.UpdateLLMDecisionReview(ctx, decision.ID, store.LLMReview{
			Status:     "corrected",
			ReviewedBy: "dashboard",
			Verdict:    "allow",
			Reason:     humanReason,
		}); err != nil {
			log.Printf("[correction] Warning: decision review update failed: %v", err)
		}
	}

	log.Printf("[correction:expected_endpoint] host=%s method=%s path=%s status=%d shape_hash=%.16s event=%s",
		host, method, path, status, shapeHash, finding.EventID)

	jsonOK(w, map[string]string{"status": "ok", "type": "expected_endpoint"})
}

// handleConfirmCorrection — "The AI got it right"
// Marks the matched pattern as human-validated AND updates the LLM decision review.
func (s *Server) handleConfirmCorrection(w http.ResponseWriter, ctx context.Context,
	finding *store.Finding, decision *store.LLMDecision, sourceScope string) {

	// Mark the pattern as human-validated in the pattern store.
	// Check decision first (has the actual pattern info), fall back to finding.
	if decision != nil && decision.PatternLearned && decision.PatternValue != "" {
		bucket := decision.PatternBucket
		if bucket == "" {
			bucket = decision.Action
		}
		scope := decision.SourceScope
		if scope == "" {
			scope = sourceScope
		}
		s.patterns.MarkPatternValidated(scope, patternstore.Verdict(bucket), decision.PatternValue)
	} else if finding.MatchedPatternValue != "" && finding.MatchedPatternBucket != "" {
		scope := finding.MatchedPatternScope
		if scope == "" {
			scope = sourceScope
		}
		s.patterns.MarkPatternValidated(scope, patternstore.Verdict(finding.MatchedPatternBucket), finding.MatchedPatternValue)
	} else if finding.NormalizedHash != "" {
		s.patterns.MarkHumanValidated(sourceScope, finding.NormalizedHash)
	}

	if err := s.patterns.Persist(); err != nil {
		log.Printf("[correction] Warning: persist failed after confirm: %v", err)
	}

	// Update the LLM decision review status (fix #6: confirm was a no-op in SQLite)
	if decision != nil {
		if err := s.store.UpdateLLMDecisionReview(ctx, decision.ID, store.LLMReview{
			Status:     "confirmed",
			ReviewedBy: "dashboard",
		}); err != nil {
			log.Printf("[correction] Warning: decision review update failed: %v", err)
		}
	}

	log.Printf("[correction:confirm] scope=%s hash=%.16s event=%s decision=%d",
		sourceScope, finding.NormalizedHash, finding.EventID, func() int64 {
			if decision != nil {
				return decision.ID
			}
			return 0
		}())

	jsonOK(w, map[string]string{"status": "ok", "type": "confirm"})
}

// =============================================================================
// JSON Helpers
// =============================================================================

// maxRequestBody bounds JSON request bodies for control-plane endpoints.
// Corrections, pattern deletes, trusted-IP add/remove all fit easily under
// this limit. Prevents OOM from oversized request abuse.
const maxRequestBody = 64 * 1024 // 64 KB

// decodeJSON reads a bounded request body and decodes it into v with strict
// schema enforcement. Unknown fields are rejected — typos in client requests
// surface as errors instead of silently corrupting control-plane semantics.
//
// Returns true on success, or false after writing an error response.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		jsonError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// isHexHash64 returns true iff s is exactly 64 characters of lowercase or
// uppercase hex — the shape of a SHA-256 hex digest. Used as a sanity check
// in handleExpectedEndpointCorrection to catch non-hash values that slipped
// past the Tier filter.
//
// Intentionally tolerant of both cases because rec.HashBody currently emits
// lowercase via "%x", but if that ever changes to "%X" we don't want this
// check to start failing silently.
func isHexHash64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}