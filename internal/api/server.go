package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
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
}

// Server is the dashboard API server.
type Server struct {
	config   ServerConfig
	token    string
	store    *store.Store
	patterns *patternstore.Store
	analyzer *analyzer.Analyzer
	collector rec.EvidenceCollector

	// Human correction callbacks — narrow interfaces to avoid coupling
	// the API package to coordinator/reclassCache internals.
	// Set via SetCorrectionCallbacks() after construction.
	onInvalidateReclassCache func(bodyHash string)
	onSeedCatchAll           func(host, method string, status int, bodyHash, reason string)
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

	return &Server{
		config:    cfg,
		token:     token,
		store:     db,
		patterns:  patterns,
		analyzer:  a,
		collector: collector,
	}, nil
}

// SetCorrectionCallbacks wires the human correction system to the coordinator
// and reclass cache. Called from main.go after both are initialized.
func (s *Server) SetCorrectionCallbacks(
	invalidateCache func(bodyHash string),
	seedCatchAll func(host, method string, status int, bodyHash, reason string),
) {
	s.onInvalidateReclassCache = invalidateCache
	s.onSeedCatchAll = seedCatchAll
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

	addr := fmt.Sprintf(":%d", s.config.Port)
	log.Printf("[api] Dashboard API listening on %s (key file: %s)", addr, s.config.KeyFile)
	return http.ListenAndServe(addr, s.corsMiddleware(mux))
}

// corsMiddleware handles CORS preflight and adds headers to all responses.
// Required because the dashboard app runs on a different origin (e.g.
// localhost:3000 or app.vaultguardian.io) and makes authenticated fetch calls.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Preflight — return immediately, don't hit auth
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Auth Middleware
// =============================================================================

// requireAuth wraps a handler with bearer token verification.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Also check query param for easy browser/curl testing
			auth = "Bearer " + r.URL.Query().Get("token")
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, "Missing Authorization: Bearer <token> header", http.StatusUnauthorized)
			return
		}

		provided := strings.TrimPrefix(auth, "Bearer ")
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
		"version": "0.22",
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
	limitStr := r.URL.Query().Get("limit")

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	ctx := r.Context()
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

	if s.collector.Enabled() {
		rStats := s.collector.Stats()
		result["rec"] = map[string]interface{}{
			"packets":            rStats.PacketsSeen,
			"http_requests":      rStats.HTTPRequests,
			"http_responses":     rStats.HTTPResponses,
			"pair_misses":        rStats.PairMisses,
			"pair_immediate":     rStats.PairImmediate,
			"orphan_responses":   rStats.OrphanResponses,
			"requests_expired":   rStats.RequestsExpired,
			"inline_requests":    rStats.InlineRequests,
			"inline_seq_dedup":   rStats.InlineDuplicateDrops,
			"inline_body_skip":   rStats.InlineBodySkips,
			"vxlan_unwrapped":    rStats.VXLANUnwrapped,
			"buffer_entries":     rStats.BufferEntries,
			"buffer_bytes":       rStats.BufferBytes,
			"reassembly_active":  rStats.ReassemblyStreamsActive,
			"reassembly_total":   rStats.ReassemblyStreamsTotal,
			"reassembly_timeout": rStats.ReassemblyStreamsTimedOut,
			"reassembly_drops":   rStats.ReassemblyStreamDrops,
			"reassembly_errors":  rStats.ReassemblyParseErrors,
			"flow_states":        rStats.FlowStates,
			"flow_evictions":     rStats.FlowEvictions,
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
			"scope":    scopeKey,
			"allow":    s.patterns.ListPatterns(scopeKey, patternstore.VerdictAllow),
			"malicious":     s.patterns.ListPatterns(scopeKey, patternstore.VerdictMalicious),
			"alert":    s.patterns.ListPatterns(scopeKey, patternstore.VerdictAlert),
			"suppress": s.patterns.ListPatterns(scopeKey, patternstore.VerdictSuppress),
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Scope == "" || req.Verdict == "" || req.Value == "" {
		jsonError(w, "Missing required fields: scope, verdict, value", http.StatusBadRequest)
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
			filter.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
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
		ID     int64            `json:"id"`
		Review store.LLMReview  `json:"review"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ID == 0 {
		jsonError(w, "id is required", http.StatusBadRequest)
		return
	}
	if req.Review.Status == "" {
		jsonError(w, "review.status is required (confirmed, corrected, ignored)", http.StatusBadRequest)
		return
	}

	// Delete-only correction is disabled — use /api/corrections instead.
	// The old path deleted patterns without creating replacements, leaving
	// the line to go back to the LLM naked. That's a half-feature that can
	// reintroduce the same bad classification. (code review final review.)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.IP == "" && req.CIDR == "" {
		jsonError(w, "Either 'ip' or 'cidr' is required", http.StatusBadRequest)
		return
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
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
//   code review caught this: suppressing "UNION SELECT" because it returned a
//   harmless page today would globally whitelist SQL injection forever.
//   (design consensus, April 28 2026.)

func (s *Server) handleCorrection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type          string `json:"type"`           // "noise", "failed_probe", or "confirm"
		EventID       string `json:"event_id"`       // finding lookup key
		DecisionID    int64  `json:"decision_id"`    // LLM decision lookup key (0 = cache hit, no decision)
		TargetVerdict string `json:"target_verdict"` // for noise: "suppress" or "allow"
		Reason        string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.EventID == "" {
		jsonError(w, "event_id is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Look up the finding server-side — never trust frontend-supplied data
	// for a security control plane. (code review catch.)
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
	case "confirm":
		s.handleConfirmCorrection(w, ctx, finding, decision, sourceScope)
	default:
		jsonError(w, "invalid correction type: must be 'noise', 'failed_probe', or 'confirm'", http.StatusBadRequest)
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
	// on priority (malicious > suppress). (code review catch #2.)
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
		Type:         patternstore.PatternHash,
		Value:        hash,
		Source:       "human",
		Reason:       humanReason,
		OriginalLine: line,
		CreatedAt:    time.Now(),
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
	// (the design review + code review guardrail.)
	if host == "" || method == "" || status == 0 || bodyHash == "" {
		jsonError(w, "Cannot mark as failed probe: no response evidence available for this event", http.StatusBadRequest)
		return
	}

	humanReason := "human: " + reason
	if reason == "" {
		humanReason = "human: marked as failed probe (no observable impact)"
	}

	// Step 1: Save to catchall_verified_v2 (persistent)
	err := s.store.SaveVerifiedCatchAll(ctx, &store.CatchAllRule{
		Host:                host,
		HTTPMethod:          method,
		HTTPStatus:          status,
		BodyPreviewHash:     bodyHash,
		VerifiedAt:          time.Now(),
		ContentType:         contentType,
		VerificationVerdict: "benign",
		VerificationReason:  humanReason,
	})
	if err != nil {
		jsonError(w, "failed to save catch-all rule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 2: Seed into live coordinator (active immediately, no restart)
	if s.onSeedCatchAll != nil {
		s.onSeedCatchAll(host, method, status, bodyHash, humanReason)
	}

	// Step 3: Invalidate reclass cache.
	// The reclass cache is keyed on the REDACTED body hash (decision.CacheKey),
	// NOT the raw BodyPreviewHash. Invalidate BOTH to be safe. (code review catch #3.)
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
		sourceScope, finding.NormalizedHash, finding.EventID, func() int64 { if decision != nil { return decision.ID }; return 0 }())

	jsonOK(w, map[string]string{"status": "ok", "type": "confirm"})
}

// =============================================================================
// JSON Helpers
// =============================================================================

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}