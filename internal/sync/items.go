package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// [A5] Hosted text caps
// =============================================================================
//
// These MUST stay identical to the hosted ingest's caps. Truncating locally
// with the same rule and the same marker means the stored hosted value is
// byte-identical whether Observer or the ingest did the cutting, and it makes
// a single item structurally unable to exceed ~100KB - which is what lets the
// byte budget below be a real guarantee rather than a hope.
//
// The rule is idempotent by construction: re-applying it to an already-capped
// string reproduces the same result, so a double truncation (ours then the
// ingest's, because cap+marker still exceeds cap) converges instead of
// compounding.
const (
	capRawLine         = 8192
	capNormalizedLine  = 8192
	capEvidencePreview = 16384
	capLLMResponseRaw  = 32768
	capReason          = 4096
	capDefaultString   = 2048

	truncationMarker = "\n...[truncated by ingest]"
)

// =============================================================================
// [A5] Batch budget
// =============================================================================
const (
	// maxBatchItems is the hosted batch size contract.
	maxBatchItems = 200

	// maxBatchBytes caps the encoded JSON body of one POST. Well under any
	// reasonable body limit, and reached only by pathological rows.
	maxBatchBytes = 3_000_000

	// scanWindow is how many rows one cursor or journal pass reads.
	scanWindow = 200
)

// truncateField applies one hosted cap.
func truncateField(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	// Back off to a rune boundary: a split multi-byte character would be
	// re-encoded as U+FFFD by the JSON encoder, changing bytes the hosted
	// side would not have changed.
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + truncationMarker
}

// truncateFinding returns a copy with every text field capped to the hosted
// limits. The caller's row is never mutated.
func truncateFinding(f store.Finding) store.Finding {
	f.RawLine = truncateField(f.RawLine, capRawLine)
	f.NormalizedLine = truncateField(f.NormalizedLine, capNormalizedLine)
	f.Reason = truncateField(f.Reason, capReason)

	f.EventID = truncateField(f.EventID, capDefaultString)
	f.SourceType = truncateField(f.SourceType, capDefaultString)
	f.SourceName = truncateField(f.SourceName, capDefaultString)
	f.SourceIP = truncateField(f.SourceIP, capDefaultString)
	f.DestHost = truncateField(f.DestHost, capDefaultString)
	f.HTTPMethod = truncateField(f.HTTPMethod, capDefaultString)
	f.HTTPPath = truncateField(f.HTTPPath, capDefaultString)
	f.UserAgent = truncateField(f.UserAgent, capDefaultString)
	f.Verdict = truncateField(f.Verdict, capDefaultString)
	f.Classification = truncateField(f.Classification, capDefaultString)
	f.MatchedVia = truncateField(f.MatchedVia, capDefaultString)
	f.MatchedPatternScope = truncateField(f.MatchedPatternScope, capDefaultString)
	f.MatchedPatternBucket = truncateField(f.MatchedPatternBucket, capDefaultString)
	f.MatchedPatternValue = truncateField(f.MatchedPatternValue, capDefaultString)
	f.OriginEventID = truncateField(f.OriginEventID, capDefaultString)
	f.NormalizedHash = truncateField(f.NormalizedHash, capDefaultString)
	f.EvidenceStatus = truncateField(f.EvidenceStatus, capDefaultString)
	f.EvidenceContentType = truncateField(f.EvidenceContentType, capDefaultString)
	f.EvidenceBodyHash = truncateField(f.EvidenceBodyHash, capDefaultString)
	f.EvidenceCaptureMode = truncateField(f.EvidenceCaptureMode, capDefaultString)
	f.CoordinatorKey = truncateField(f.CoordinatorKey, capDefaultString)
	f.DowngradeReason = truncateField(f.DowngradeReason, capDefaultString)
	f.ResolutionStatus = truncateField(f.ResolutionStatus, capDefaultString)
	f.ResolutionMethod = truncateField(f.ResolutionMethod, capDefaultString)
	f.PreviousVerdict = truncateField(f.PreviousVerdict, capDefaultString)
	return f
}

// truncateDecision returns a copy with every text field capped.
func truncateDecision(d store.LLMDecision) store.LLMDecision {
	d.RawLine = truncateField(d.RawLine, capRawLine)
	d.NormalizedLine = truncateField(d.NormalizedLine, capNormalizedLine)
	d.EvidencePreview = truncateField(d.EvidencePreview, capEvidencePreview)
	d.LLMResponseRaw = truncateField(d.LLMResponseRaw, capLLMResponseRaw)
	d.Reason = truncateField(d.Reason, capReason)

	d.EventID = truncateField(d.EventID, capDefaultString)
	d.Tier = truncateField(d.Tier, capDefaultString)
	d.Model = truncateField(d.Model, capDefaultString)
	d.ReasoningEffort = truncateField(d.ReasoningEffort, capDefaultString)
	d.SourceScope = truncateField(d.SourceScope, capDefaultString)
	d.NormalizedHash = truncateField(d.NormalizedHash, capDefaultString)
	d.EvidenceType = truncateField(d.EvidenceType, capDefaultString)
	d.EvidenceHash = truncateField(d.EvidenceHash, capDefaultString)
	d.Classification = truncateField(d.Classification, capDefaultString)
	d.Action = truncateField(d.Action, capDefaultString)
	d.PatternType = truncateField(d.PatternType, capDefaultString)
	d.PatternValue = truncateField(d.PatternValue, capDefaultString)
	d.SourceHint = truncateField(d.SourceHint, capDefaultString)
	d.PatternBucket = truncateField(d.PatternBucket, capDefaultString)
	d.CacheKey = truncateField(d.CacheKey, capDefaultString)
	d.FinalVerdict = truncateField(d.FinalVerdict, capDefaultString)
	d.FindingID = truncateField(d.FindingID, capDefaultString)
	d.PromptVersion = truncateField(d.PromptVersion, capDefaultString)
	d.CodeVersion = truncateField(d.CodeVersion, capDefaultString)
	d.ReviewStatus = truncateField(d.ReviewStatus, capDefaultString)
	d.ReviewedBy = truncateField(d.ReviewedBy, capDefaultString)
	d.ReviewedAt = truncateField(d.ReviewedAt, capDefaultString)
	d.ReviewerVerdict = truncateField(d.ReviewerVerdict, capDefaultString)
	d.ReviewerReason = truncateField(d.ReviewerReason, capDefaultString)
	d.ReplacementPattern = truncateField(d.ReplacementPattern, capDefaultString)
	return d
}

// =============================================================================
// [A3] Pre-validation
// =============================================================================
//
// The hosted ingest hard-rejects malformed items by SKIPPING them, and a
// skipped item makes the whole ack fail validation - which would wedge the
// stream on a row that can never succeed. So we apply the same rules locally,
// log the row once, and let the cursor move past it. A permanently unsendable
// row must not become a permanent outage.

// validateFinding returns a non-empty reason when the hosted ingest would
// reject this finding.
func validateFinding(f *store.Finding) string {
	if strings.TrimSpace(f.EventID) == "" {
		return "empty event_id"
	}
	if !parsableTimestamp(f.Timestamp) {
		return "unparseable timestamp"
	}
	if strings.TrimSpace(f.Verdict) == "" {
		return "empty verdict"
	}
	if strings.TrimSpace(f.Classification) == "" {
		return "empty classification"
	}
	return ""
}

// validateDecision returns a non-empty reason when the hosted ingest would
// reject this decision.
func validateDecision(d *store.LLMDecision) string {
	if d.ID <= 0 {
		return "non-positive id"
	}
	if strings.TrimSpace(d.EventID) == "" {
		return "empty event_id"
	}
	if !parsableTimestamp(d.Timestamp) {
		return "unparseable timestamp"
	}
	if strings.TrimSpace(d.Tier) == "" {
		return "empty tier"
	}
	return ""
}

// parsableTimestamp mirrors the hosted "parseable timestamp" rule against the
// exact bytes we put on the wire. Marshaling a time.Time always yields RFC3339
// today; this guards the day that stops being true.
func parsableTimestamp(t time.Time) bool {
	encoded, err := t.MarshalJSON()
	if err != nil {
		return false
	}
	var parsed time.Time
	return parsed.UnmarshalJSON(encoded) == nil
}

// =============================================================================
// Batching
// =============================================================================

// preparedItem is one validated, truncated, marshaled row plus the cursor
// position it represents.
type preparedItem struct {
	rowid   int64
	encoded []byte
}

// prepareFindings validates, truncates and marshals a scan window.
// Rows the hosted ingest would reject are logged once and dropped; the caller
// still advances the cursor past them.
func prepareFindings(rows []store.SyncFinding) []preparedItem {
	items := make([]preparedItem, 0, len(rows))
	for _, row := range rows {
		if reason := validateFinding(&row.F); reason != "" {
			log.Printf("[sync] skipping unsendable row: rowid=%d table=findings reason=%s event_id=%q",
				row.Rowid, reason, row.F.EventID)
			continue
		}
		encoded, err := json.Marshal(truncateFinding(row.F))
		if err != nil {
			log.Printf("[sync] skipping unsendable row: rowid=%d table=findings reason=marshal: %v",
				row.Rowid, err)
			continue
		}
		items = append(items, preparedItem{rowid: row.Rowid, encoded: encoded})
	}
	return items
}

// prepareDecisions is the decisions counterpart. A decision's rowid IS its id.
func prepareDecisions(rows []store.LLMDecision) []preparedItem {
	items := make([]preparedItem, 0, len(rows))
	for _, d := range rows {
		if reason := validateDecision(&d); reason != "" {
			log.Printf("[sync] skipping unsendable row: rowid=%d table=llm_decisions reason=%s event_id=%q",
				d.ID, reason, d.EventID)
			continue
		}
		encoded, err := json.Marshal(truncateDecision(d))
		if err != nil {
			log.Printf("[sync] skipping unsendable row: rowid=%d table=llm_decisions reason=marshal: %v",
				d.ID, err)
			continue
		}
		items = append(items, preparedItem{rowid: d.ID, encoded: encoded})
	}
	return items
}

// splitBatches groups prepared items into POST-sized chunks: at most
// maxBatchItems each, and at most maxBatchBytes of encoded JSON body.
//
// A single item larger than the budget still gets its own batch - dropping it
// would be a silent gap, and pre-truncation already bounds how large that can
// be (~100KB), so it stays comfortably sendable.
func splitBatches(key string, items []preparedItem) [][]preparedItem {
	if len(items) == 0 {
		return nil
	}
	overhead := len(envelopePrefix(key)) + len(envelopeSuffix)

	var batches [][]preparedItem
	var current []preparedItem
	size := overhead

	for _, item := range items {
		// +1 for the separating comma (only needed after the first item).
		cost := len(item.encoded)
		if len(current) > 0 {
			cost++
		}
		if len(current) > 0 && (len(current) >= maxBatchItems || size+cost > maxBatchBytes) {
			batches = append(batches, current)
			current = nil
			size = overhead
			cost = len(item.encoded)
		}
		current = append(current, item)
		size += cost
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

func envelopePrefix(key string) string { return `{"` + key + `":[` }

const envelopeSuffix = `]}`

// encodeBatch renders {"<key>":[item, item, ...]} without re-marshaling the
// already-encoded items.
func encodeBatch(key string, items []preparedItem) []byte {
	var buf bytes.Buffer
	buf.WriteString(envelopePrefix(key))
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item.encoded)
	}
	buf.WriteString(envelopeSuffix)
	return buf.Bytes()
}

// maxRowid returns the highest cursor position in a batch. Items are always
// in ascending rowid order, but this does not rely on that.
func maxRowid(items []preparedItem) int64 {
	var max int64
	for _, item := range items {
		if item.rowid > max {
			max = item.rowid
		}
	}
	return max
}

// =============================================================================
// Transport + [A3] ack validation
// =============================================================================

// ingestAck is the hosted batch-route response contract.
type ingestAck struct {
	OK       bool `json:"ok"`
	Upserted int  `json:"upserted"`
	Skipped  int  `json:"skipped"`
}

// postBatch sends one batch and validates the acknowledgement.
//
// [A3] A POST only counts as success when the hosted mirror confirms it stored
// exactly what we sent: 2xx, ok:true, skipped == 0, upserted == len(items).
// A 2xx with skipped > 0 is NOT success - after local pre-validation it means
// Observer and the hosted contract have drifted, and silently advancing the
// cursor past those rows would lose them forever. Cursors and journal rows
// never move on an unvalidated 2xx.
func (e *Engine) postBatch(ctx context.Context, path, key string, items []preparedItem) error {
	body := encodeBatch(key, items)
	status, respBody, err := e.postIngest(ctx, path, body)
	if err != nil {
		return fmt.Errorf("%s rowids %d-%d: %w", path, items[0].rowid, maxRowid(items), err)
	}

	if status < 200 || status > 299 {
		return fmt.Errorf("%s rowids %d-%d: HTTP %d: %s",
			path, items[0].rowid, maxRowid(items), status, snippet(respBody))
	}

	var ack ingestAck
	if err := json.Unmarshal(respBody, &ack); err != nil {
		return fmt.Errorf("%s rowids %d-%d: unparseable ack (%s): %w",
			path, items[0].rowid, maxRowid(items), snippet(respBody), err)
	}
	if !ack.OK || ack.Skipped != 0 || ack.Upserted != len(items) {
		return fmt.Errorf("%s rowids %d-%d: ack rejected (sent=%d ok=%t upserted=%d skipped=%d) - "+
			"hosted contract drift, not advancing",
			path, items[0].rowid, maxRowid(items), len(items), ack.OK, ack.Upserted, ack.Skipped)
	}
	return nil
}

// postIngest performs one authenticated POST to the hosted ingest.
func (e *Engine) postIngest(ctx context.Context, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.cfg.Token)

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Bounded read: an ack is tiny, and a misconfigured URL could return a
	// very large page.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// snippet renders a response body for a log line without flooding it.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
