# Observer Development Session Summary

**Date:** March 24, 2026
**Previous Session:** March 23, 2026
**Purpose:** Fix evidence pipeline, implement design consensus on alert noise, design SQLite store.
**Releases this session:** v0.13.4, v0.13.5, v0.13.6, v0.13.7, v0.14, v0.14.1, v0.15, v0.15.1

---

## 1. The Journey (Timeline)

### v0.13.4 — Evidence Check Diagnostic Logging

**The problem:** Coordinator evidence check was failing 100% of the time overnight. Every investigation timed out and dispatched without evidence. Zero downgrades, zero reclassify cache hits.

**The fix:** Added diagnostic logging before the silent early return in `makeEvidenceCheckCallback()`. Two log points:
- `[coordinator] Evidence check SKIP:` — when `parseNormalizedLine` can't extract HTTP
- `[coordinator] Evidence check MISS:` — full diagnostic showing candidates, transport, preview_len, format, status

**Result:** Immediately revealed `candidates=0 status=not_available_no_match` — evidence was in the buffer but the lookup couldn't find it.

---

### v0.13.5 through v0.13.7 — Sniffer Stream Key Debugging

**The problem:** Evidence check showed zero candidates despite `buf_entries=1`. Needed to see WHY the sniffer wasn't pairing requests with responses.

**The fix:** Added stream key logging to `handleRequest()` and `handleResponse()` in `sniffer.go`:
- `[rec] REQ:` — srcIP:port→dstIP:port + method + path
- `[rec] RESP paired:` — when pairing succeeds
- `[rec] RESP pair miss:` — when pairing fails, shows reverse key + pending stream count

**Deployment issues:** Multiple attempts due to `sniffer.go` being saved to wrong path (root instead of `internal/rec/`), and a GitHub release uploading a stale binary. Used `scan.py` diagnostic to find `main.go` had been overwritten with `package rec` content.

**Result:** Stream key logs revealed the root cause:

```
REQ: REDACTED_KOVI_AWS_IP:59752→172.18.0.8:80 GET /checkhealth     ← incoming to nginx on port 80
RESP pair miss: 10.0.1.72:8080→10.0.1.19:50386 status=200  ← response from backend on port 8080
```

Requests arrive on port 443 (encrypted, invisible to sniffer). After nginx terminates TLS, it proxies to backend on port 8080 — but AF_PACKET in the namespace doesn't capture outgoing packets. So the sniffer sees the backend's RESPONSE but never saw the proxy REQUEST. Response stored with empty Method/Path → buffer lookup rejects it because `"" != "GET"`.

---

### v0.14 — Orphan Response Matching (THE EVIDENCE FIX)

**Root cause confirmed:** The sniffer captures backend responses perfectly (status, body, headers) but can't pair them with requests because:
1. Inbound request is on port 443 (TLS encrypted, invisible)
2. Outbound proxy request is an outgoing packet (AF_PACKET doesn't capture it in namespace mode)

**The fix:** Two changes:

**`buffer.go` — Allow orphan responses to match:**
```go
// Old: reject if Method doesn't match
if entry.Method != req.Method || entry.Path != req.Path {
    continue
}

// New: only check Method/Path if the entry has request info
if entry.Method != "" {
    if entry.Method != req.Method || entry.Path != req.Path {
        continue
    }
}
// Orphan responses fall through to StatusCode + timestamp matching
```

**`collector.go` — Honest capture mode reporting:**
```go
captureMode := "single_segment_preview"
if isOrphan {
    captureMode = "single_segment_preview_orphan"
}
```

**Result:** First-ever end-to-end evidence pipeline on production:
```
[DOWNGRADED] Original=malicious→recon_failed
Reason=Response body is the standard Laravel framework page (default/app template).
No DB records, stack traces, or sensitive data returned — the injection was not successful.
```

Second curl: `[reclassify] Cache hit` — instant downgrade, zero LLM cost.

---

### v0.15 — AI Committee Consensus (THE BIG RELEASE)

**Four AIs (the team, code review, /) independently converged on all three decisions.** This is rare and the signal is strong.

#### Decision 1: Seed List Purge (25 → 6 patterns)

**Committee verdict:** Option D — trim to "always malicious regardless of context."

**Removed (now handled by intelligent pipeline):**
- `/etc/shadow`, `/etc/passwd`, `.bash_history`, `authorized_keys`
- `UNION SELECT`, `DROP TABLE`
- `; ls -la`, `&& cat /etc`
- `phpinfo()`, `../../etc/passwd`, `curl ifconfig.me`, `wget -q -O-`
- `chmod 777`, `iptables -F`, `crontab -e`
- `reverse shell` (keyword), `python -c 'import socket`, `perl -e 'use Socket`

**Kept (conclusive on sight):**
- `bash -i >& /dev/tcp` — Bash reverse shell
- `nc -e /bin/sh` — Netcat reverse shell
- `base64 -d | bash` — Encoded execution
- `curl | sh` — Download and execute
- `wget | sh` — Download and execute
- `rm -rf /` — Destructive filesystem

**Rationale:** Seeds bypass LLM classification, evidence check, and coordinator downgrade. With 97%+ cache hit rates, seeds save one LLM call worth fractions of a penny but prevent the system from correctly suppressing failed probes.

#### Decision 2: LLM Prompt Noise Rules

Added 25-line APPLICATION NOISE RULES section to the Tier 1 classification prompt:

- Node.js stack frames (`at handleDocumentRequest...`) → noise/suppress
- Python tracebacks → noise/suppress
- Java/JVM exceptions → noise/suppress
- Go panics (without attacker input) → noise/suppress
- Route not found / missing handler → noise/suppress
- Health check failures, connection pool events → noise/suppress
- Explicit rule: "A stack trace ALONE is not an attack"
- Safety rule: stack traces WITH exploit evidence → let LLM classify normally

#### Decision 3: Deterministic Stack Trace Suppression

New `isOperationalNoise()` function in `analyzer.go`:
- Runs on raw line BEFORE pattern store or LLM
- Detects Node.js `at` frames, Python tracebacks, Go panic dumps, Java stack traces
- Zero LLM cost, zero ambiguity
- New `NoiseSuppressed` counter in pipeline stats

**Pattern store wiped** — old cache had Remix stack traces marked as "alert" and `.env` probes as "deny" from seeds. Fresh start with new intelligence.

---

### v0.15.1 — Deterministic Failed Probe Suppression

**The problem:** After v0.15 deployed, the LLM correctly suppressed most 404 probes as `recon_failed` but occasionally still classified clean 404s as "alert." Example: `gifclass.php 404` → SUSPICIOUS, while `adminer-3.3.4-cs.php 404` → suppress. One bad LLM call, cached forever, 70 alert patterns.

**The fix:** New `isFailedProbe()` function in `analyzer.go`:
1. Extracts HTTP status code from normalized line (handles all three formats)
2. If status is 400/403/404/405/410 → candidate for suppression
3. Checks for attack indicators in the request (SQL keywords, traversal, encoding, XSS, command injection, PHP wrappers — 20+ patterns)
4. If attack indicators found → let LLM decide (payload matters regardless of status)
5. If clean path + failed status → `VerdictSuppress` immediately

**401 deliberately excluded** (code review's catch): A 401 means "this endpoint exists and requires auth" — that's surface discovery, not pure nothing. `/admin` returning 401 is a meaningful finding.

**Attack indicators list:**
```
SQL: UNION, SELECT, DROP, INSERT, UPDATE, DELETE
Traversal: ../, ..\\
Encoding: %00, %0a, %0d, %27, %22
XSS: <script, javascript:
Command injection: ;ls, ;cat, ;rm, ;wget, ;curl, |, `, $(, ${
PHP wrappers: php://, data://, file://
Code execution: eval(, exec(, system(
```

**Pattern store wiped again** — 70 cached alert verdicts for 404 probes were poison.

---

## 2. Production Stats

### After v0.15 (2 hour soak):
```
processed=2077  pattern_hits=2033  llm_calls=44  learned=41
Patterns: hash=430 prefix=1094 regex=500 contains=9
deny=18  alert=70  suppress=910  misses=44
```

- 97.9% cache hit rate
- 910 suppress patterns learned automatically
- 44 LLM calls total — system learning fast
- LLM correctly classifying 404 probes as recon_failed ~90% of time
- 70 alert patterns from occasional LLM inconsistency on 404s → fixed by v0.15.1

### After v0.15.1:
- Fresh pattern store, re-learning overnight with deterministic 404 suppression
- Evidence pipeline confirmed working: UNION SELECT → evidence → downgrade → cache hit

---

## 3. Release History

| Version | Changes |
|---------|---------|
| v0.13.4 | Debug: diagnostic logging in coordinator evidence check |
| v0.13.5 | Debug: sniffer stream key logging (build issues) |
| v0.13.6 | Debug: sniffer stream key logging (stale binary on GitHub) |
| v0.13.7 | Debug: confirmed sniffer stream key logging deployed |
| v0.14 | Fix: orphan response matching — evidence pipeline unblocked |
| v0.14.1 | Fix: buffer.go included (missed in v0.14 deploy) |
| v0.15 | Committee consensus: seed purge (25→6), LLM prompt noise rules, deterministic stack trace suppression |
| v0.15.1 | Deterministic 404/403/405 suppression, 401 excluded (surface discovery) |

---

## 4. Files Changed This Session

| File | Version | Change |
|------|---------|--------|
| `main.go` | v0.13.4 | Evidence check diagnostic logging, noise_suppressed in stats |
| `internal/rec/sniffer.go` | v0.13.5 | Stream key debug logging in handleRequest/handleResponse |
| `internal/rec/buffer.go` | v0.14 | Orphan response matching (skip Method/Path check when empty) |
| `internal/rec/collector.go` | v0.14 | Orphan capture mode reporting (single_segment_preview_orphan) |
| `seeds.go` | v0.15 | Seed purge: 25 → 6 patterns (always-malicious only) |
| `internal/llm/client.go` | v0.15 | 25-line APPLICATION NOISE RULES in classification prompt |
| `internal/analyzer/analyzer.go` | v0.15, v0.15.1 | isOperationalNoise() stack trace filter, isFailedProbe() 404 filter, NoiseSuppressed counter, attack indicators list |

---

## 5. Evidence Pipeline — How It Works Now (Proven on Production)

```
Log line arrives
  ↓ Step 1: Normalize
  ↓ Step 1.5: isOperationalNoise? → suppress (stack traces)
  ↓ Step 1.6: isFailedProbe? → suppress (clean 404/403/405)
  ↓ Step 2: Pattern store check (hash/prefix/regex/contains)
  ↓ Step 3: LLM classification (intent × outcome)
  ↓ Step 4: Learn pattern from LLM response
  ↓
  VerdictDeny or VerdictAlert + HTTP + REC enabled?
  ↓ YES
  Coordinator creates investigation
    ↓ Sibling containers join huddle (nginx + backend = 1 finding)
    ↓ Evidence check every 500ms for 5 seconds:
    ↓   Ring buffer lookup (orphan matching for namespace capture)
    ↓   Structural redaction (HTML/JSON/dotenv/passwd)
    ↓   Dual-gate: correlation high + redaction high?
    ↓   Re-classification cache check (redacted body hash)
    ↓   LLM re-classification with evidence if cache miss
    ↓
    Evidence says attack failed? → [DOWNGRADED] → no email
    Evidence says attack succeeded? → [ALERT] → email (future: Tier 3)
    No evidence? → dispatch with honest language
```

---

## 6. AI Committee Briefing Document

Created `observer-design team-briefing-2026-03-24.md` covering three connected decisions:

1. **Seed list reform** — 5 options (A through E), design team chose D
2. **Application noise handling** — 4 options (A through D), design team chose D
3. **Three-tier LLM verification** — design for "3am email" gate (future)

All four AIs (the team, code review, , ) converged on:
- Seeds: Option D (trim to always-malicious)
- Noise: Option D (deterministic tags + prompt improvement)
- Tier 3: Yes, fail-open, same model with richer prompt, narrow gate

Additional design team insight: **Outcome clustering** — same source IP + same response body hash + short window = one finding, not 50 emails. Identified as highest-priority next feature after inbox relief.

---

## 7. SQLite Store Design (Agreed, Not Yet Built)

### Architecture Decision
- **Journald** stays for operational telemetry (startup, debug, sniffer, coordinator traces)
- **SQLite** for security findings (alerts, suppressions, downgrades, evidence, scanner sessions)
- Package-level singleton pattern: `store.RecordFinding(ctx, f)` callable from anywhere
- `*Store` struct wrapping `*sql.DB` (not raw global)
- WAL mode, context.Context on all methods, schema migrations in Init()

### Schema (Agreed)

**findings** — every classification decision:
- Event identity: event_id, timestamp, source_type, source_name
- Request details: source_ip, dest_host, http_method, http_path, http_status, response_size, user_agent
- Raw data: raw_line, normalized_line, normalized_hash
- Classification: verdict, classification, confidence, reason, matched_via, tier
- Evidence: evidence_status, evidence_status_code, evidence_content_type, evidence_body_hash, evidence_preview, evidence_capture_mode
- Re-classification: reclass_result, reclass_reason, tier3_summary
- Coordinator: coordinator_key, coordinator_events, downgraded, dispatched
- Metadata: created_at

**scanner_sessions** — outcome clustering:
- source_ip, target_app, body_hash, first_seen, last_seen, probe_count, sample_paths, verdict, notified

**pipeline_stats** — time-series for dashboards:
- timestamp + all pipeline/pattern/REC counters

### Package Structure
```
internal/store/
├── store.go        ← Store struct, Init(), Close(), migrations, pragmas
├── types.go        ← Finding, ScannerSession, PipelineStats structs
├── findings.go     ← RecordFinding(), QueryByIP(), QueryByVerdict(), QueryRecent()
├── scanner.go      ← RecordScannerProbe(), GetOrCreateSession(), QuerySessions()
├── stats.go        ← RecordStats(), QueryStats()
└── pruner.go       ← Background goroutine, TTL-based cleanup
```

### Implementation Notes
- Pure Go SQLite (`modernc.org/sqlite`) — no CGO, maintains single-binary philosophy
- Write buffering: allows/suppresses batch every 1-2s, alerts/denies write immediately
- Pruning: allow rows after 7 days, suppress/downgrade after 90 days, alerts/intrusions never auto-pruned
- Indexes: source_ip, timestamp, verdict, normalized_hash, scanner source_ip

---

## 8. Key Discoveries

1. **Namespace capture sees responses but not requests** — TLS terminates at nginx (port 443 encrypted), proxy request is outgoing (AF_PACKET misses it). Orphan response matching solves this.
2. **Orphan matching is safe** — on low-traffic servers, one response in the 5-second window is unambiguous. Multiple candidates → low confidence → dual-gate blocks body preview.
3. **Seeds cause more harm than good at 97% cache hit rates** — they bypass the intelligent pipeline for fractions of a penny savings.
4. **LLM is 90% right on 404s but 10% wrong is enough to poison the cache** — deterministic override for structural facts.
5. **401 is not a failed probe** — it's surface discovery. Committee agreed to exclude from blanket suppression.
6. **Four AIs converging on the same answer is a strong signal** — happened on all three design team decisions.

---

## 9. Deployment Cheat Sheet

### Build and Release (WSL)
```bash
cd ~/vaultguardian-logwatch
GOOS=linux GOARCH=amd64 go build -o observer .
git add .
git commit -m "description"
git push
gh release create vX.X ./observer --title "Observer vX.X" --notes "description"
```

### Deploy to Server
```bash
rm -f observer
gh release download vX.X --repo VaultGuardian/logwatch --pattern "observer"
sudo mv observer /usr/local/bin/observer
sudo chmod +x /usr/local/bin/observer
sudo rm /var/lib/observer/patternstore.json    # only if classification logic changed
sudo systemctl restart observer
sudo journalctl -u observer -f
```

### Environment Variables (Production)
```
DOCKER_SOCKET=/var/run/docker.sock
DATA_DIR=/var/lib/observer
LLM_URL=https://api.openai.com
LLM_MODEL=gpt-5-mini-2025-08-07
LLM_API_KEY=sk-...
EXCLUDE_CONTAINERS=
RESEND_API_KEY=re_...
ALERT_EMAIL_TO=drew@vaultdec.com
REC_ENABLED=true
REC_NS_CONTAINER=captain-nginx
```

---

## 10. Next Session Priority

1. **Check overnight soak results** — compare email count to previous nights. `noise_suppressed` should be climbing.
2. **Build `internal/store/` SQLite package** — schema, Init(), RecordFinding(), basic queries
3. **Wire store into pipeline** — coordinator dispatch callback writes findings, periodic stats writes pipeline_stats
4. **Outcome clustering** — scanner_sessions table, collapse same-IP + same-body-hash into one finding
5. **Tier 3 forensic narrative** — confirmation call before "confirmed intrusion" emails
6. **Remove debug logging** — stream key logs in sniffer, evidence check diagnostics in coordinator (once stable)

---

## 11. Architecture Principles (Updated)

- **Deterministic over opinion:** If a fact is structurally certain (404 + no payload = failed probe), don't let the LLM vote on it.
- **Physics, not probability:** Stack traces, failed HTTP status codes, and framework errors are structural truths. Classify them with code, not AI.
- **Seeds are for game-overs only:** Reverse shells and destructive commands. Everything else goes through the intelligent pipeline.
- **Evidence changes conclusions:** 200 without body = ambiguous. 200 with Laravel welcome page = attack ignored.
- **Cache the right answer:** One bad LLM call cached forever = 70 emails. Deterministic filters prevent bad answers from entering the cache.
- **Journald for ops, SQLite for findings:** Different questions deserve different storage. Debug traces and security findings don't belong in the same firehose.
- **401 is not 404:** Surface discovery (endpoint exists + requires auth) is a finding. Failed probe (resource doesn't exist) is noise.
