# Observer Development Session Summary

**Date:** March 24, 2026
**Previous Session:** March 23, 2026
**Purpose:** Fix evidence pipeline, implement design consensus on alert noise, design SQLite store. Late session: deep research on 404 suppression safety, live attack analysis, evidence timing diagnosis.
**Releases this session:** v0.13.4, v0.13.5, v0.13.6, v0.13.7, v0.14, v0.14.1, v0.15, v0.15.1, v0.15.2

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

---

### v0.15.2 — Stack Trace Detection Bug Fix + Module Rename

**Bug found in production:** Remix stack traces were still firing as `[ALERT]` despite the noise filter. `noise_suppressed=13` showed the filter was catching some things, but hash `d01711...` (`at handleDocumentRequest...`) was hitting a cached alert verdict.

**Root cause:** `TrimSpace` was running BEFORE the Node.js indentation check, eating the leading whitespace that IS the stack trace signal:

```go
// BUG: TrimSpace eats the indentation
trimmed = strings.TrimSpace(trimmed)
// Now trimmed = "at handleDocumentRequest..." — no leading space
if trimmed[0] == ' ' { // FALSE — TrimSpace already removed it
```

**The fix:** Node.js stack frame check now runs BEFORE TrimSpace:

```go
// Check BEFORE TrimSpace — leading whitespace IS the signal
if len(trimmed) > 4 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
    inner := strings.TrimLeft(trimmed, " \t")
    if strings.HasPrefix(inner, "at ") {
        return true
    }
}
// NOW TrimSpace for remaining checks
trimmed = strings.TrimSpace(trimmed)
```

**Module rename:** `go.mod` and all imports changed from `github.com/vaultguardian/logwatch` to `github.com/vaultguardian/observer`. GitHub repo already renamed via Settings. 7 files updated, 17 import references changed.

**Production result after v0.15.2:**
```
processed=1840  noise_suppressed=1126  llm_calls=0  alert=0  deny=0
```

**1,126 lines suppressed deterministically.** Zero LLM calls. Zero alerts. Zero emails. Compare to previous night: 50+ PHP scanner emails, 25+ Remix stack trace alert emails.

---

## 2. Production Stats Comparison

### Before (v0.13, overnight March 23-24):
- 50+ PHP scanner alert emails
- 25+ Remix stack trace alert emails
- 70 cached alert patterns from bad LLM calls on 404s
- Evidence pipeline broken (100% evidence check failures)

### After (v0.15.2, first hour):
```
processed=1840  pattern_hits=714  noise_suppressed=1126  llm_calls=0
Patterns: deny=0  alert=0  suppress=331
```
- Zero alert emails
- 1,126 deterministic suppressions (stack traces + 404s)
- Zero LLM calls needed (patterns + deterministic filters handled everything)
- Evidence pipeline working (UNION SELECT → downgrade proven)

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
| v0.15.2 | Fix: stack trace TrimSpace bug, module rename logwatch→observer |

---

## 4. Files Changed This Session

| File | Version | Change |
|------|---------|--------|
| `main.go` | v0.13.4, v0.15.2 | Evidence check diagnostics, noise_suppressed in stats, module rename |
| `internal/rec/sniffer.go` | v0.13.5 | Stream key debug logging in handleRequest/handleResponse |
| `internal/rec/buffer.go` | v0.14 | Orphan response matching (skip Method/Path check when empty) |
| `internal/rec/collector.go` | v0.14 | Orphan capture mode reporting (single_segment_preview_orphan) |
| `seeds.go` | v0.15, v0.15.2 | Seed purge: 25 → 6 patterns (always-malicious only), module rename |
| `internal/llm/client.go` | v0.15 | 25-line APPLICATION NOISE RULES in classification prompt |
| `internal/analyzer/analyzer.go` | v0.15, v0.15.1, v0.15.2 | isOperationalNoise() TrimSpace fix, isFailedProbe() 404 filter, NoiseSuppressed counter, attack indicators list, module rename |
| `go.mod` | v0.15.2 | Module rename: logwatch → observer |
| `internal/normalizer/normalizer.go` | v0.15.2 | Module rename |
| `internal/normalizer/normalizer_test.go` | v0.15.2 | Module rename |
| `internal/notifier/notifier.go` | v0.15.2 | Module rename |

---

## 5. Evidence Pipeline — How It Works Now (Proven on Production)

```
Log line arrives
  ↓ Step 1: Normalize
  ↓ Step 1.5: isOperationalNoise? → suppress (stack traces, framework errors)
  ↓ Step 1.6: isFailedProbe? → suppress (clean 404/403/405, no payload)
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

## 6. AI Committee Briefing & Decisions

Created `observer-design team-briefing-2026-03-24.md` covering three connected decisions.

All four AIs (the team, code review, , ) converged on:
- **Seeds:** Option D — trim to always-malicious only (IMPLEMENTED)
- **Noise:** Option D — deterministic tags + prompt improvement (IMPLEMENTED)
- **Tier 3:** Yes, fail-open, same model with richer prompt, narrow gate (DESIGNED, NOT BUILT)

Additional design team insight: **Outcome clustering** — same source IP + same response body hash + short window = one finding, not 50 emails. Highest-priority next feature after inbox relief.

---

## 7. SQLite Store Design (Agreed, Not Yet Built)

### Architecture Decision
- **Journald** stays for operational telemetry (startup, debug, sniffer, coordinator traces)
- **SQLite** for security findings (alerts, suppressions, downgrades, evidence, scanner sessions)
- Package-level singleton pattern: `store.RecordFinding(ctx, f)` callable from anywhere
- `*Store` struct wrapping `*sql.DB` (not raw global — code review's recommendation)
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
- Metadata: metadata (JSON column)
- Timestamps: created_at

**scanner_sessions** — outcome clustering:
- source_ip, target_app, body_hash, first_seen, last_seen, probe_count, sample_paths (JSON), verdict, notified

**pipeline_stats** — time-series for dashboards:
- timestamp + all pipeline/pattern/REC counters

### Package Structure
```
internal/store/
├── store.go        ← Store struct, Init(), Close(), migrations, pragmas (WAL, foreign keys, busy timeout)
├── types.go        ← Finding, ScannerSession, PipelineStats structs
├── findings.go     ← RecordFinding(), QueryByIP(), QueryByVerdict(), QueryRecent()
├── scanner.go      ← RecordScannerProbe(), GetOrCreateSession(), QuerySessions()
├── stats.go        ← RecordStats(), QueryStats()
└── pruner.go       ← Background goroutine, TTL-based cleanup
```

### Implementation Notes (Committee Technical Guidance)
- Pure Go SQLite (`modernc.org/sqlite`) — no CGO, maintains single-binary philosophy
- Write buffering: allows/suppresses batch every 1-2s via channel, alerts/denies write immediately
- Pruning: allow rows after 7 days, suppress/downgrade after 90 days, alerts/intrusions never auto-pruned
- Indexes: source_ip, timestamp, verdict, normalized_hash, scanner source_ip
- Metadata stored as JSON column (SQLite json_extract for queries)
- All methods accept context.Context
- Init() owns full DB setup: open → pragmas → migrations → verify → ready

---

## 8. Future Design Discussions (Not Yet Built)

### Tier 3 Forensic Narrative (The "3am Email" Gate)
- Only fires when Tier 2 confirms attack SUCCEEDED
- Gets everything: log line, normalized line, response body, headers, recent alerts from same IP, sibling container logs, pattern store history
- Produces human-readable forensic summary for the email
- Fail-open: if LLM times out, send Tier 2 alert as-is
- Same model (GPT-5 mini) with richer prompt, higher reasoning effort
- Committee agreed, design complete, implementation after SQLite store

### Outcome Clustering
- Same source IP + same redacted body hash + short time window = one finding
- "Scanner probed 53 PHP filenames; all returned default Laravel page" = one email
- Requires SQLite store (scanner_sessions table)
- Highest-priority feature after store is built

### Response Actions (Observer → fail2ban/iptables)
- Observer detects scanner → triggers automated block
- Observer knows more than fail2ban (intent, outcome, evidence)
- Architecture: findings → action system → iptables/fail2ban/Cloudflare API/DEC-1
- Simplest v1: Observer writes blocklist file, cron job reads it
- Requires high-confidence classification before automated action (ties to Tier 3)
- DEC-1 ecosystem play: Observer application intelligence → DEC-1 network enforcement

---

## 9. Deep Research: 404 Suppression Safety (Late Session)

### Context
Observer's `isFailedProbe()` deterministically suppresses HTTP 404/403/405 responses with no attack payload in path/query. Eliminated 1,126+ alerts/hour. Research brief (`research-404-suppression-safety.md`) sent to both the team and code review for independent deep research.

### Core Finding
**404 suppression is industry-standard and safe as implemented, but path/query-only inspection is a noise filter, not a security boundary.** Both AIs converged on identical conclusions.

### Three Consensus Blind Spots

**1. 403 ≠ 404 (HIGHEST PRIORITY)**
- 403 confirms resource EXISTS but access denied. RFC 9110 Section 6.5.3 acknowledges this.
- Every enumeration tool (Gobuster, Feroxbuster, dirb) filters 404s but keeps 403s.
- Standard attack workflow: scan → discard 404s → collect 403s → attempt bypass.
- 403→200 transitions may indicate successful access-control bypass.
- **Recommendation:** Remove 403 from blanket suppression. Track per-IP 403 patterns. Alert on 403→200 transitions.

**2. Header/Body Payloads Are Invisible**
- Path/query-only inspection misses ~50% of injection attack surface.
- Log4Shell (CVE-2021-44228): payload in User-Agent, fires during logging, response code irrelevant.
- Apache Struts (CVE-2017-5638): RCE via Content-Type header.
- Blind SSRF (CVE-2020-10770, Keycloak): fires during request processing.
- **Recommendation:** Scan User-Agent/Referer for `${jndi:`, OGNL markers, control chars. Low-cost regex, no LLM needed.

**3. Volume-Based Scanning Detection Is Missing**
- No major security tool alerts on individual 404s. All use volume thresholds.
- OSSEC/Wazuh: 12 events/90s from same IP → alert. ModSecurity CRS: 5 errors/60s → block.
- **Recommendation:** Alert when single source IP generates >12 suppressed 404/403 within 90 seconds.

### Additional Recommendations
- **Method gating (code review unique):** Only suppress GET/HEAD. Never suppress POST/PUT/PATCH/DELETE 404s — those methods carry body payloads. Zero-cost guard.
- **Sensitive path watchlist (never suppress):** `/.env`, `/.git`, `/wp-admin`, `/actuator`, `/_ignition`, `/debug`, `/phpinfo`, `/server-status`
- **Record suppressed events as telemetry:** Counters per IP, not full logs. Answer "what scanning happened last night?" without email noise.
- **Recursive URL decoding:** Decode at least twice before pattern matching. Double-encoding (`%252e%252e`) evades single-pass checks.

### CapRover-Specific Finding (Both AIs)
CapRover's default nginx `proxy_pass` means most 404s are Laravel-generated (full bootstrap runs). Global middleware executes. `web` middleware group does NOT execute on unmatched routes by default — a meaningful security boundary.

### CVEs Referenced
CVE-2021-44228 (Log4Shell), CVE-2017-5638 (Struts), CVE-2020-10770 (Keycloak SSRF), CVE-2021-3129 (Laravel Ignition RCE), CVE-2016-4977 (Spring SpEL), Magecart 2023 (404 page skimmers), CVE-2019-0941 (IIS CPDoS).

### Implementation Priority
1. Separate 403 handling from 404/405
2. Method gating — only suppress GET/HEAD
3. Volume-based scanner detection (~12 events/90s)
4. Scan User-Agent/Referer for JNDI, control chars, OGNL
5. Never suppress known sensitive paths
6. Record suppressed events as lightweight telemetry

---

## 10. Live Attack Analysis (Late Session — Real Production Alerts)

Three alerts received between 6:55pm and 7:25pm PST on production:

### Alert 1 — DNS Out-of-Band Probe
- **Source:** `47.91.125.252`
- **Payload:** `GET /?dns=<base64>` — decodes to DNS query to `dnsmeasure.top` (known OAST service)
- **Technique:** Trigger DNS lookup to attacker-controlled domain, confirm target processes input regardless of HTTP response
- **Response:** 200 + 2401 bytes (CapRover catch-all page, not real execution)
- **Matched Via:** `llm` — first time seeing this pattern
- **Verdict:** LLM correctly identified as SSRF/OOB probe

### Alerts 2 & 3 — Node.js RCE Probe (CVE-2025-55182 Scanner)
- **Source:** `45.148.10.160`
- **Payload:** Base64-encoded JavaScript in query string, decodes to:
```javascript
(function(){
  try {
    var cmd = "echo VULN_TEST";
    var result = require('child_process').execSync(cmd, {encoding: 'utf8'});
    return btoa(result);
  } catch(e) { return btoa(e.toString()); }
})()
```
- **Target:** `api.admin.kovicloud.com` (Laravel backend — wrong target, not a Node.js RSC app)
- **Response:** 200 + 34,033 bytes (KOVI Laravel app returning normal page, attack NOT executed)
- **LLM impressive:** Decoded base64, identified `child_process.execSync`, classified as malicious
- **LLM wrong:** "server returned 200 and likely executed" — the 34KB is the Laravel app, not command output
- **THIS IS THE EXACT SCENARIO TIER 3 WOULD FIX:** With response body, Tier 3 would see Laravel page and downgrade

### Dual-Container Problem Confirmed Live
- Alert #2 = nginx log, Alert #3 = backend log, same attack at same timestamp (01:54:56)
- Two separate emails for one attack
- Coordinator should have grouped into one huddle but dispatched both
- Likely cause: normalization difference (nginx hostname-prefixed vs backend bare format) producing different coordinator keys, or massive base64 query string truncated differently

### Evidence Timing Problem Confirmed
- All three alerts show `Response Evidence: not_available_no_match`
- Evidence pipeline IS working (proven earlier with manual UNION SELECT test)
- Coordinator's 5-second finalize window expires before orphan response arrives in buffer
- **Fix needed: extend finalize window** or make evidence check retroactive/async

### CapRover Host Header Leak
- LeakIX scanner earlier probed `test3.admin.kovicloud.com` with `GET /` and got 200
- CapRover's nginx has no default server block dropping unrecognized Host headers
- Unrecognized hosts fall through to catch-all, returning CapRover landing page
- **Fix: add default server block returning 444 for unrecognized hosts**

---

## 11. Self-Correcting Evidence Loop (Design Insight)

The complete self-correcting loop that Tier 3 + reclass cache creates:

1. **First attack:** LLM classifies as malicious (correct — payload IS malicious). Tier 3 gets response body (Laravel welcome page). Reclassifies as `malicious → recon_failed`. **Caches result keyed on redacted body hash.**
2. **Same attack, same response:** Cache hit on body hash → instant downgrade, zero LLM cost, no email.
3. **Same attack, DIFFERENT response body:** Cache miss (different hash) → fresh Tier 3 call with new body. If new body contains `VULN_TEST` output or `child_process` stack trace → **confirmed breach** → email at critical severity. **That result gets cached too.**

The cache becomes a **verdict lookup table indexed by what the server actually returned.** Same attack + Laravel page = noise. Same attack + command output = breach. The response body is the oracle, and the cache ensures you only pay for the LLM once per unique outcome.

---

## 12. Key Discoveries

1. **Namespace capture sees responses but not requests** — TLS terminates at nginx (port 443 encrypted), proxy request is outgoing (AF_PACKET misses it). Orphan response matching solves this.
2. **Orphan matching is safe** — on low-traffic servers, one response in the 5-second window is unambiguous. Multiple candidates → low confidence → dual-gate blocks body preview.
3. **Seeds cause more harm than good at 97% cache hit rates** — they bypass the intelligent pipeline for fractions of a penny savings.
4. **LLM is 90% right on 404s but 10% wrong is enough to poison the cache** — deterministic override for structural facts.
5. **TrimSpace before indentation check = invisible bug** — the whitespace that signals a stack trace gets eaten before you check for it. Check first, trim after.
6. **401 is not a failed probe** — it's surface discovery. Committee agreed to exclude from blanket suppression.
7. **Four AIs converging on the same answer is a strong signal** — happened on all three design team decisions AND the 404 suppression research.
8. **1,126 suppressions in one hour with zero LLM calls** — deterministic filters are the only thing that scales linearly.
9. **Observer knows more than fail2ban** — classification + evidence + intent makes Observer a potential security orchestrator, not just an alerting tool.
10. **404 suppression is industry-standard but path/query-only inspection is a noise filter, not a security boundary** — the team and code review deep research independently converged on same three blind spots.
11. **403 is not 404** — a 403 confirms resource existence. Suppressing 403s eliminates visibility into access-control probing. RFC 9110 even says servers should return 404 to hide forbidden resources.
12. **Evidence timing is the remaining bottleneck** — orphan matching works, reclass cache works, but coordinator's 5-second window expires before evidence arrives for real scanner traffic. Need to extend or make async.
13. **GPT-5 mini decoded base64 and identified child_process.execSync** — the LLM classification quality is excellent; the problem is not having the response body to tell it "but the server ignored it."
14. **Cache architecture eliminated the need for local AI hardware** — the Jetson Orin Nano went from essential to unnecessary. NanoPi R6S now 100% allocated to DEC-1.

---

## 13. Hardware Update

**NanoPi R6S arrived** after being lost in shipping for weeks. Originally considered alongside Jetson Orin Nano for Observer's local AI inference, but Observer's cache architecture made local LLM unnecessary:
- 97%+ cache hit rate → LLM is cold-start learning tool, not hot-path dependency
- OpenAI API cost <$1/month
- NanoPi R6S now 100% allocated to DEC-1 security appliance prototype
- Dual 2.5GbE for inline network monitoring, RK3588S for packet processing

---

## 14. Deployment Cheat Sheet

### Build and Release (WSL)
```bash
cd ~/vaultguardian-observer
GOOS=linux GOARCH=amd64 go build -o observer .
git add .
git commit -m "description"
git push
gh release create vX.X ./observer --title "Observer vX.X" --notes "description"
```

### Deploy to Server
```bash
rm -f observer
gh release download vX.X --repo VaultGuardian/observer --pattern "observer"
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

## 15. Next Session Priority

1. **Fix evidence timing** — extend coordinator finalize window from 5s to 15s, or make evidence check async/retroactive
2. **Fix dual-container coordinator key mismatch** — investigate why nginx + backend alerts for same attack produce different keys
3. **Implement 404 suppression hardening** — separate 403, method gating, volume-based scanner detection
4. **Add CapRover default server block** — return 444 for unrecognized Host headers
5. **Build `internal/store/` SQLite package** — schema, Init(), RecordFinding(), basic queries
6. **Wire store into pipeline** — coordinator dispatch writes findings, periodic stats writes pipeline_stats
7. **Outcome clustering** — scanner_sessions table, collapse same-IP + same-body-hash
8. **Tier 3 forensic narrative** — confirmation call before "confirmed intrusion" emails

---

## 16. Architecture Principles (Updated)

- **Deterministic over opinion:** If a fact is structurally certain (404 + no payload = failed probe), don't let the LLM vote on it.
- **Physics, not probability:** Stack traces, failed HTTP status codes, and framework errors are structural truths. Classify them with code, not AI.
- **Seeds are for game-overs only:** Reverse shells and destructive commands. Everything else goes through the intelligent pipeline.
- **Evidence changes conclusions:** 200 without body = ambiguous. 200 with Laravel welcome page = attack ignored.
- **Cache the right answer:** One bad LLM call cached forever = 70 emails. Deterministic filters prevent bad answers from entering the cache.
- **The cache is a verdict oracle:** Same attack + different response body = different verdict. The cache self-corrects as it learns server behavior.
- **Check before you trim:** Whitespace, indentation, and formatting ARE data. Don't normalize signals away before you've checked for them.
- **Journald for ops, SQLite for findings:** Different questions deserve different storage.
- **401 is not 404:** Surface discovery (endpoint exists + requires auth) is a finding. Failed probe (resource doesn't exist) is noise.
- **403 is not 404:** A 403 confirms resource existence. RFC 9110 says servers should use 404 to hide forbidden resources.
- **Suppression is a noise filter, not a security boundary:** Industry consensus validates 404 suppression, but path/query-only inspection misses headers, bodies, and methods entirely.
- **Detection → Classification → Evidence → Response:** Observer's pipeline should eventually close the loop by feeding intelligence into enforcement tools (fail2ban, iptables, DEC-1).