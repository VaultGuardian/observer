# Observer Development Session Summary

**Date:** March 23, 2026
**Previous Session:** March 20, 2026 (afternoon — REC Phase 1, VXLAN discovery)
**Purpose:** Implement the full evidence pipeline: VXLAN decap → namespace capture → structural redaction → evidence-aware re-classification → re-classification caching → forensic huddle coordinator.
**Releases this session:** v0.12, v0.12.1, v0.12.2, v0.12.3, v0.12.4, v0.13, v0.13.1, v0.13.2

---

## 1. The Journey (Timeline)

### v0.12 — VXLAN Decapsulation + Tier 2 Fixes

**New files:**
- `internal/rec/vxlan.go` — RFC 7348 VXLAN decapsulation. Always-on, no-op when absent.
- `internal/rec/vxlan_test.go` — 9 test functions.
- `internal/rec/bpf.go` — BPF kernel filter reference stub.

**Modified:** sniffer.go (VXLAN-first processFrame), collector.go (VXLANPort/DockerSocket/Stats), types.go (RECStats), analyzer.go (source hint removed), main.go (env vars, REC stats, cross-container dedup).

**Production discovery:** No VXLAN traffic on single-node Swarm. Traffic stays inside Docker network namespaces.

---

### v0.12.1 — Namespace Capture (THE BREAKTHROUGH)

**Discovery:** `sudo nsenter -t 2484 -n tcpdump` showed HTTP flowing inside nginx's namespace while the host saw nothing.

**New file:** `internal/rec/nsenter.go` — `openSocketInNamespace()` via `setns(CLONE_NEWNET)` + `findContainerPID()` via Docker API.

**Env var:** `REC_NS_CONTAINER=captain-nginx`

**Result:** First-ever evidence capture: `EvidenceStatus=available_high_confidence`

**Problem found:** LLM concluded "likely exploitation attempt" for SQL injection that returned standard Laravel welcome page. 200 + 34KB looks scary without the body.

---

### v0.12.2 — Structural Redaction + Re-Classification (THE PAYOFF)

**New file:** `internal/rec/redaction.go` — `detectFormat()` + `redactHTML/JSON/Dotenv/Passwd`. HTML redactor keeps visible text, strips secrets — LLM can see "Laravel v11.36.1".

**New method:** `ReclassifyWithEvidence()` in `internal/llm/client.go`

**Dedup key fix:** Removed reason from key, now `method|path|statusCode` only.

**Result:**
```
[DOWNGRADED] Original=malicious→recon_failed
Reason=Response is the default Laravel welcome page — the app returned a normal
framework page and ignored the SQL payload.
```

---

### v0.12.3 — Re-Classification Cache

Added `reclassCache` keyed on body preview hash. Same body = same conclusion, skip LLM.

**Problem:** Cache wasn't hitting — raw BodyPreviewHash changes every request (CSRF tokens).

---

### v0.12.4 — Cache Fix: Hash on Redacted Body

Changed cache key from raw body hash to `rec.HashBody([]byte(evidence.SafeBodyPreview))`. Redacted body is stable across requests.

**Result:**
```
First attack:  [DOWNGRADED] (5 seconds, LLM call)
Second attack: [reclassify] Cache hit (same second, free)
```

---

### v0.13 — Forensic Huddle Coordinator

**Problem:** Nginx fires email instantly on seeded pattern before evidence arrives. Backend correctly downgrades seconds later. Email already sent.

**AI Committee convergence:** the team, code review, the design review all agreed: hold ambiguous HTTP alerts, fire immediately for non-HTTP.

**New file:** `internal/coordinator/coordinator.go` — Map of pending investigations, 2s evidence window, 5s finalize window, retry every 500ms. Three states: pending → resolved → dispatched.

**Removed:** Old alertDedup code (coordinator handles dedup via shared correlation key).

---

### v0.13.1 — Fix Backend Routing

Backend bare normalized lines (`GET /path HTTP/1.0 200`) didn't match hostname-prefixed regex. Added `reNormalizedHTTPBare`.

---

### v0.13.2 — Fix Generic Normalizer Format

Generic normalizer produces `<IP> ... "GET /path HTTP/1.0" 200` with request inside quotes. Added `reNormalizedHTTPQuoted` to find HTTP anywhere in the line.

**Result:** Both containers join same huddle:
```
[coordinator] New investigation: key=GET|/?q=UNION+SELECT+1,2,3|200
[coordinator] Event joined huddle: events=2
```

---

## 2. Current State (v0.13.2)

### What Works
- ✅ VXLAN decap (multi-node Swarm ready)
- ✅ Namespace capture (single-node Swarm — production proven)
- ✅ Structural redaction (HTML/JSON/dotenv/passwd)
- ✅ Evidence-aware re-classification (correct conclusions proven)
- ✅ Re-classification cache on redacted body hash (instant after first)
- ✅ Coordinator groups nginx + backend into one investigation
- ✅ Three HTTP parse formats handled
- ✅ REC telemetry in journal

### What's Broken (One Issue)
- ❌ **Coordinator evidence check can't find/use evidence.** Huddle works, but `tryEvidenceCheck()` returns false for 5 seconds, then times out and dispatches. Evidence IS being captured (proven in v0.12.2), but the coordinator's callback can't access it.

### Three Suspects (All AIs Agree)
1. **Evidence found but SafeBodyPreview empty** — dual-gate blocking on single-segment capture or format detection. MOST LIKELY.
2. **Path mismatch** — sniffer stores `req.RequestURI` raw, parseNormalizedLine extracts from normalized line. Any difference = zero candidates.
3. **Buffer expiry** — least likely (10s buffer vs 5s window).

### The Root Cause of Blindness
```go
if evidence == nil || evidence.SafeBodyPreview == "" || evidence.Transport == nil {
    return false, ""  // ← hides ALL diagnostic info
}
```
This early return treats "no match", "low confidence", "unknown format", and "empty preview" all identically: silence.

### The Fix (Next Session, 2 Minutes)
Add one debug log before the early return. Reveals which suspect is guilty in one curl.

---

## 3. Release History

| Version | Changes |
|---------|---------|
| v0.13.2 | Fix: generic normalizer quoted format parsed for coordinator |
| v0.13.1 | Fix: backend bare HTTP format parsed for coordinator |
| v0.13 | Forensic huddle coordinator — hold HTTP alerts for evidence |
| v0.12.4 | Cache on redacted body hash (stable across CSRF changes) |
| v0.12.3 | Re-classification cache (skip LLM on repeat) |
| v0.12.2 | Structural redaction + evidence-aware re-classification |
| v0.12.1 | Namespace capture. First evidence on production. |
| v0.12 | VXLAN decap, dedup, source hint removal, REC telemetry |

---

## 4. Environment Variables (Production)

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

## 5. Architecture Principles

- **Observer lives at the Linux boundary.** /proc, setns, AF_PACKET, Docker API. No app configs.
- **Evidence changes conclusions.** 200 without body = ambiguous. 200 with Laravel welcome page = attack ignored.
- **Detection is instant, notification is patient.** Coordinator holds HTTP alerts for evidence.
- **Cache everything.** Pattern store for log classification. Reclass cache for body verdicts.

---

## 6. Three Deployment Topologies

| Deployment | Capture Strategy | Status |
|---|---|---|
| docker-compose | Host AF_PACKET | ✅ Works |
| Multi-node Swarm | VXLAN decap | ✅ Ready |
| Single-node Swarm | Namespace capture | ✅ Production proven |

---

## 7. Key Discoveries

1. Single-node Swarm doesn't use VXLAN — traffic in kernel namespaces
2. Namespace capture via setns(CLONE_NEWNET) works
3. Redaction must keep visible text for LLM re-classification
4. Cache on redacted body, not raw (CSRF tokens bust raw hash)
5. Dedup key can't include reason string
6. Three normalized line formats exist (hostname, bare, quoted)
7. Evidence check callback is too silent — hides all diagnostic info

---

## 8. Next Session Priority

1. Add debug log to evidence check (2 min) — find the broken wire
2. Fix whatever it reveals
3. Let coordinator soak against real traffic
4. Begin journald watcher research (code review researching output format + Go patterns + noise list)

---

## 9. Files Changed This Session

| File | Version | Change |
|------|---------|--------|
| `internal/rec/vxlan.go` | v0.12 | NEW — VXLAN decap + Swarm detection |
| `internal/rec/vxlan_test.go` | v0.12 | NEW — 9 tests |
| `internal/rec/bpf.go` | v0.12 | NEW — BPF reference stub |
| `internal/rec/nsenter.go` | v0.12.1 | NEW — Namespace capture |
| `internal/rec/redaction.go` | v0.12.2 | NEW — Format detection + 4 redactors |
| `internal/coordinator/coordinator.go` | v0.13 | NEW — Forensic huddle |
| `internal/rec/sniffer.go` | v0.12 | VXLAN-first processFrame, counters |
| `internal/rec/collector.go` | v0.12-v0.12.2 | NSContainer, Stats, redaction stubs replaced |
| `internal/rec/types.go` | v0.12 | RECStats type |
| `internal/analyzer/analyzer.go` | v0.12 | Source hint gate removed |
| `internal/llm/client.go` | v0.12.2 | ReclassifyWithEvidence method |
| `main.go` | v0.12-v0.13.2 | Coordinator, reclass cache, 3 parse regexes, env vars |

---

## 10. Refactoring Audit (Late Session)

Seven issues identified and fixed. Zero behavior changes — same logic, better organized.

### What Was Refactored

**1. main.go God function → 5 files**
- `config.go` — Config struct, LoadConfig(), getEnv(), truncate()
- `seeds.go` — denySeeds data table + seedDenyPatterns()
- `httpparse.go` — Three normalized line regexes + parseNormalizedLine()
- `reclasscache.go` — reclassCache struct + get/put methods
- `main.go` — Now just wiring. Callbacks extracted to named functions: makeDispatchCallback(), makeEvidenceCheckCallback(), makeLogHandler(), runPeriodicStats()

**2. Dead code removed**
- `sourceHintMatches()` + `isFillerWord()` from analyzer.go (70 lines, unused since v0.12 source hint removal)
- `autoDetectInterface()` from sniffer.go (18 lines, unused since v0.11.1)
- Unused `strings` and `net` imports cleaned from both files

**3. classifyAndRedact moved** from collector.go to redaction.go (where the redactors it calls live)

**4. Dockerfile updated** — binary `logwatch` → `observer`, comments updated

**5. docker-compose.yml updated** — service `logwatch` → `observer`, container `vg-logwatch` → `vg-observer`, volume `logwatch-data` → `observer-data`

**NOT done (next session):** Module rename `logwatch` → `observer` in go.mod + all imports. Biggest change, should be tested in isolation.

---

## 11. Design Principles Queued for Next Session

### Tier 3 LLM Verification
Before sending "confirmed intrusion" alert, run a third LLM call with higher reasoning effort. Feed it EVERYTHING: original line, normalized line, response body, status/headers, recent alerts from same source, pattern store history, other container logs from same timestamp. LLM produces a short human-readable summary for the 3am email. Only fires on Tier 2 confirmed positives (extremely rare). Cost: one extra call vs. cost of false alarm destroying trust.

### Ephemeral Raw, Persistent Clean
Raw log lines and response bodies are transient — they exist in memory briefly, never written to disk, zeroed after use. What persists (pattern store, reclass cache, coordinator state) contains only hashes, verdicts, and summaries. Never raw content.

Attack surfaces to harden:
- REC buffer holds raw bodies for 10s (required for HTTP parsing)
- PendingAlert holds raw Line field (required for LLM re-classification)
- Both bounded lifetime, memory-only, zeroed on eviction

### Normalized Out, Raw Stays Local
Currently raw log lines are transmitted to OpenAI (LLM calls) and Resend (email alerts). Fix: send normalized lines to LLM (IPs/timestamps already stripped). Send only reason + summary in emails, not raw lines. Tier 3 is the exception — gets raw data for maximum accuracy, but that's one call per confirmed breach.

### Data Transparency
- First-run consent before any external transmission
- `--data-policy` flag shows exactly what goes where
- `--local-only` mode with Ollama (zero external transmission)
- Debug mode logs exactly what was sent to external APIs
- Open core = anyone can audit the claims

Rule: Security tools that spy on their users are the exact thing Observer is built to catch. We can't be the thing we're fighting.

---

## 12. Pending Bug (Coordinator Evidence Check)

The coordinator groups alerts correctly but evidence check returns false for 5 seconds, then times out. Three suspects ranked by all AIs:

1. Evidence found but SafeBodyPreview empty (dual-gate blocking)
2. Path mismatch between normalizer and sniffer
3. Buffer expiry (least likely)

**Debug line to add next session:**
```go
log.Printf("[coordinator] Evidence check: key=%s status=%v candidates=%d transport=%v preview_len=%d format=%v",
    pending.Key, evidence.Status, evidence.CandidateCount,
    evidence.Transport != nil, len(evidence.SafeBodyPreview),
    func() any { if evidence.Disclosure != nil { return evidence.Disclosure.Format }; return nil }())
```
