# Observer Development Session Summary

**Date:** March 18, 2026
**Purpose:** Capture all decisions, architecture, working code state, and next steps from this session for use as context in future development chats.

---

## 1. What Is Observer

Observer is a host-level log security system that watches container logs (and eventually systemd, journald, file logs), classifies them using a tiered pattern matching system backed by LLM inference, and alerts on malicious/suspicious activity. It learns over time — the first time it sees a log pattern it consults the LLM (~2 sec), then caches the result so every repeat is instant (nanoseconds).

**Key principle:** The system gets *faster* as it learns, not slower.

---

## 2. Architecture

### Pipeline Flow

```
Collector → Event → Normalize → Pattern Match → LLM Fallback → Learn → Alert/Suppress
```

### Core Components

```
internal/
├── event/
│   └── event.go              ← Canonical event model (SourceType, SourceName, Line, Metadata)
├── normalizer/
│   ├── normalizer.go          ← Interface + Registry with fuzzy service matching
│   ├── generic.go             ← Fallback normalizer (timestamps, IPs, UUIDs, durations, numbers)
│   ├── docker.go              ← Docker stream header + timestamp stripping
│   ├── nginx.go               ← Access + error log normalization (PID, conn#, client IP, user-agent, bytes)
│   ├── sshd.go                ← Auth log normalization (PID, IP, port, fingerprint, UID)
│   ├── syslog.go              ← Generic syslog envelope stripping
│   └── postgres.go            ← PG timestamps, PIDs, SQL literals, session context
├── patternstore/
│   └── store.go               ← 3-bucket (allow/deny/suppress), 4-tier matching, persistence
├── analyzer/
│   └── analyzer.go            ← Pipeline orchestrator with LLM semaphore + backpressure
├── llm/
│   └── client.go              ← OpenAI-compatible client with pattern learning + JSON sanitizer
├── notifier/                  ← Email, SMS, webhook, APNs, FCM (unchanged from prior sessions)
└── watcher/                   ← Docker socket watcher (unchanged, bridges to Event via main.go)
main.go                        ← Wiring: normalizer registry → pattern store → analyzer → LLM → notifier
```

### Three-Bucket Model

| Bucket | Purpose | Trust Model |
|--------|---------|-------------|
| **Allow** | Known-good logs, skip silently | Auto-learns from LLM (hash + prefix/regex patterns) |
| **Deny** | Known-bad logs, alert immediately | Hash auto-learned, patterns only from seeds/admin |
| **Suppress** | Known-noise, ignore permanently | Auto-learns from LLM (debug spam, health checks, etc.) |

### Four-Tier Matching (per bucket, priority order)

```
1. Hash      → O(1) map lookup, nanoseconds
2. Prefix    → strings.HasPrefix, sub-nanosecond
3. Regex     → pre-compiled regexp, microseconds (anchored, specific)
4. Contains  → strings.Contains, guarded, rare (minimum 10 chars)
```

**Contains is ranked LAST** despite being fast — it's the most dangerous for overgeneralization. An anchored regex is safer than a vague substring.

---

## 3. Key Design Decisions Made This Session

### Event Model
- `SourceType` + `SourceName` is the scope key (e.g. "docker:nginx", "systemd:sshd")
- `Metadata map[string]string` for extensibility without premature structure
- `ScopeKey()` method returns the pattern store lookup key
- Decided AGAINST a separate "logical service key" abstraction — too early, `SourceType:SourceName` is stable enough for current scope

### Normalizer Architecture
- **Source-family-specific normalizers** are the highest-value optimization — better normalization → more hash hits → fewer LLM calls
- Registry lookup: exact scope key → exact source name → fuzzy contains match → source type → generic fallback
- Fuzzy matching catches "demo-nginx" → "nginx" normalizer, "my-postgres-db" → "postgres" normalizer
- Each normalizer strips Docker framing first, then applies service-specific normalization
- Generic normalizer replaces variables with tokens: `<TS>`, `<IP>`, `<DUR>`, `<NUM>`, `<UUID>`
- Nginx normalizer additionally strips: PID#TID, connection number, client IP, user-agent, response bytes

### Pattern Learning
- LLM returns `pattern_type` (prefix/regex/contains) + `pattern` + `source_hint`
- **Asymmetric trust:** allow/suppress auto-learn patterns; deny only learns exact hash from LLM
- Confidence gate: patterns only learned at ≥0.85 confidence
- Source hint cross-check: fuzzy contains match (not exact) — "demo-nginx" contains "nginx" passes
- Validation: regex must compile + match original line; contains minimum 10 chars; rejects `.*` and `.+`
- Seeded deny patterns are global (all sources) and use substring matching

### Concurrency
- All stats use `sync/atomic.Int64` — safe for concurrent goroutine access
- `StatsSnapshot` structs for serialization/logging (atomic fields can't be copied)
- LLM semaphore with `maxConcurrentLLM=2` prevents startup log floods from overwhelming Ollama
- Non-blocking acquire — if semaphore full, log line is dropped (returns unknown) rather than queuing

### LLM Client
- Uses OpenAI-compatible `/v1/chat/completions` endpoint — works with Ollama, OpenAI, Groq, Together, etc.
- System prompt teaches JSON escape rules (the LLM kept writing `\;` `\+` `\(` which aren't valid JSON escapes)
- `sanitizeJSON()` safety net fixes broken escapes: strips junk escapes (`\;` → `;`), preserves regex metacharacters (`\d` → `\\d`)
- Deny and alert verdicts have patterns stripped server-side (defense in depth)

### Container Exclusion
- `EXCLUDE_CONTAINERS` env var: comma-separated list of container names to skip
- Default: `vg-logwatch,vg-llm` — prevents feedback loop where Observer watches its own logs

---

## 4. Current Deployment

### Docker Compose (testing)
- **vg-logwatch** — Observer container (Go binary)
- **vg-llm** — Ollama with qwen2.5:7b, GPU passthrough to RTX 2070 Super
- **demo-nginx** — Test target generating logs
- Ollama lazy-loads model on first inference request (~40s cold start, then ~2s per call)

### Production Target
- Observer runs as native Go binary on host (systemd service)
- Ollama either native install or Docker — Observer just needs an HTTP endpoint
- Could swap to OpenAI/cloud API with `LLM_URL` and `LLM_API_KEY` env vars

### Environment Variables
```
DOCKER_SOCKET=/var/run/docker.sock
DATA_DIR=/data
LLM_URL=http://llm:11434      (Ollama default)
LLM_MODEL=qwen2.5:7b
LLM_API_KEY=                   (empty for Ollama, set for cloud APIs)
EXCLUDE_CONTAINERS=vg-logwatch,vg-llm
RESEND_API_KEY=                (for email alerts)
ALERT_EMAIL_TO=drew@vaultdec.com
```

---

## 5. Validated Test Results

### Normal Traffic
```bash
curl http://localhost:8080
```
- First request: LLM classifies as safe/allow (~2 sec), learns prefix pattern `^GET / HTTP/1\\.1`
- Second request: **instant pattern hit**, zero LLM calls

### Attack: Command Injection
```bash
curl "http://localhost:8080/;ls+-la"
```
- Error log: LLM classifies as **malicious** "Command injection attempt"
- Access log: LLM classifies as **suspicious** "command injection attempt"
- Second request: error log caught by **deny hash hit** (instant), access log still hits LLM (normalization difference)

### Attack: Path Traversal
```bash
curl "http://localhost:8080/../../etc/passwd"
```
- Both access and error logs caught by **seeded deny pattern** (`/etc/passwd` substring)
- **Instant**, zero LLM calls, both runs

### Attack: SQL Injection
```bash
curl "http://localhost:8080/?q=UNION+SELECT+1,2,3"
```
- First request: LLM classifies as **malicious** "SQL injection attempt" (also matched by seeded `UNION SELECT` pattern)
- Second request: **instant deny hash hit**

### Learning Progression (second run of all attacks)
- 5 attack lines total
- 4 caught instantly (deny hash + seeded patterns)
- 1 hit LLM (access log normalization gap)
- System is measurably smarter on repeat traffic

---

## 6. Known Issues / Bugs Fixed This Session

| Issue | Status | Fix |
|-------|--------|-----|
| Source hint exact match too strict | ✅ Fixed | Fuzzy contains match in both directions |
| LLM returns invalid JSON escapes (`\;` `\+` `\(`) | ✅ Fixed | Prompt rules + `sanitizeJSON()` safety net |
| Stats not thread-safe (data race) | ✅ Fixed | `sync/atomic.Int64` for all counters |
| `PatternCount++` not using atomic | ✅ Fixed | `.Add(1)` |
| `GetStats()` copying atomic fields | ✅ Fixed | Returns `StatsSnapshot` instead |
| LLM_URL default wrong (8080 vs 11434) | ✅ Fixed | Changed to `http://llm:11434` |
| Feedback loop (Observer watching itself) | ✅ Fixed | `EXCLUDE_CONTAINERS` env var |
| Nginx normalizer not being used for "demo-nginx" | ✅ Fixed | Fuzzy service name lookup in registry |
| No LLM backpressure (30 startup logs = 30 concurrent calls) | ✅ Fixed | Semaphore with `maxConcurrentLLM=2` |
| Docker compose `version` warning | ✅ Fixed | Removed obsolete `version: "3.8"` |
| Dockerfile Go version mismatch (1.22 vs 1.23) | ✅ Fixed | Updated to `golang:1.23-alpine` |

---

## 7. Known Issues Remaining

| Issue | Priority | Description |
|-------|----------|-------------|
| Nginx access log normalization gap | Medium | `;ls -la` access log still differs between requests (timestamp position after stripping varies). Needs access log normalizer tuning. |
| Startup log flood | Low | ~30 nginx startup logs all hit LLM sequentially on first boot. Backpressure limits concurrency but doesn't batch. Could batch multiple lines in one LLM call. |
| LLM learns duplicate patterns | Low | Same "start worker process" pattern learned multiple ways because each log line has slightly different normalization. Need dedup on pattern learning. |
| No degraded-mode alert | Low | If LLM is down for 5 min and 200 lines pass through unclassified, nobody knows. Need meta-alert after N consecutive failures. |
| Seeded deny patterns are global and blunt | Low | `"DROP TABLE"` could match a legitimate migration log. Future: scope seeds per source family. |
| No admin UI for pattern management | Future | Can't view/promote/delete/export learned patterns without reading JSON file. |
| Watcher is Docker-only | Future | Need journald, file tail, syslog watchers for host-level monitoring. |
| Pattern store not scoped to source family for deny | Future | Deny hash from "docker:demo-nginx" might not match same attack from "systemd:nginx". |

---

## 8. code review's Review Summary

code review reviewed the full codebase and called it "a strong V1 security-observer prototype, not a joke project." Key feedback:

**Agreed with:**
- Pipeline shape is right
- Three-bucket model is a win
- Pattern tier ordering is correct
- Conservative deny trust model is good

**Issues found (all fixed this session):**
- Concurrency/race on stats → fixed with atomics
- Config drift (LLM URL) → fixed
- Watcher `since=time.Now()` misses pre-attach logs → acknowledged, intentional tradeoff

**Suggestions for later:**
- Bounded LLM concurrency → implemented (semaphore)
- Dedupe/cooldown for repeated unknowns
- Admin surface for pattern management
- Source-family normalization as first-class pillar → implemented

---

## 9. Implementation Priority for Next Session

1. **Nginx access log normalization** — fix the remaining gap so `;ls -la` access logs hash consistently
2. **Pattern dedup** — prevent learning 15 variations of "start worker process"
3. **LLM degraded-mode alert** — meta-notification when classifier is down for >N seconds
4. **Batch LLM calls** — send multiple unknown lines in one prompt to reduce cold-start overhead
5. **Journald watcher** — first non-Docker collector (sshd, systemd services)
6. **Pattern export/import API** — `/api/patterns` for viewing and managing learned patterns
7. **Switch to OpenAI for production** — cloud API for smarter classifications, keep Ollama as offline fallback

---

## 10. File Inventory

All files in the project and their status:

| File | Status | Description |
|------|--------|-------------|
| `main.go` | **Updated** | Wiring with EXCLUDE_CONTAINERS, LLM semaphore, fuzzy source hint |
| `docker-compose.yml` | **Updated** | GPU passthrough, EXCLUDE_CONTAINERS, fixed LLM_URL, no version |
| `Dockerfile` | **Updated** | Go 1.23, go.sum copy |
| `internal/event/event.go` | **New** | Canonical event model |
| `internal/normalizer/normalizer.go` | **New** | Interface + Registry with fuzzy lookup |
| `internal/normalizer/generic.go` | **New** | Fallback normalizer |
| `internal/normalizer/docker.go` | **New** | Docker stream header stripping |
| `internal/normalizer/nginx.go` | **New** | Access + error log normalization |
| `internal/normalizer/sshd.go` | **New** | SSH auth log normalization |
| `internal/normalizer/syslog.go` | **New** | Syslog envelope stripping |
| `internal/normalizer/postgres.go` | **New** | PostgreSQL log normalization |
| `internal/patternstore/store.go` | **New** | Three-bucket, four-tier pattern store |
| `internal/analyzer/analyzer.go` | **Replaced** | New pipeline orchestrator |
| `internal/llm/client.go` | **Replaced** | Pattern learning + JSON sanitizer |
| `internal/notifier/*` | Unchanged | Email, SMS, webhook, push notifications |
| `internal/watcher/watcher.go` | Unchanged | Docker socket log streaming |
| `go.mod` | Unchanged | `github.com/vaultguardian/logwatch`, Go 1.23 |

---

## 11. Key Commands

```bash
# Build and run (testing)
docker compose up --build

# Clean restart (wipe learned patterns)
docker compose down
docker volume rm vaultguardian-logwatch_logwatch-data
docker compose up --build

# Test traffic
curl http://localhost:8080                              # normal
curl "http://localhost:8080/;ls+-la"                    # command injection
curl "http://localhost:8080/../../etc/passwd"           # path traversal
curl "http://localhost:8080/?q=UNION+SELECT+1,2,3"     # SQL injection

# Pre-pull LLM model
docker compose up -d llm
docker exec vg-llm ollama pull qwen2.5:7b

# Build without Docker (native)
go build ./...
```
