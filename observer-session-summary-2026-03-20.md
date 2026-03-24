# Observer Development Session Summary

**Date:** March 20, 2026
**Previous Session:** March 19, 2026
**Purpose:** Capture all decisions, fixes, root cause analysis, deployments, and next steps.

---

## 1. What Was Accomplished

### Website Updates (VaultGuardian.io)

**New `/observer` page** — Full teaser/announcement page with SEO metadata, seven sections:
- Hero with "In Development" badge
- The Problem (log noise / alert fatigue)
- How It Works (5-step pipeline walkthrough)
- What It Catches (6 threat categories)
- Architecture highlights
- AI vs AI economics comparison
- Open Core announcement (core engine will be open-source)
- Ecosystem section positioning DEC-1 + Observer

**Rewritten `/about` page** — Origin story rewrite based on 's founder narrative advice:
- Hero changed from "We studied the breaches" → "I just wanted to protect a backup server"
- New "The Origin" section with the real story (driver's licenses in R2 → backup server → DEC-1 → Observer)
- Terminal widget showing chain of causality (origin.log)
- Breach analysis repositioned as "validation" not origin
- "Two Products" section with DEC-1-first hierarchy
- "The Founder" section replacing anonymous "The Team"
- Updated Radical Honesty (removed "Not AI-powered", added "Not a SIEM replacement")
- Open Core badges throughout

**Homepage** — New "THE VAULTGUARDIAN ECOSYSTEM" section between Defense in Depth and pricing. DEC-1 and Observer side-by-side cards. Narrative: "We built the DEC-1 first. Then we built Observer because blocking alone wasn't enough."

**How It Works** — Observer bridge CTA above existing CTA: "The DEC-1 stops data from leaving. Want to catch the act itself?"

**Header** — Observer added to nav between "How It Works" and "Threat Intel"

**Footer** — Observer added to Product column

**Key positioning decisions:**
- DEC-1 is the backbone, Observer is the expansion (not a pivot)
- "In Dev — Open Core" badges on Observer everywhere
- Open-source core when ready, commercial add-ons TBD
- Origin story leads with the operational problem, not "we love cybersecurity"

---

### Observer v0.6 — Provenance & Stabilization

**Event IDs** — Every event gets a unique `ID` (`evt_` + 16 hex chars) at creation via `crypto/rand`. Carried through pipeline into alerts and email.

**Seed Deduplication** — Two fixes:
- `SeedDenyPattern()` checks for existing patterns before appending
- `load()` runs `deduplicateContains()` to clean up existing duplicates
- Production had 168 duplicates → cleaned to 24 on first restart

**LLM Classification/Action Reconciliation** — `reconcileClassificationAction()` in `client.go` ensures classification and action fields agree. When they contradict, classification wins. Logs contradictions for monitoring.

**Immutable Alert Snapshots** — `buildAlert()` closure in `main.go` captures `evt` and `result` by value from the same goroutine-local scope. Alert struct now includes `EventID`, `MatchedVia`, `NormalizedHash`.

**Email Template Updated** — Shows "Matched Via" row and `event=evt_xxxx hash=abcd...` in footer for forensic tracing.

**Journal Log Tracing** — `[ALERT]` and `[SUSPICIOUS]` lines now include `EventID=`, `MatchedVia=`, `Hash=`.

---

### Observer v0.7 — Intent/Outcome Classification

**New LLM prompt** with intent × outcome matrix:
- `recon_failed` + `suppress` — Scanner probed, got 404/403/405/400 = noise, no email
- `recon_success` + `alert` — Scanner probed, got 200 on sensitive path = URGENT
- `malicious` + `deny` — Attack payload in URL regardless of status code
- `safe` + `allow` — Normal operational logs
- `noise` + `suppress` — Debug spam, health checks

**Explicit rules for HTTP status codes:**
- 404/403/405/400 on suspicious path = recon_failed = suppress
- 200 on suspicious path = recon_success = alert
- nginx "open() failed (No such file or directory)" = recon_failed = suppress

**Reconciliation updated** for new `recon_failed` and `recon_success` classifications.

---

### Observer v0.8 — Model Upgrade

**Model:** `gpt-5-nano-2025-08-07` → `gpt-5-mini-2025-08-07`
- 5x cost increase ($0.05→$0.25 input, $0.40→$2.00 output)
- Dramatically better instruction following
- At ~500K tokens/day learning phase, cost is ~$1.35 vs $0.27 — trivial given cache architecture

**Reasoning effort:** `"low"` → `"medium"` — nano was ignoring prompt rules at low; medium gives enough reasoning budget for mini to follow the intent/outcome classification correctly.

**Result:** Zero LLM errors (nano was returning empty content with `finish_reason: "length"` at medium reasoning)

---

### Observer v0.9 — Nginx Normalizer Root Cause Fix (THE BIG ONE)

**Root cause found:** The nginx normalizer had two critical bugs causing all alerts to share the same hash and the same cached reason.

**Bug 1: CapRover hostname field parsed as request line**

CapRover nginx log format includes hostname before request line:
```
"api.admin.kovicloud.com" "GET /?q=UNION+SELECT HTTP/2.0" 200 34020 "-" "curl" "-"
```

The normalizer assumed first quoted field = request line. It grabbed `"api.admin.kovicloud.com"`, then `reQuotedField.ReplaceAllString` nuked the actual request line as a "trailing field." Every request to the same host with the same status code and response size normalized identically.

**Bug 2: Query strings fully stripped**

`reQueryString.ReplaceAllString(requestPart, "?<QUERY>")` collapsed all query-string attacks into `GET /?<QUERY> HTTP/2.0`. UNION SELECT, cat /etc/passwd, DROP TABLE — all same hash.

**Fix: Complete rewrite of `normalizeAccess()`**

New approach:
1. Extract ALL quoted fields via `reAllQuotedFields`
2. Find the one matching `reRequestLine` (starts with HTTP method)
3. If a quoted field appears before it, that's the hostname
4. Preserve the full request line including query string (SACRED)
5. Extract status code from text after request line
6. Output: `HOST REQUESTLINE STATUS` — nothing else

Normalized output examples:
```
api.admin.kovicloud.com GET /?q=UNION+SELECT+1,2,3 HTTP/2.0 200
api.admin.kovicloud.com GET /?cmd=cat+/etc/passwd HTTP/2.0 200
api.admin.kovicloud.com GET /.env HTTP/2.0 403
api.admin.kovicloud.com GET /admin HTTP/2.0 404
```

All different hashes. All independent classifications.

**New tests added:** `TestCapRoverNginxFormat` with 4 subtests:
- Hostname field does not eat request line
- Different attacks produce different hashes (the original bug)
- Different 404 paths produce different hashes
- Same request from different IPs hashes identically

All 28 tests pass in 4ms.

---

## 2. Bug Investigation Timeline

The session started with a false alert email: "SQL injection attempt (DROP TABLE)" on a clean GPTBot GET / request.

**Initial theory (the team):** LLM hallucinated the reason field.

**'s counter-theory:** Event contamination — a real malicious reason from an earlier event attached to the wrong request.

**What the data showed:**
- LLM returned `classification=safe confidence=0.75 action=allow` but an `[ALERT]` fired with "DROP TABLE" reason
- Deny count jumped from 126→127 at the same moment
- `MatchedVia=auto` — it was a cached hash match, not an LLM response

**Breakthrough:** All malicious requests shared hash `5e6926ec...`. All scanner spray paths shared hash `76a6054a...`. The normalizer was collapsing different requests into identical hashes.

**Root cause confirmed:** Normalizer bug, not LLM hallucination, not event contamination. The first request to get classified got its reason cached, and every subsequent different request with the same broken hash inherited that reason.

**Both the team and  agreed on the diagnosis independently** before the fix was implemented.

---

## 3. Production Stats After v0.9

```
processed=573  pattern_hits=543  llm_calls=30  llm_errors=0  learned=17
deny=5  alert=2  suppress=6  misses=30
```

- 95% cache hit rate
- Zero LLM errors (mini + medium reasoning)
- 17 patterns learned automatically
- 5 deny alerts (all real attack payloads with correct reasons)
- 6 suppressed pattern types (failed recon, noise)
- Zero noise emails for failed probes

**Alert accuracy confirmed:**
| Attack | Reason | Correct? |
|--------|--------|----------|
| `?q=UNION+SELECT` | "SQL injection payload (UNION SELECT)" | ✅ |
| `?cmd=cat+/etc/passwd` | "Password file access" (seeded) | ✅ |
| `?page=;ls+-la` | "Shell command injection (page=;ls -la)" | ✅ |
| `?file=../../etc/shadow` | "Shadow password file access" (seeded) | ✅ |
| `?id=1;DROP+TABLE` | "SQL injection payload (DROP TABLE)" | ✅ |

---

## 4. Release History

| Version | Changes |
|---------|---------|
| v0.6 | Event provenance (EventID), seed dedup, LLM reconciliation, immutable alert snapshots, email template with MatchedVia/EventID/hash |
| v0.7 | Intent/outcome classification prompt (recon_failed/recon_success), suppress failed probes |
| v0.8 | Model upgrade nano→mini, reasoning_effort low→medium |
| v0.9 | Root cause fix: nginx normalizer rewrite, preserve request lines and query strings, handle CapRover hostname field |

---

## 5. Files Changed This Session

| File | Change |
|------|--------|
| `internal/event/event.go` | Added `ID` field, `NewID()` function |
| `internal/normalizer/nginx.go` | **Rewritten** `normalizeAccess()` — finds real request line, preserves query strings, handles CapRover hostname |
| `internal/normalizer/normalizer_test.go` | Added `TestCapRoverNginxFormat` (4 subtests), helper functions |
| `internal/patternstore/store.go` | Seed dedup in `SeedDenyPattern()` and `load()`, added `deduplicateContains()` |
| `internal/llm/client.go` | New intent/outcome prompt, `reconcileClassificationAction()`, reasoning_effort medium |
| `internal/notifier/notifier.go` | Alert struct: added EventID, MatchedVia, NormalizedHash |
| `internal/notifier/email.go` | Template: added Matched Via row, event/hash footer |
| `main.go` | Event ID assignment, `buildAlert()` snapshot, MatchedVia in log lines |
| `/etc/systemd/system/observer.service` | LLM_MODEL changed to gpt-5-mini-2025-08-07 (on server) |

---

## 6. Known Issues Remaining

| Issue | Priority | Description |
|-------|----------|-------------|
| Dual container alerts | Low | Same request logged by nginx AND backend container = two alert emails. Need cross-container dedup. |
| Source hint mismatch blocking pattern learning | Medium | LLM returns "nginx" or "docker" as source hint for CapRover containers. Patterns not learned for `srv-captain--*` containers. Hash learning works fine though. |
| Contamination theory not fully disproven | Low | 's event contamination theory was superseded by the normalizer root cause. EventID trail is in place to confirm on next occurrence. |
| Reason sanity check | Low | Alert reason should verify tokens actually appear in matched line. Not implemented yet. |
| Pattern dedup | Low | Same log pattern can learn multiple similar patterns. |
| No degraded-mode alert | Low | If LLM is down for extended period, nobody knows. |
| Exclude CapRover infra containers | Low | captain-captain, captain-certbot, captain-netdata generate some noise. Can exclude via EXCLUDE_CONTAINERS env var. |
| Remix stack traces | Low | Node.js stack traces from login service still cached as "suspicious" from earlier classification. Will fix on next pattern store wipe. |

---

## 7. Design Discussions (Future Features)

### Response Evidence Capture (v0.8+ — agreed with )

**Concept:** Capture outgoing HTTP response bodies passively (not replay) and correlate with alerts. Turn alerts from "someone asked for something bad" into "someone asked for something bad AND here's what they got."

**Drew's insight:** Rolling 5-second buffer of outgoing responses. When an alert fires, check what was actually returned.

**'s framing:** Call it "Response Evidence Capture" not "packet capture." Product becomes "disclosure-aware."

**Architecture agreed:**
- Start with plaintext HTTP behind reverse proxy (covers 90% of deployments)
- Bounded ring buffer, short retention, size-capped
- Capture: status, content-type, first 1-4KB, SHA-256 of body
- Only persist when tied to an alert
- Disabled by default

**Drew's redaction idea:** Don't store raw secrets. Use structural fingerprinting:
- Keep keys, strip values: `DB_PASSWORD=hunter2` → `DB_PASSWORD=<REDACTED>`
- Keep HTML tags, strip content
- Keep JSON keys, strip values
- Simple classifier: dotenv, HTML page, passwd file, JSON, binary

**Future path:** Start with gopacket on plaintext side → graduate to eBPF for universal coverage.

### Universal Log Collection

Event model already supports `SourceDocker`, `SourceSystemd`, `SourceFile`, `SourceJournal`, `SourceAudit`. Only Docker watcher built. Roadmap:
- Journald watcher (sshd, systemd services)
- File tail watcher (custom log paths via config)
- Covers "any system" use case Drew raised

---

## 8. Deployment Cheat Sheet

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
sudo rm /var/lib/observer/patternstore.json    # only if normalizer/classification changed
sudo systemctl daemon-reload                    # only if service file changed
sudo systemctl restart observer
sudo journalctl -u observer -f
```

### Service File Location
```
/etc/systemd/system/observer.service
```

### Key Environment Variables (current production)
```
DOCKER_SOCKET=/var/run/docker.sock
DATA_DIR=/var/lib/observer
LLM_URL=https://api.openai.com
LLM_MODEL=gpt-5-mini-2025-08-07
LLM_API_KEY=sk-...
EXCLUDE_CONTAINERS=
RESEND_API_KEY=re_...
ALERT_EMAIL_TO=drew@vaultdec.com
```

---

## 9. Key Principles Reinforced

- **Look at the data before diagnosing** — Drew insisted on checking logs before accepting theories. Led to finding the real root cause.
- **The normalizer is the foundation** — If normalization is wrong, everything downstream is wrong. Cache amplifies normalizer bugs.
- **Request lines are sacred** — For security classification, the HTTP request line (method, path, query, protocol) must never be stripped.
- **Use the right model for the job** — Nano couldn't follow the prompt. Mini at medium reasoning follows it perfectly. The cache means model cost barely matters.
- **Three AIs validating = strong signal** — the team, , and code review all converged on the normalizer root cause independently.
- **Ship stabilization before features** — v0.6-v0.9 were all fixes and improvements, no new features. The product went from "unreliable alerts" to "5 correct alerts with reasons matching payloads."
- **Open core as ecosystem play** — DEC-1 funds the business, Observer builds trust and adoption. 's framing: "DEC-1 is the backbone, Observer is the adoption engine."
