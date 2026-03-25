# Observer Development Session Summary

**Date:** March 25, 2026
**Previous Session:** March 24, 2026
**Purpose:** Fix alert noise from nginx error logs, implement design consensus on transport-only evidence downgrade and dual-container dedup, investigate body inspection pipeline blockage.
**Releases this session:** v0.16, v0.17

---

## 1. The Journey (Timeline)

### v0.16 — Nginx Error Log Suppression + Sensitive Path Watchlist

**The problem:** Overnight soak showed 20+ alert emails from a single PHPUnit scanner spraying `eval-stdin.php` across every path prefix (`/www/`, `/api/`, `/admin/`, `/blog/`, `/cms/`, etc.). All were nginx error logs: `open() "..." failed (2: No such file or directory)`. The `isFailedProbe()` function only matched HTTP access log format (looks for `HTTP/x.x STATUS`), so nginx error logs sailed right through to the LLM, which hedged with "not successful but warrants attention" → cached as alert → email.

**The fix:** Extended `isFailedProbe()` with two new detection paths:

**Path 1 — Nginx error log "No such file or directory":**
- New regex `reNginxFileNotFound` matches `open() "..." failed (2: No such file or directory)`
- New regex `reNginxErrorRequest` extracts the HTTP request from `request: "GET /path HTTP/1.1"`
- Structurally equivalent to a 404 — the file doesn't exist on disk, period

**Path 2 — Sensitive path watchlist (22 paths, never suppressed):**
- `/.env`, `/.git`, `/.aws`, `/.ssh`, `/.docker`, `/.htaccess`, `/.htpasswd`
- `/wp-admin`, `/wp-login`, `/wp-config`
- `/actuator`, `/_ignition`, `/debug`, `/phpinfo`
- `/server-status`, `/server-info`, `/elmah.axd`, `/web.config`
- `/config.php`, `/config.json`, `/credentials`, `/containers/json`
- These bypass suppression on BOTH access log and error log paths — always route to LLM

**Factored helpers:** `hasAttackIndicators()` and `hasSensitivePath()` — eliminated duplicated loops.

**Attack indicators expanded:** Added `call_user_func` and `invokefunction` for ThinkPHP RCE detection. Test caught this — ThinkPHP passes function names as parameters (`call_user_func_array&vars[0]=system`) rather than calling them directly (`system(`).

**New test file:** `internal/analyzer/analyzer_test.go` — 41 test cases:
- 13 nginx error log cases (phpunit spray, .env, .git, ThinkPHP, Docker API, permission denied)
- 19 access log cases (clean 404s, 401 exclusion, attack payloads, sensitive paths)
- 13 operational noise cases (Node.js, Python, Go, Java stack traces)
- 6 helper function cases (attack indicators, sensitive paths)

**Production validation:** Ran test curls. All phpunit/webshell/mcp probes → `noise_suppressed`. Sensitive paths (.env, .git, actuator, containers/json) → routed to LLM, correctly classified as `recon_failed` and learned as suppress patterns. Attack payloads (UNION SELECT, ;ls+-la, ThinkPHP) → correctly alerted. Zero false suppressions.

---

### AI Committee Session — Transport-Only Downgrade + Graveyard Dedup

**Briefing document created:** `observer-design team-briefing-coordinator-evidence-2026-03-25.md` covering Bug 1 (dual-container duplicate emails) and Bug 2 (evidence underuse — throwing away transport metadata).

**Committee process:** Drew sent briefing to code review and / independently. Multiple rounds of cross-review between AIs. Drew synthesized and brought results to the team for final review.

**Full consensus achieved on architecture:**

**Bug 2 (fix first) — Transport-only downgrade:**
- In evidence check callback, before requiring `SafeBodyPreview`, check transport status code
- If 403/404/405/410 → instant downgrade, no body needed, no LLM call
- 400 excluded from v1 (code review's recommendation — "fuzzier, add later if soak data is clean")
- 401 excluded (surface discovery)
- 5xx never auto-downgraded (suspicious/ambiguous, keep on alert path)

**Bug 1 (fix second) — Graveyard / recently finalized outcomes cache:**
- After every investigation concludes, write a tombstone to `recentFinalized` map
- Stores ALL outcomes: alerted, downgraded, suppressed (code review's critical catch — if only "dispatched" is remembered, a downgraded nginx finding gets forgotten and the late backend reopens the case)
- TTL: 300 seconds (5 minutes) — covers worst-case LLM queue delays
- Late-arriving siblings check the graveyard before creating new investigations

**403 nuance (the team's contribution, design team agreed):**
- Clean-path 403 = surface discovery (valuable intel, don't blanket-suppress in `isFailedProbe`)
- Payload-bearing 403 = server blocked the attack (safe to auto-downgrade in evidence check)
- Not a contradiction — two different stages of the pipeline doing two different jobs

---

### v0.17 — Transport-Only Downgrade + Graveyard Dedup

**`internal/coordinator/coordinator.go` (451 lines, was 393):**
- New `FinalizedOutcome` struct: outcome, reason, timestamp, event count
- New `recentFinalized` map (the graveyard) on the Coordinator struct
- `GraveyardTTL` in Config (default 300s / 5 minutes)
- `Process()` now checks: active investigation → graveyard → create new
- Late siblings die silently with `[coordinator] Late sibling suppressed via graveyard` log
- `recordFinalized()` called on every dispatch path: alerted, downgraded, evicted
- `graveyardCleanup()` background goroutine sweeps expired entries every 30s
- `Stats()` returns `(pending int, graveyard int)`

**`main.go` (474 lines, was 411):**
- Evidence callback restructured with two downgrade paths
- **Path 1 (transport-only):** If REC has transport and status is 403/404/405/410 → instant downgrade, no body needed, no LLM. Logs `[coordinator] Transport downgrade: key=... status=... candidates=...`
- **Path 2 (body-aware):** For ambiguous codes (200/3xx/5xx) → falls through to body preview + LLM re-classification
- Better diagnostic logging: separate messages for "no evidence at all" vs "have transport but ambiguous status, no body preview"
- Status code tier table in comments documenting design consensus

**Production validation:** Both bugs confirmed fixed:

Transport downgrade:
```
[coordinator] Transport downgrade: key=GET|/;ls+-la|404 status=404 candidates=20
[coordinator] Investigation resolved: DOWNGRADED key=GET|/;ls+-la|404 events=2
[DOWNGRADED] Transport evidence confirms attack failed (HTTP 404) — payload was rejected/ignored
```

Graveyard dedup (second round of curls ~48s later):
```
[coordinator] Late sibling suppressed via graveyard: key=GET|/?q=UNION+SELECT+1,2,3|200 outcome=alerted age=48.551s
[coordinator] Late sibling suppressed via graveyard: key=GET|/;ls+-la|404 outcome=downgraded age=52.944s
[coordinator] Late sibling suppressed via graveyard: key=GET|/?cmd=cat+/etc/passwd|200 outcome=alerted age=48.422s
```

**Score:** Same curl test that produced 8 emails on v0.16 now produces 3 emails on v0.17. The `;ls+-la` attack that sent 2 emails this morning now sends zero.

---

### Dual-Gate Body Preview Investigation

**The remaining problem:** Three emails from attack payloads returning HTTP 200 (UNION SELECT, cat /etc/passwd, ThinkPHP). The body inspection pipeline exists and is proven but never fires because `SafeBodyPreview` is always empty.

**Root cause found:** The dual-gate confidence model is architecturally broken for namespace capture deployments.

The gate requires `CorrelationConfidence == HIGH`, which requires exactly 1 candidate in the buffer. But in namespace capture mode, every response is an orphan (no paired request because the inbound request is TLS-encrypted). The buffer matches on `StatusCode + timestamp window` only. Multiple concurrent requests returning 200 → multiple candidates → LOW confidence → `SafeBodyPreview` empty → body inspection never fires.

**On ANY server with more than one request per 5 seconds, the buffer will always have multiple candidates, correlation will always be LOW, and `SafeBodyPreview` will NEVER populate.**

**Key insight (the team):** The dual-gate was designed before namespace capture existed. The confidence model assumes paired request+response matching. In namespace capture mode, that assumption is permanently false.

**Two consumers with different risk profiles:**
1. **Email template** (shown to human) — dual-gate is correct, don't show a body you're not sure about
2. **LLM re-classification** (automated judgment) — robust to picking the wrong candidate because the question is "what kind of page is this" not "is this the exact page"

**Committee briefing created:** `observer-design team-briefing-dual-gate-2026-03-25.md` with 5 options (A through E) and 5 questions. the team's recommendation: Option B — separate LLM-confidence from email-confidence. Let the LLM use the body even at low correlation confidence while emails remain strict.

**Status:** Awaiting design team responses.

---

## 2. Overnight Soak Results (v0.15.2 → v0.16)

### Stats at time of v0.16 deploy:
```
processed=11,579  pattern_hits=8,633  noise_suppressed=2,928  llm_calls=18  llm_errors=0  learned=8
```

- 99.84% handled without LLM (18 calls out of 11,579 events)
- 2,928 deterministic noise suppressions (stack traces + 404s)
- llm_calls flat for hours — system fully learned
- Zero LLM errors — mini + medium reasoning rock solid

### Alerts that fired (all nginx error logs — the v0.16 bug):
- ~20 PHPUnit `eval-stdin.php` scanner spray alerts (different path prefixes)
- ThinkPHP `invokefunction` exploit probes
- `.env` probes (correctly alerted — sensitive path)
- `/containers/json` Docker API probe
- `/mcp` and `/sse` probes (MCP server scanning)

### Evidence pipeline:
- 100% evidence check MISS (`candidates=0`) — known ingress SNAT problem
- Zero downgrades, zero reclassify cache hits
- Transport downgrade would have killed the phpunit alerts if it existed then

---

## 3. Release History

| Version | Changes |
|---------|---------|
| v0.16 | Nginx error log "No such file or directory" suppression, sensitive path watchlist (22 paths), ThinkPHP/call_user_func attack indicators, analyzer test suite (41 tests) |
| v0.17 | Transport-only evidence downgrade (403/404/405/410), graveyard dedup TTL map (300s), dual-container duplicate emails fixed. design consensus. |

---

## 4. Files Changed This Session

| File | Version | Change |
|------|---------|--------|
| `internal/analyzer/analyzer.go` | v0.16 | `isFailedProbe()` extended with nginx error log detection + sensitive path watchlist + `hasAttackIndicators()`/`hasSensitivePath()` helpers + `call_user_func`/`invokefunction` indicators |
| `internal/analyzer/analyzer_test.go` | v0.16 | NEW — 41 test cases covering failed probe detection, operational noise, attack indicators, sensitive paths |
| `internal/coordinator/coordinator.go` | v0.17 | `FinalizedOutcome` struct, `recentFinalized` graveyard map, `GraveyardTTL` config, `recordFinalized()` on all dispatch paths, `graveyardCleanup()` goroutine, `Process()` checks graveyard before creating investigation |
| `main.go` | v0.17 | Evidence callback restructured: transport-only downgrade path (403/404/405/410), improved diagnostic logging for ambiguous status codes |

---

## 5. Test Coverage

69 tests across 4 packages, all passing in 7ms:

| Package | Tests | Coverage |
|---------|-------|----------|
| `internal/analyzer` | 41 | `isFailedProbe()` (nginx error + access log), `isOperationalNoise()`, `hasAttackIndicators()`, `hasSensitivePath()` |
| `internal/normalizer` | 18 | Docker framing, nginx access/error stability, CapRover format, registry fuzzy lookup, collision detection |
| `internal/rec` | 10 | VXLAN decapsulation, depth guard |
| **Total** | **69** | |

---

## 6. AI Committee Decisions

### Briefing 1: Coordinator + Evidence Bugs (Consensus Achieved)

**Bug 2 — Transport-only downgrade:**
- Auto-downgrade: 403, 404, 405, 410 ✅ IMPLEMENTED
- Not auto-downgraded: 400 (v1 exclusion), 401 (surface discovery), 200/3xx (ambiguous), 5xx (suspicious)
- All three AIs agreed independently

**Bug 1 — Graveyard dedup:**
- `recentFinalized` TTL map storing ALL outcomes (alerted, downgraded, suppressed) ✅ IMPLEMENTED
- TTL: 300 seconds
- Late siblings check graveyard before creating investigations
- All three AIs agreed independently

**403 nuance:**
- Clean-path 403 = surface discovery (don't blanket-suppress upstream)
- Payload-bearing 403 = attack blocked (safe to downgrade in evidence check)
- the team identified, code review and  confirmed

### Briefing 2: Dual-Gate Body Preview (Awaiting Responses)

**5 options presented (A through E):**
- A: Same body hash confidence boost
- B: Separate LLM-confidence from email-confidence (the team's recommendation)
- C: Always populate SafeBodyPreview with confidence flag
- D: Improve orphan matching to reduce candidate count
- E: Combination (D + A + B)

**Status:** Briefing sent to code review and /. Awaiting independent reviews.

---

## 7. Known Issues Remaining

| Issue | Priority | Description |
|-------|----------|-------------|
| Body inspection blocked by dual-gate | HIGH | Namespace capture always produces low correlation confidence → SafeBodyPreview never populated → LLM re-classification never fires for 200 responses. Committee briefing sent. |
| Clean-path 403 over-suppressed | MEDIUM | `isFailedProbe()` currently suppresses clean 403s like 404s. Research says 403 is surface discovery. Fix: reclassify as low-severity finding when SQLite store exists. |
| Method gating in isFailedProbe | MEDIUM | Currently suppresses all HTTP methods. Should only suppress GET/HEAD. POST/PUT/PATCH/DELETE carry body payloads. |
| Volume-based scanner detection | MEDIUM | No alert when single IP generates >12 suppressed probes in 90s. Industry standard (OSSEC/Wazuh pattern). |
| Header payload scanning | MEDIUM | Path/query-only inspection misses Log4Shell (User-Agent), Struts (Content-Type). Low-cost regex on User-Agent/Referer. |
| CapRover default server block | LOW | Returns 200 for unrecognized Host headers. Need 444 for unrecognized hosts. |
| REC pair misses | LOW | 100% pair miss rate on namespace capture (ingress SNAT). Transport-only downgrade mitigates for 4xx. Body inspection fix needed for 200s. |
| SQLite store | FUTURE | Schema designed, not built. Blocks outcome clustering, scanner sessions, telemetry. |
| Outcome clustering | FUTURE | Same IP + same body hash + short window = one finding. Requires SQLite. |
| Tier 3 forensic narrative | FUTURE | Higher-effort LLM call for confirmed intrusions. Only matters once body inspection works. |

---

## 8. Deployment Cheat Sheet

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

## 9. Architecture Principles (Updated)

- **Transport is the first oracle.** A 404 on an attack payload means the attack failed. Don't wait for the body to confirm what the status code already proved.
- **The graveyard remembers everything.** Alerted, downgraded, suppressed — late siblings check the graveyard and die silently. One attack = one finding = one email max.
- **Sensitive paths always get a vote.** `.env`, `.git`, `/actuator`, `/containers/json` — never auto-suppressed, always routed through the intelligent pipeline.
- **The dual-gate serves the email, not the LLM.** Humans need high-confidence bodies. The LLM is robust to ambiguity — it can work with a probable body and fail safely.
- **Design for your deployment topology.** The dual-gate assumed paired capture. Namespace capture changed the game. Architecture must adapt to how the system actually runs, not how it was first imagined.
- **403 has two meanings.** Clean-path 403 = surface discovery (the attacker learned something). Payload-bearing 403 = attack blocked (the server defended itself). Same status code, different pipeline stages, different conclusions.
- **Committee consensus is the strongest signal.** Three AIs agreeing independently on architecture is rare. When it happens, ship it.
