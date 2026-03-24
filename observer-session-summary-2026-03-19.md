# Observer Development Session Summary

**Date:** March 19, 2026
**Previous Session:** March 18, 2026
**Purpose:** Capture all decisions, fixes, deployments, and next steps from this session.

---

## 1. What Was Accomplished

### Phase 1: Normalizer Overhaul (The Original Gameplan)

**Problem:** Docker framing (8-byte stream header + ISO timestamp prefix) was being stripped independently in three different normalizers (docker.go, nginx.go, generic.go), each slightly differently. This caused nginx access logs to hash inconsistently — the same attack from two different requests produced different hashes, meaning the second request hit the LLM instead of caching.

**Fix: Upstream Docker Framing Strip**
- Added `stripCollectorFraming()` to `normalizer.go` — runs once in `NormalizeEvent()` before any normalizer sees the line
- Gutted `docker.go` — now just delegates to GenericNormalizer (framing handled upstream)
- Cleaned `generic.go` — removed Docker header check and unused `reDockerHeader` regex
- Cleaned `nginx.go` — removed all Docker framing code

**Fix: Nginx Access Log Stability**
- Rewrote access log normalization with a smarter split approach: parse the request line first, then replace ALL trailing quoted fields (referrer, user-agent, x-forwarded-for) with `"<VAR>"` using a single `reQuotedField` regex
- Added `reTrailingStatusBytes` regex for byte count stripping after the request line split
- Old approach had a specific user-agent regex that missed unknown agents — new approach catches everything

**Fix: Worker Process Numbers**
- Added `reNginxProcessNum` regex (`process \d+` → `process <NUM>`) to the error normalizer
- Now `start worker process 30/31/32` all hash identically

**Normalizer Test Harness (New: `normalizer_test.go`)**
- 8 test functions, 24 subtests covering:
  - Docker framing strip consistency
  - Access log stability across timestamps, IPs, byte counts, user-agents, referrers
  - Error log stability across PIDs, connection IDs, client IPs
  - Docker-timestamp-plus-nginx-access regression test (the original bug)
  - Worker process normalization
  - Registry fuzzy lookup verification
  - Over-normalization collision detection (different attacks must NOT hash the same)
- All 24 tests pass in 3ms

---

### VerdictAlert: Proper Alert Hash Caching

**Problem:** When the LLM classified a log as "suspicious/alert", the verdict was not cached. Every identical suspicious line hit the LLM again — wasting calls on lines it had already evaluated.

**Initial Fix (rejected by code review):** Store alert hashes in the deny bucket. code review correctly identified the semantic mismatch — first hit returned `VerdictUnknown` (because `mapActionToVerdict` didn't handle "alert"), repeat hits returned `VerdictDeny`. Inconsistent.

**Proper Fix (all three AIs agreed):**
- Added `VerdictAlert` as a first-class verdict type in patternstore
- Added `Alert` bucket to `ScopeEntry` (now four buckets: allow/deny/alert/suppress)
- Added `AlertHits` to stats tracking
- Alert bucket checked between deny and allow in `Match()` priority order
- `mapActionToVerdict("alert")` → `VerdictAlert` (was falling through to `VerdictUnknown`)
- Alert hashes learned as `VerdictAlert` (not `VerdictDeny`)
- `main.go` handles `VerdictAlert` with `[SUSPICIOUS]` log + `SeveritySuspicious` notification
- Cleaned up `VerdictUnknown` case — no longer handles suspicious (that's `VerdictAlert` now)
- Renamed `NormalizerHits` → `PatternHits` (code review caught the misleading name)
- Updated `getBucket`, `getOrCreateScope`, `load`, `recompileAll`, `GetStats` for new bucket
- **Result:** First `;ls+-la` access log hits LLM once, every repeat is instant `[SUSPICIOUS]` with zero LLM cost

**Test Results After VerdictAlert:**
```
processed=24  pattern_hits=23  llm_calls=1  llm_errors=0
deny=6  alert=3
```
Second batch: 12 new lines, 12 pattern hits, 0 LLM calls. **100% cache hit rate.**

---

### Phase 2: Normalization Hints in LLM Response

**Concept:** We're already paying for the LLM call. The model is already reading the log line. Ask one more question: "what parts of this line are variable?"

**Implementation:**
- Added `VariableField` struct to `llm/client.go` with `Token`, `Type`, `Replacement` fields
- Added `variable_fields` to the Verdict struct and LLM prompt with examples
- New file: `internal/normalizer/hints.go` — `HintCollector` that accumulates hints per source key
- After 20 LLM responses for the same source, if 60%+ agree on a variable type, logs:
  ```
  [hints] Suggestion for docker:my-app: field type "pid" seen in 17/20 lines, example: "31#31:" → "<PID>:"
  ```
- No auto-generation — just data for developers to use when writing normalizers
- Wired into analyzer: after every LLM call, any `variable_fields` get fed to the HintCollector

---

### Source Hint Matching Fix for Docker Swarm Names

**Problem:** CapRover uses Docker Swarm, so container names look like `captain-nginx.1.hjfscqq05nqtarebk0ps5xsgo`. The LLM returns verbose hints like `"nginx access logs in docker container"`. The old fuzzy matcher checked if either full string contained the other — always failed because both were long and wrapped in extra words.

**Fix:** New `sourceHintMatches()` function with multi-strategy matching:
1. Direct containment (handles simple cases)
2. Extract short name before first `.` → `captain-nginx`
3. Split short name by `-` and check meaningful segments (≥4 chars, not filler words)
4. Reverse: tokenize the hint and check if meaningful words appear in the source name
5. Filler word filter: ignores "docker", "container", "access", "logs", "service", etc.

---

### First Production Deployment

**GitHub Repo:** `github.com/VaultGuardian/logwatch` (private)
- Set up repo with `gh repo create`
- Cross-compile: `GOOS=linux GOARCH=amd64 go build -o observer .`
- GitHub Releases for binary distribution (v0.1 through v0.5)
- Deploy cycle: build locally → tag release → `gh release download` on server → restart systemd

**Production Server:** Kovi test server (Ubuntu, CapRover, 8 Docker containers)
- Observer runs as systemd service at `/usr/local/bin/observer`
- Data persisted to `/var/lib/observer`
- LLM: OpenAI `gpt-5-nano-2025-08-07` ($0.05/1M input tokens)
- Alerts via Resend email to drew@vaultdec.com

**First Real Threats Caught:**
- `/autodiscover/autodiscover.json?@zdi/Powershell` — ProxyShell/ProxyNotShell Exchange RCE scanner
- CensysInspect automated scanning
- Email alerts delivered successfully via Resend

---

### Empty LLM Response Debugging

**Problem:** GPT-5 nano returned `content: ""` with `finish_reason: "length"` and `completion_tokens: 4096`. Nano's internal reasoning consumed the entire token budget, leaving nothing for the actual response.

**Fixes applied:**
- Bumped `max_completion_tokens` from 1024 → 2048 → 4096
- Added `reasoning_effort: "low"` to API request — limits reasoning token budget so nano actually produces output
- Added debug logging: when content is empty, logs the raw API response (first 500 bytes) so we can see `finish_reason` and token usage

**Result:** Zero LLM errors after the `reasoning_effort: "low"` fix.

---

## 2. User Input / Product Strategy Discussion

Three AIs (the team, code review, "the design review") converged on the same conclusion:

**Where human input belongs:**
1. **Triage & Policy** — the dashboard with Allow/Suppress/Deny buttons (future)
2. **Environment context** — "here's what normal looks like for my deployment" (highest leverage)
3. **NOT** normalizers, NOT LLM tuning, NOT individual alert decisions

**Alert severity discussion:**
- Current model: everything bad = "malicious" → email. Not sustainable.
- Correct model: intent (recon/exploit/brute force/post-exploit) × outcome (failed/uncertain/succeeded)
- `/autodiscover` + `404` = recon, don't email. `/autodiscover` + `200` = critical, email NOW.
- Status code survives normalization, so different outcomes produce different hashes → different cached verdicts
- This is a prompt improvement, not an architecture change
- **Not implemented yet** — queued for next session

---

## 3. Production Stats

**After ~30 minutes on Kovi test server:**
```
processed=463  pattern_hits=423  llm_calls=39  llm_errors=19  learned=0
```
- 91% cache hit rate
- LLM calls completely flat after initial learning
- OpenAI cost: less than a penny for the entire session

**After v0.5 (reasoning_effort fix):**
```
processed=10  pattern_hits=10  llm_calls=0  llm_errors=0
```
- 100% cache hit rate on known patterns, zero LLM cost

---

## 4. Release History

| Version | Changes |
|---------|---------|
| v0.1 | Initial release — normalizer fixes, VerdictAlert, hint collector |
| v0.2 | Source hint matching fix for Docker Swarm names |
| v0.3 | Bump max_completion_tokens to 2048 |
| v0.4 | Bump tokens to 4096, debug empty LLM responses |
| v0.5 | Set reasoning_effort to "low", fix empty responses |

---

## 5. Files Changed This Session

| File | Change |
|------|--------|
| `internal/normalizer/normalizer.go` | Added `stripCollectorFraming()` in `NormalizeEvent()` |
| `internal/normalizer/docker.go` | Gutted — delegates to GenericNormalizer |
| `internal/normalizer/generic.go` | Removed Docker header check |
| `internal/normalizer/nginx.go` | Rewrote access log normalization, added worker process number strip |
| `internal/normalizer/normalizer_test.go` | **New** — 8 test functions, 24 subtests |
| `internal/normalizer/hints.go` | **New** — HintCollector for LLM normalization suggestions |
| `internal/patternstore/store.go` | Added VerdictAlert, Alert bucket, AlertHits stat |
| `internal/analyzer/analyzer.go` | VerdictAlert handling, PatternHits rename, hint wiring, sourceHintMatches() |
| `internal/llm/client.go` | VariableField struct, variable_fields prompt, reasoning_effort, debug logging |
| `main.go` | VerdictAlert case, PatternHits rename, alert= in stats log |

---

## 6. Known Issues Remaining

| Issue | Priority | Description |
|-------|----------|-------------|
| Source hint mismatch still blocks pattern learning | High | Improved but some verbose LLM hints still miss. `learned=0` on production. Hash learning works fine though. |
| No intent/outcome classification | High | All bad = "malicious". Need recon vs exploit vs intrusion distinction to prevent alert fatigue. Prompt upgrade. |
| Empty responses on some log formats | Medium | Fixed with `reasoning_effort: "low"` but some unusual formats may still choke nano. Monitor. |
| No exclude for CapRover infra containers | Low | captain-captain, captain-certbot, captain-netdata generate noise. Can exclude via env var. |
| Pattern dedup | Low | Same log pattern can learn multiple similar patterns. Needs "does existing pattern cover this?" check. |
| No degraded-mode alert | Low | If LLM is down for extended period, nobody knows. |

---

## 7. Next Session Priority

1. **Intent/outcome classification** — teach the LLM to distinguish recon (404) vs intrusion (200) and route alerts accordingly
2. **Move to busy production server** — more containers, more real traffic, more diverse log patterns
3. **Fix source hint matching further** — get pattern learning working on production (currently only hash learning)
4. **Exclude CapRover infra containers** — reduce noise from captain-captain, certbot, netdata
5. **Monitor hint collector** — once enough LLM calls accumulate, check for `[hints]` suggestions
6. **Pattern dedup** — prevent redundant pattern learning

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
sudo rm -rf /var/lib/observer/*    # only if pattern store structure changed
sudo systemctl daemon-reload       # only if service file changed
sudo systemctl restart observer
sudo journalctl -u observer -f
```

### Service File Location
```
/etc/systemd/system/observer.service
```

### Key Environment Variables
```
DOCKER_SOCKET=/var/run/docker.sock
DATA_DIR=/var/lib/observer
LLM_URL=https://api.openai.com
LLM_MODEL=gpt-5-nano-2025-08-07
LLM_API_KEY=sk-...
EXCLUDE_CONTAINERS=
RESEND_API_KEY=re_...
ALERT_EMAIL_TO=drew@vaultdec.com
```

---

## 9. Key Principles Reinforced

- **Fix what's broken before building new things** — normalizer fix before hint collector
- **Get free data from existing calls** — variable_fields costs nothing extra per LLM call
- **Separate detection from response** — LLM classifies intent+outcome, routing config decides who gets emailed
- **Three AIs agreeing = strong signal** — VerdictAlert design was validated by the team, code review, and the design review independently
- **User input belongs at the policy level** — not triaging individual alerts, but defining what "normal" means
- **AI vs AI** — attackers use AI to generate novel payloads, Observer uses AI to classify them. Your AI only pays once per technique, their AI has to generate every time. Economic advantage.
