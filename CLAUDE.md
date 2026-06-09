# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ground rules

- **Never commit, never branch — always hand back uncommitted.** The operator reviews and commits all changes themselves.
- Never run `release.sh`.

## Commands

```bash
go build ./...                                  # build everything
go test ./...                                   # run all tests
go test ./internal/store/ -run TestName -v     # run a single test
```

No Makefile. Pure Go — SQLite via `modernc.org/sqlite`, no CGO required.

## Architecture

Observer (module `github.com/vaultguardian/observer`) is a single Go binary that watches Docker/journald logs, classifies suspicious activity, and captures the server's HTTP response to determine whether an attack actually worked. Design principle: **deterministic-first** — the LLM sees only events nothing else could classify (<5% of traffic), and **email only on confirmed impact**.

Pipeline (one log line's journey):

```
watcher (Docker / journald)
  → deterministic filters (stack traces, failed probes, SSH brute force)
  → policy engine (SSH logins, user creation, privilege escalation)
  → seed patterns (credential dumps, reverse shells — hard-coded, no LLM)
  → pattern store (4 buckets [allow/malicious/alert/suppress] × 4 tiers
                   [hash → prefix → regex → contains]; known events end here)
  → LLM classifier (unknowns only; local Ollama default, results cached)
  → coordinator (holds malicious findings 2–5s waiting for response evidence)
  → REC (AF_PACKET sniffer in the reverse proxy's network namespace;
         TCP reassembly, HTTP response capture)
  → verdict: recon (downgraded, no email) / alert / malicious (email)
             / evidence_unavailable (logged honestly)
```

### Layout

- Root package: main wiring — `config.go`, `llmscheduler.go`, `resultrouter.go`, `reclasscache.go`, `seeds.go`, `httpparse.go`. The evidence callback (`main.go: makeEvidenceCheckCallback`) is where evidence-driven reclassification is orchestrated.
- `internal/watcher`, `internal/normalizer`, `internal/event` — log ingestion and normalization.
- `internal/policy`, `internal/patternstore` — deterministic classification layers.
- `internal/llm`, `internal/analyzer` — LLM client and classification logic.
- `internal/coordinator` — request/response correlation, hold-for-evidence, expected-endpoint tracker.
- `internal/rec` — Runtime Evidence Collector: per-public-container namespace packet captures (Docker-specific), discovered via dry-run Docker inspection; host-interface capture is a degraded fallback, not equivalent coverage.
- `internal/store` — SQLite persistence; schema migrations live in `store.go`.
- `internal/api` — dashboard API server (bearer-token auth, localhost bind by default).
- `internal/notifier` — email dispatch.

## Load-bearing invariants

- **ExpectedEndpoint ordering (reclassify path):** the expected-endpoint short-circuit must run **after redaction** (its match key is the REDACTED response-shape hash, `rec.HashBody(SafeBodyPreview)` — raw transport hashes rotate with tokens) but **before the reclass cache and before the LLM** (operator-explicit truth beats both; a stale cached "token-looking = malicious" verdict must not pre-empt an operator-confirmed downgrade). See `internal/coordinator/expected_endpoint.go` header comment. Any refactor of the evidence callback / T2 router must preserve this ordering.
- **Findings resolution lifecycle** (`internal/store/findings.go: UpdateFindingResolution`): only findings with empty/pending/NULL `resolution_status` may be resolved; a trusted `resolved` may additionally heal `evidence_unavailable`. Resolution transitions are monotonic by trust — the timeout reconciler must never clobber a resolved row.
- **LLM decisions are immutable originals** (`internal/store/llm_store.go`): the model's response is never edited. Human review lives in separate `review_*` columns — the gold dataset for corrections and future fine-tuning. Reviewed decisions are never auto-pruned.
- **REC namespace capture is Docker-specific:** host-network-mode containers bypass the reverse-proxy namespace entirely (the original candidates=0 → SUSPICIOUS bug); the app-log fallback is the cross-platform path. All-namespaces-failed means DEGRADED/blind, not covered.
