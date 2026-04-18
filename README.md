# Observer

**Detects attacks. Verifies outcomes. Learns over time.**
Low-noise intrusion detection for Linux servers.

---

Observer watches your Docker container logs and host system events (sshd, sudo, kernel), classifies threats using an LLM, captures HTTP response evidence, and verifies whether attacks actually succeeded — before waking you up.

Most security tools scream "SQL injection detected!" when a bot sprays your server. Observer captures the server's response, reads it, and tells you "the app returned its welcome page and ignored the payload." One accurate finding instead of fifty false alarms.

## Install

One command on any Linux server with Docker:

```bash
curl -fsSL https://raw.githubusercontent.com/VaultGuardian/observer/main/install.sh | sudo bash
```

The installer prompts for your OpenAI API key and alert email, sets up the systemd service, and starts Observer. You'll need a GitHub account with access to the repo (private beta).

After install, manage with the CLI:

```bash
vaultguardian status          # Service status + recent logs
vaultguardian logs            # Tail logs
vaultguardian stats           # Pipeline performance
vaultguardian update          # Update to latest release
vaultguardian update v0.35    # Update to specific version
vaultguardian restart         # Restart observer
vaultguardian version         # Current + available versions
vaultguardian uninstall       # Remove observer
```

## How It Works

```
Log line arrives (Docker container or journald)
  → Deterministic filters (stack traces, failed HTTP probes)
  → Policy engine (SSH logins, user creation, privilege escalation)
  → Pattern store (nanosecond hash/prefix/regex/contains lookup)
    → Known-good? Skip silently.
    → Known-noise? Suppress silently.
    → Known-bad? → Coordinator holds for evidence
    → Unknown? → LLM classifies → learns pattern → next time is instant

If alert-worthy:
  → REC captures the HTTP response from inside the container namespace
  → Structural redaction (keep visible text, strip secrets)
  → Re-classify with evidence: "Did the attack succeed or get ignored?"
  → Downgraded? Log it, don't email.
  → Confirmed credential exposure? Email immediately.
```

## What It Catches

**Policy engine (deterministic, pre-LLM):**
- SSH login from unknown IP → instant email alert
- New user created (`useradd`) → escalation
- Privilege grant (`usermod -aG sudo`) → escalation
- SSH authorized_keys modification → escalation
- Failed sudo attempts → alert

**LLM classification (learns over time):**
- SQL injection, shell injection, PHP wrappers, encoded exploits
- Path traversal, reconnaissance probes
- Successful vs failed attack outcomes (intent × outcome)
- Protocol mismatches, binary probes, scanner noise

**Deterministic suppression (never hits the LLM):**
- Application stack traces (Node.js, Python, Go, Java)
- Failed HTTP probes (404/403/405/400 with no attack payload)
- SSH brute force (thousands/day on every public server)
- Nginx file-not-found errors
- Firewall blocks (UFW/iptables)

## What Makes It Different

- **Evidence-aware.** Captures HTTP responses and verifies whether attacks succeeded. A `200 OK` with a welcome page is different from a `200 OK` with your database credentials.
- **Intent × outcome.** "Attacker probed and got nothing" (suppress) vs "attacker probed and got data" (email immediately).
- **Learns over time.** First novel log line: LLM call (~3s, fraction of a cent). Every repeat: cache hit (nanoseconds, free). Cache rates reach 97%+ within hours.
- **Low noise by design.** Failed scanners suppressed. SSH brute force invisible. Duplicate alerts grouped. False alarms downgraded with evidence.
- **Single binary, no dependencies.** One Go binary, one systemd service. No Docker-in-Docker, no sidecar, no cloud requirement.
- **Trusted IP allowlist.** Known IPs (your office, VPN) bypass SSH alerts. Unknown IP logs in → instant email.

## Production Numbers

Real production stats from a server running Observer for 30 days:

| Metric | Value |
|--------|-------|
| Events processed | 145,000+ |
| Cache hit rate | 97% |
| Total LLM calls | 354 |
| LLM errors | 3 |
| Total OpenAI spend | ~$17 lifetime |
| False alarm emails | 0 |
| Real escalations caught | 1 (.env credential exposure) |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_URL` | `https://api.openai.com` | LLM API endpoint (OpenAI-compatible) |
| `LLM_MODEL` | `gpt-5-nano-2025-08-07` | Model for classification |
| `LLM_API_KEY` | | API key for the LLM provider |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket path |
| `DATA_DIR` | `/data` | Pattern store + SQLite persistence |
| `EXCLUDE_CONTAINERS` | | Comma-separated container names to skip |
| `RESEND_API_KEY` | | Resend API key for email alerts |
| `ALERT_EMAIL_TO` | | Alert recipient email address |
| `REC_ENABLED` | `false` | Enable Response Evidence Capture |
| `REC_NS_CONTAINER` | | Container name for namespace capture (e.g. `captain-nginx`) |
| `JOURNALD_EXCLUDE_UNITS` | | Additional systemd units to suppress |

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │  Observer (single Go binary)                │
                    │                                             │
  Journald ────────▶│  Journald     ┌──────────┐                 │
  (sshd, sudo,      │  Watcher  ──▶│           │                 │
   kernel)           │              │ Normalize │                 │
                    │              │     │      │                 │
  Docker API ──────▶│  Docker   ──▶│  Policy   │                 │
  (container logs)  │  Watcher     │  Engine   │                 │
                    │              │     │      │                 │
                    │              │  Pattern   │                 │
                    │              │  Store     │                 │
                    │              │     │      │                 │
                    │              │  LLM ──────│──▶ OpenAI      │
                    │              │     │      │                 │
                    │              │ Coordinator│                 │
  AF_PACKET ───────▶│  REC ───────▶│  (evidence │──▶ Email alert │
  (namespace sniff) │  Sniffer     │   huddle)  │                │
                    │              └──────────┘                 │
                    └─────────────────────────────────────────────┘
```

### Pipeline Layers

1. **Deterministic filters** — Stack traces, failed HTTP probes, SSH brute force. Regex-free structural detection. Never touches the LLM.
2. **Policy engine** — SSH logins, user creation, privilege escalation, authorized_keys. Identity-based decisions with trusted IP allowlist.
3. **Pattern store** — 4-bucket model (allow/malicious/alert/suppress), 4-tier matching (hash → prefix → regex → contains). Nanosecond lookups.
4. **LLM classifier** — OpenAI-compatible API. Intent × outcome classification. Learns patterns from verdicts. Bounded retry queue for backpressure.
5. **REC (Response Evidence Capture)** — AF_PACKET sniffer inside the reverse proxy's network namespace. Captures HTTP responses, redacts secrets, correlates with alerts.
6. **Coordinator** — Groups alerts, holds for evidence (2-5s), downgrades false alarms, dispatches findings. Email only on confirmed credential exposure.
7. **Catch-all suppression** — Learns server fingerprints (host, status, body size). Auto-downgrades repeated identical responses across different attack paths.

## Dashboard

Observer includes a web dashboard at `http://your-server:9090` showing:

- **Overview** — Security outcomes (escalations, blocked, downgraded, needs review) and system health
- **Events** — Every security event with AI classification, evidence, confirm/correct buttons
- **Internals** — LLM decision audit trail, pattern store stats, REC metrics
- **Settings** — Trusted IP management, active policy rules

Access is protected by a randomly generated key stored at `/etc/vaultguardian/dashboard.key`.

## Project Structure

```
├── main.go                           # Pipeline wiring, coordinator, retry queue
├── seeds.go                          # Curated malicious pattern seeds
├── resultrouter.go                   # Shared classification outcome handler
├── config.go                         # Environment variable configuration
├── install.sh                        # One-command installer
├── internal/
│   ├── analyzer/                     # Normalize → match → classify → learn
│   ├── api/                          # Dashboard REST API + static files
│   ├── coordinator/                  # Evidence huddle + catch-all suppression
│   ├── event/                        # Canonical event model
│   ├── llm/                          # LLM client, Tier 1 + Tier 2 prompts
│   ├── normalizer/                   # Source-specific log normalization
│   │   ├── nginx.go                  # Nginx access + error logs
│   │   ├── sshd.go                   # SSH auth logs
│   │   ├── postgres.go               # PostgreSQL logs
│   │   ├── syslog.go                 # Syslog envelope
│   │   ├── docker.go                 # Docker framing
│   │   └── generic.go                # Fallback normalizer
│   ├── notifier/                     # Email (Resend), webhook, SMS, push
│   ├── patternstore/                 # 4-bucket, 4-tier pattern matching
│   ├── policy/                       # Deterministic pre-LLM policy engine
│   ├── rec/                          # Response Evidence Capture (AF_PACKET)
│   ├── store/                        # SQLite persistence (findings, decisions)
│   └── watcher/                      # Docker + journald log streaming
├── Dockerfile
├── docker-compose.yml
├── go.mod / go.sum
└── README.md
```

## Build from Source

```bash
# Clone
git clone https://github.com/VaultGuardian/observer.git
cd observer

# Test
go test ./...

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o observer .
```

## Contributing

Observer's normalizers are the primary contribution path. Each normalizer teaches Observer to recognize a specific service's log format, improving hash-hit rates and reducing LLM calls.

Observer works with everything out of the box via the generic normalizer. Service-specific normalizers make it faster and cheaper.

To add a normalizer:
1. Create `internal/normalizer/yourservice.go` implementing the `Normalizer` interface
2. Register it in `normalizer.go`
3. Add tests in `normalizer_test.go`

## Open Core

Observer's detection engine is open source. The full pipeline — classification, evidence capture, re-classification, pattern learning, policy engine, and local deployment — is free and unrestricted.

Future commercial offerings (fleet dashboard at [app.vaultguardian.io](https://app.vaultguardian.io), multi-server management, long-term retention, team workflows) are separate.

## License

TBD

---

*Part of the [VaultGuardian](https://vaultguardian.io) ecosystem. Observer detects the intrusion. [DEC-1](https://vaultguardian.io) stops the data from leaving.*