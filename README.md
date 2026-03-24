# Observer

**Detects attacks. Verifies outcomes.**
Low-noise intrusion detection for Linux workloads.

---

Observer watches container logs (and soon host services via journald), classifies threats using an LLM, captures HTTP response evidence, and verifies whether attacks actually succeeded — before waking you up.

Most security tools scream "SQL injection detected!" when a bot sprays your server. Observer captures the server's response, reads it, and tells you "the app returned its welcome page and ignored the payload." One accurate finding instead of fifty false alarms.

## How It Works

```
Log line arrives
  → Normalize (strip timestamps, IPs, variable content)
  → Pattern store check (nanosecond hash/prefix/regex/contains lookup)
    → Known-good? Skip silently.
    → Known-noise? Suppress silently.
    → Known-bad? → Coordinator holds for evidence (2-5s)
    → Unknown? → LLM classifies → learns pattern → next time is instant

If alert-worthy:
  → REC captures the HTTP response from inside the container namespace
  → Structural redaction (keep visible text, strip secrets)
  → Re-classify with evidence: "Did the attack succeed or get ignored?"
    → Cache hit? Instant verdict, zero LLM cost.
    → Cache miss? LLM re-evaluates with the response body.
  → Downgraded? Log it, don't email.
  → Confirmed? Alert with evidence attached.
```

The system gets **cheaper as it learns**. First time seeing an attack technique: LLM call (~2s). Every repeat: cache hit (nanoseconds, free). First time seeing a response body: LLM re-classification. Every repeat with the same body: cached verdict (free).

## What Makes It Different

- **Evidence-aware.** Captures HTTP responses and uses them to verify whether attacks succeeded. A `200 OK` with a welcome page is different from a `200 OK` with your database.
- **Intent × outcome classification.** Distinguishes "attacker probed and got nothing" (suppress) from "attacker probed and got data" (alert immediately).
- **Learns over time.** LLM classifies novel log lines once, then the pattern store handles all repeats at zero cost. Your bill shrinks as the system gets smarter.
- **Low noise by design.** Failed scanners are suppressed. Duplicate alerts from multiple containers are grouped. False alarms are downgraded with evidence. You only hear about things that matter.
- **Single binary, no dependencies.** One Go binary, systemd service, no Docker-in-Docker, no sidecar containers, no cloud requirement.
- **Three deployment topologies, auto-detected:**

| Deployment | How REC captures HTTP | Config needed |
|---|---|---|
| docker-compose | Host AF_PACKET socket | Just `REC_ENABLED=true` |
| Multi-node Swarm | VXLAN decapsulation (RFC 7348) | Auto-detected |
| Single-node Swarm | Namespace capture via `setns` | `REC_NS_CONTAINER=captain-nginx` |

## Quick Start

### As a systemd service (production)

```bash
# Build (from your dev machine)
GOOS=linux GOARCH=amd64 go build -o observer .

# Copy to server
scp observer yourserver:/usr/local/bin/observer

# Create service file
sudo tee /etc/systemd/system/observer.service << 'EOF'
[Unit]
Description=VaultGuardian Observer
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/local/bin/observer
Restart=always
RestartSec=5

# Core config
Environment=DOCKER_SOCKET=/var/run/docker.sock
Environment=DATA_DIR=/var/lib/observer
Environment=LLM_URL=https://api.openai.com
Environment=LLM_MODEL=gpt-5-mini-2025-08-07
Environment=LLM_API_KEY=sk-your-key-here

# Alerts
Environment=RESEND_API_KEY=re_your-key-here
Environment=ALERT_EMAIL_TO=you@example.com

# Response Evidence Capture (opt-in)
Environment=REC_ENABLED=true
Environment=REC_NS_CONTAINER=captain-nginx

# Capabilities
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable observer
sudo systemctl start observer
sudo journalctl -u observer -f
```

### With Docker Compose (development/testing)

```bash
docker compose up --build
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket path |
| `DATA_DIR` | `/var/lib/observer` | Pattern store persistence |
| `LLM_URL` | `https://api.openai.com` | LLM API endpoint (OpenAI-compatible) |
| `LLM_MODEL` | `gpt-5-mini-2025-08-07` | Model for classification |
| `LLM_API_KEY` | | API key for the LLM provider |
| `EXCLUDE_CONTAINERS` | | Comma-separated container names to skip |
| `RESEND_API_KEY` | | Resend API key for email alerts |
| `ALERT_EMAIL_TO` | | Alert recipient email address |
| `REC_ENABLED` | `false` | Enable Response Evidence Capture |
| `REC_NS_CONTAINER` | | Container name pattern for namespace capture (e.g. `captain-nginx`) |
| `REC_INTERFACE` | | Network interface to capture on (empty = all) |
| `REC_VXLAN_PORT` | auto-detect | VXLAN port override (default: detected from Docker Swarm API) |

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  Observer (single Go binary)            │
                    │                                         │
  Docker API ──────▶│  Watcher ──▶ Normalizer ──▶ Pattern    │
  (container logs)  │                             Store      │
                    │                              │          │
                    │                     miss?    │          │
                    │                              ▼          │
                    │                          LLM Client ───▶│──▶ OpenAI / Ollama / etc.
                    │                              │          │
                    │                     learn    │          │
                    │                              ▼          │
                    │              ┌─── Coordinator ───┐      │
                    │              │  (forensic huddle) │      │
                    │              │  holds 2-5s for    │      │
  AF_PACKET ───────▶│  REC ────▶  │  evidence before   │──────▶ Email / Webhook / SMS
  (namespace sniff) │  Sniffer    │  dispatching       │      │
                    │              └────────────────────┘      │
                    └─────────────────────────────────────────┘
```

### Pipeline Detail

1. **Watcher** streams container logs via Docker socket
2. **Normalizer** strips variable content (timestamps, IPs, PIDs) for stable hashing. Source-specific normalizers for nginx, sshd, postgres. Generic fallback for everything else.
3. **Pattern Store** — 4-bucket model (allow/deny/alert/suppress), 4-tier matching (hash → prefix → regex → contains). Nanosecond lookups.
4. **LLM Client** — OpenAI-compatible API. Intent × outcome classification. Learns patterns from verdicts. Reconciles contradictory fields.
5. **REC (Response Evidence Capture)** — AF_PACKET sniffer inside the reverse proxy's network namespace. Captures HTTP responses, redacts secrets, correlates with alerts.
6. **Coordinator** — Groups alerts from multiple containers into one investigation. Holds for 2-5 seconds to collect evidence. Downgrades false alarms. Dispatches one accurate finding.
7. **Re-Classification Cache** — Keyed on redacted body hash. Same response body = same conclusion. Zero LLM cost on repeat.

### Seeded Deny Patterns

Observer ships with curated attack indicators:

- Shell injection: `rm -rf /`, `chmod 777`, reverse shells (`nc -e`, `bash -i >& /dev/tcp`)
- Path traversal: `../../etc/passwd`, `/etc/shadow`
- SQL injection: `UNION SELECT`, `DROP TABLE`
- Command injection: `; ls -la`, `&& cat /etc`
- Remote code execution: `curl | sh`, `wget | sh`, `base64 -d | bash`
- Reconnaissance: `phpinfo()`, `.bash_history`, `authorized_keys`

These trigger instant deny verdicts. The LLM handles everything else.

## Project Structure

```
├── main.go                           # Pipeline wiring, coordinator, cache
├── internal/
│   ├── coordinator/
│   │   └── coordinator.go            # Forensic huddle — hold alerts for evidence
│   ├── rec/
│   │   ├── sniffer.go                # AF_PACKET raw socket HTTP capture
│   │   ├── nsenter.go                # Network namespace capture via setns
│   │   ├── vxlan.go                  # VXLAN decapsulation (RFC 7348)
│   │   ├── redaction.go              # Structural redaction (HTML/JSON/dotenv/passwd)
│   │   ├── buffer.go                 # Multi-constraint ring buffer
│   │   ├── collector.go              # Evidence collector interface + live/noop
│   │   ├── types.go                  # Evidence, confidence, format types
│   │   ├── capability.go             # CAP_NET_RAW check
│   │   ├── bpf.go                    # BPF kernel filter (reference stub)
│   │   └── vxlan_test.go             # VXLAN decap tests
│   ├── analyzer/
│   │   └── analyzer.go               # Normalize → match → classify → learn
│   ├── normalizer/
│   │   ├── normalizer.go             # Registry with fuzzy service matching
│   │   ├── nginx.go                  # Nginx access + error log normalizer
│   │   ├── generic.go                # Fallback: timestamps, IPs, UUIDs
│   │   ├── docker.go                 # Docker framing strip
│   │   ├── sshd.go                   # SSH auth log normalizer
│   │   ├── postgres.go               # PostgreSQL log normalizer
│   │   ├── syslog.go                 # Syslog envelope normalizer
│   │   ├── hints.go                  # LLM normalization hint collector
│   │   └── normalizer_test.go        # 28 normalizer tests
│   ├── patternstore/
│   │   └── store.go                  # 4-bucket, 4-tier pattern matching
│   ├── llm/
│   │   └── client.go                 # LLM client + re-classification
│   ├── notifier/
│   │   ├── notifier.go               # Alert dispatch
│   │   ├── email.go                  # Resend email alerts
│   │   ├── webhook.go                # Webhook alerts
│   │   ├── sms.go                    # Twilio SMS
│   │   ├── apns.go                   # Apple push notifications
│   │   ├── fcm.go                    # Firebase push notifications
│   │   └── config.go                 # Notification config loader
│   ├── watcher/
│   │   └── watcher.go                # Docker socket log streaming
│   └── event/
│       └── event.go                  # Canonical event model
├── Dockerfile
├── docker-compose.yml
├── go.mod
└── go.sum
```

## Testing

```bash
# Run all tests
go test ./internal/... -v

# VXLAN decapsulation tests only
go test ./internal/rec/ -run TestDecapVXLAN -v

# Normalizer tests only
go test ./internal/normalizer/ -v
```

## Build & Deploy

```bash
# Build for Linux
GOOS=linux GOARCH=amd64 go build -o observer .

# Release via GitHub
gh release create v0.X ./observer --title "Observer v0.X" --notes "description"

# Deploy
gh release download v0.X --repo YourOrg/logwatch --pattern "observer"
sudo mv observer /usr/local/bin/observer
sudo chmod +x /usr/local/bin/observer
sudo systemctl restart observer
```

## Roadmap

- [x] Docker container log watching
- [x] LLM classification with pattern learning
- [x] Intent × outcome classification (recon_failed vs recon_success)
- [x] Response Evidence Capture (namespace + VXLAN)
- [x] Structural redaction (HTML/JSON/dotenv/passwd)
- [x] Evidence-aware re-classification
- [x] Re-classification caching
- [x] Forensic huddle coordinator
- [ ] Journald watcher (SSH, systemd, host-level events)
- [ ] Integration configs (YAML service definitions)
- [ ] LLM circuit breaker (degraded-mode alerting)
- [ ] BPF kernel filtering (CPU optimization)
- [ ] Admin API for pattern management
- [ ] Web dashboard

## Open Core

Observer's core engine is open source. The detection pipeline, evidence capture, re-classification, and local deployment are free and unrestricted.

Future commercial add-ons (fleet management, centralized dashboard, long-term retention, team workflows) will be separate.

## License

TBD

---

*Part of the [VaultGuardian](https://vaultguardian.io) ecosystem. Observer detects the act. [DEC-1](https://vaultguardian.io) stops the data from leaving.*