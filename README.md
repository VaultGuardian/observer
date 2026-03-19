# VaultGuardian LogWatch

AI-powered container log anomaly detection for edge deployment.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker Host                                            │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Service A │  │ Service B │  │ Service C │  ...        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       │logs          │logs         │logs                │
│       └──────────────┼─────────────┘                    │
│                      ▼                                  │
│  ┌──────────────────────────────────────┐               │
│  │         vg-logwatch                  │               │
│  │                                      │               │
│  │  1. Stream logs via Docker socket    │               │
│  │  2. SHA-256 hash each line           │               │
│  │  3. Check whitelist → skip if known  │               │
│  │  4. Check blacklist → ALERT if match │               │
│  │  5. Unknown → forward to LLM ───────┼──┐            │
│  │  6. LLM verdict → update lists      │  │            │
│  │                                      │  │            │
│  └──────────────────────────────────────┘  │            │
│                                            ▼            │
│                               ┌──────────────────┐     │
│                               │  vg-llm (Ollama)  │     │
│                               │  qwen2.5:7b       │     │
│                               └──────────────────┘     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## How It Works

1. **LogWatch** connects to the Docker socket and streams stdout/stderr from every container
2. Each log line is **SHA-256 hashed** after normalizing timestamps
3. **Whitelist check** — known-good hashes are skipped instantly (nanoseconds)
4. **Blacklist check** — known-bad hashes + pattern matching trigger immediate alerts
5. **Unknown lines** get forwarded to a local LLM for classification
6. The LLM returns a structured verdict: `safe/suspicious/malicious` + action
7. Based on the verdict, the hash is added to whitelist or blacklist
8. Over time, the system **learns your baseline** and the LLM gets called less and less

## Quick Start

```bash
# 1. Start the stack
docker compose up -d

# 2. Pull the LLM model (first time only)
docker exec vg-llm ollama pull qwen2.5:7b

# 3. Check logs
docker logs -f vg-logwatch
```

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Path to Docker socket |
| `DATA_DIR` | `/data` | Persistence dir for whitelist/blacklist |
| `LLM_URL` | `http://llm:11434` | LLM inference endpoint |
| `LLM_MODEL` | `qwen2.5:7b` | Model name for Ollama |

## Jetson / Edge Deployment

For Nvidia Jetson, uncomment the GPU passthrough section in `docker-compose.yml`:

```yaml
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: all
          capabilities: [gpu]
```

## Blacklist Patterns (Seeded)

The app comes with default patterns for common attack indicators:
- Shell injection: `rm -rf /`, `chmod 777`, reverse shells
- Path traversal: `../../etc/passwd`, `/etc/shadow`
- SQL injection: `UNION SELECT`, `DROP TABLE`
- Command chaining: `curl | sh`, `wget | sh`, `base64 -d | bash`

Add custom patterns by editing the `seedBlacklistPatterns()` function in `main.go` or via the persistent `patterns.json` file.

## Project Structure

```
├── main.go                      # Entry point, pipeline wiring
├── internal/
│   ├── analyzer/
│   │   └── analyzer.go          # Hash, whitelist, blacklist engine
│   ├── watcher/
│   │   └── watcher.go           # Docker socket log streaming
│   └── llm/
│       └── client.go            # LLM inference client (OpenAI-compat)
├── Dockerfile                   # Multi-stage build
├── docker-compose.yml           # Full stack: logwatch + Ollama
└── README.md
```

## Next Steps

- [ ] HTTP API for managing whitelist/blacklist manually
- [ ] Webhook/Slack/email alerting on blacklist hits
- [ ] Web dashboard for real-time log monitoring
- [ ] Rate limiting on LLM calls during log floods
- [ ] Log batching (send N lines to LLM at once instead of one-by-one)
- [ ] Admin SSH session whitelist (by source IP or user)
