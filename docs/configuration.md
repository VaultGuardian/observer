# Configuration

Observer is configured entirely through environment variables, loaded from
`/etc/vaultguardian/observer.env` (mode `0600`, root-only) by the systemd
unit's `EnvironmentFile=` directive. The installer writes the common ones;
everything below can be added or overridden by editing that file and running
`systemctl restart observer`.

All variables are optional unless noted — Observer ships with working
defaults for every setting.

## Core

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/data` | Pattern store + SQLite persistence directory |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket path for container log streaming |
| `HOSTNAME` | (system hostname) | Server nickname shown in alert emails alongside the IP. The installer's "server nickname" prompt writes this. |
| `JOURNALD_ENABLED` | `false` | Set to `true` to watch the host's systemd journal |
| `JOURNALD_EXCLUDE_UNITS` | (none) | Comma-separated systemd units to suppress, in addition to the built-in noise list |
| `EXCLUDE_CONTAINERS` | (none) | Comma-separated container names to skip |

## LLM

The LLM is consulted only for events the deterministic pipeline hasn't seen
before — typically under 5% of traffic. Defaults point at a local Ollama
instance so logs never leave your network.

| Variable | Default | Description |
|---|---|---|
| `LLM_URL` | `http://llm:11434` | Endpoint. Any OpenAI-compatible `/v1/chat/completions` API works. |
| `LLM_MODEL` | `qwen2.5:7b` | Model name on the endpoint |
| `LLM_API_KEY` | (none) | Only required if your endpoint demands one (cloud providers do; Ollama does not) |
| `LLM_SLOTS` | `4` | Max concurrent LLM requests |
| `LLM_TIER1_EFFORT` | `low` | Reasoning effort for Tier 1 (intent) classification |
| `LLM_TIER2_EFFORT` | `medium` | Reasoning effort for Tier 2 (evidence) review |

To use a cloud provider instead of local Ollama:

```bash
LLM_URL=https://api.openai.com
LLM_MODEL=gpt-5-mini
LLM_API_KEY=sk-xxxxxxxx
```

## Dashboard API

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_PORT` | `9090` | Port the REST API listens on |
| `DASHBOARD_BIND_ADDR` | `127.0.0.1` | Bind address. Loopback-only by default. |
| `DASHBOARD_KEY_FILE` | `/etc/vaultguardian/dashboard.key` | Bearer token file, auto-generated at `0600` on first start |
| `DASHBOARD_ALLOWED_ORIGINS` | (none) | Comma-separated CORS allowlist. Empty = no CORS headers (correct for server-side proxy patterns). |

> The dashboard binds to `127.0.0.1` by default. If you set
> `DASHBOARD_BIND_ADDR=0.0.0.0` to expose it, do so behind a reverse proxy
> with TLS and authentication, and firewall the port to known sources.

## Email alerts (optional)

| Variable | Default | Description |
|---|---|---|
| `RESEND_API_KEY` | (none) | Resend API key for delivery |
| `ALERT_EMAIL_TO` | (none) | Destination address for alert emails |
| `ALERT_EMAIL_FROM` | `VaultGuardian Observer <onboarding@resend.dev>` | Sender address. Must be verified in **your** Resend account. The default uses Resend's sandbox sender, which works without domain setup; switch to your own verified domain once you have one. |

## Response Evidence Capture (REC)

REC sniffs the reverse proxy's network namespace to capture the HTTP
responses your server actually sent, so failed probes can be downgraded and
confirmed impact escalated.

### Core

| Variable | Default | Description |
|---|---|---|
| `REC_ENABLED` | `false` | Master switch for REC |
| `REC_INTERFACE` | (auto) | Interface to sniff; auto-detected if unset |
| `REC_NS_CONTAINER` | (none) | Container whose network namespace REC enters (e.g. `captain-nginx`) |
| `REC_PORTS` | `80,8080` | Comma-separated HTTP ports REC always sniffs |
| `REC_LEARNED_PORT_CAP` | `64` | Cap on runtime-learned ports (`0` disables learning) |
| `REC_VXLAN_PORT` | (auto) | VXLAN port override; auto-detected if unset |
| `REC_VERBOSE` | `false` | Verbose REC diagnostics (debug only) |

### Evidence buffer

| Variable | Default | Description |
|---|---|---|
| `REC_BUFFER_MAX_ENTRIES` | `10000` | Max buffered response entries |
| `REC_BUFFER_MAX_BYTES` | `134217728` (128 MB) | Max total bytes held in the evidence buffer. Static ceiling — sized for scanner-burst headroom. |
| `REC_BUFFER_MAX_AGE` | `30s` | Max age before a buffered entry is evicted |
| `REC_BUFFER_MAX_BODY` | `2048` | Max bytes of response body retained per entry |

### TCP reassembly

| Variable | Default | Description |
|---|---|---|
| `REC_REASSEMBLY_MAX_BODY` | `2048` | Max bytes reassembled per HTTP response |
| `REC_REASSEMBLY_STREAM_TTL` | `5s` | Lifetime of an idle reassembly stream |
| `REC_REASSEMBLY_IDLE_TIMEOUT` | `2s` | Idle timeout before a stream is flushed |
| `REC_REASSEMBLY_MAX_BUFFERED_PAGES_TOTAL` | `4096` | Total reassembly page cap across all streams |
| `REC_REASSEMBLY_MAX_BUFFERED_PAGES_PER_CONN` | `16` | Per-connection reassembly page cap |
| `REC_REASSEMBLY_MAX_ACTIVE_STREAMS` | `10000` | Max concurrent reassembly streams |

### Flow pairing

| Variable | Default | Description |
|---|---|---|
| `REC_FLOW_MAX_STATES` | `50000` | Max tracked request/response flows |
| `REC_FLOW_MAX_REQ_PER_FLOW` | `64` | Max queued requests per flow |
| `REC_FLOW_MAX_RESP_PER_FLOW` | `64` | Max queued responses per flow |
| `REC_FLOW_RESP_ORPHAN_TIMEOUT` | `2s` | How long an orphan response waits for its request |
| `REC_FLOW_REQ_EXPIRE_TIMEOUT` | `30s` | How long a request waits for its response |

## Debugging

| Variable | Default | Description |
|---|---|---|
| `OBSERVER_DEBUG` | (unset) | Set to enable the gated `pprof` profiling endpoints |