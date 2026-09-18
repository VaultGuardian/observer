# Configuration

Observer is configured entirely through environment variables, loaded from
`/etc/vaultguardian/observer.env` (mode `0600`, root-only) by the systemd
unit's `EnvironmentFile=` directive. The installer writes the common ones;
everything below can be added or overridden by editing that file and running
`systemctl restart observer`.

Tables show **binary defaults**. The installer uses `/var/lib/observer`, detects journald, offers localhost Ollama, and defaults its REC prompt to yes. An LLM service/model must already be available; a bare host does not normally resolve the binary default hostname `llm`.

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

Tier 1 classifies events not resolved by policy, filters, or patterns. Tier 2 can review response evidence even after a Tier 1 cache hit. The README reports approximately 87–91% cache hits on the founder's soak box, not a universal model-call avoidance rate. Local Ollama keeps the LLM path local; sync and notification channels have separate data flows.

| Variable | Default | Description |
|---|---|---|
| `LLM_URL` | `http://llm:11434` | Base URL without `/v1`. Observer appends `/v1/chat/completions` and sends `max_completion_tokens` and `reasoning_effort`. The endpoint/model must accept these and return the expected JSON verdict. |
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

> **Cloud caveat.** The cloud path sends the raw, unredacted Tier 1 log line
> to the provider. Log lines can contain tokens in URLs, request bodies, and
> other sensitive material. If that is unacceptable, use Ollama. Structural
> redaction applies to Tier 2 response evidence, not to Tier 1 log lines.
> Tier 1 redaction before cloud calls is planned.

## Dashboard API

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_PORT` | `9090` | Port the REST API listens on |
| `DASHBOARD_BIND_ADDR` | `127.0.0.1` | Bind address. Loopback-only, and the installer never writes anything else. |
| `DASHBOARD_KEY_FILE` | `/etc/vaultguardian/dashboard.key` | Bearer token file, auto-generated at `0600` on first start |
| `DASHBOARD_ALLOWED_ORIGINS` | (none) | Comma-separated CORS allowlist. Empty = no CORS headers (correct for server-side proxy patterns). |

The API binds to loopback by default. With a compatible outbound service, pairing/sync needs no inbound connection or port change. The hosted website reads records pushed to its database. See [pairing and data handling](../README.md#hosted-dashboard-pairing); no public local API is needed.

For your own LAN or a reverse proxy on this host, `DASHBOARD_BIND_ADDR` is an override. Put TLS and authentication in front of the API and restrict access. Observer warns on a non-loopback bind.

## Email alerts (optional)

| Variable | Default | Description |
|---|---|---|
| `RESEND_API_KEY` | (none) | Resend API key for delivery |
| `ALERT_EMAIL_TO` | (none) | Destination address for alert emails |
| `ALERT_EMAIL_FROM` | `VaultGuardian Observer <onboarding@resend.dev>` | The sandbox sender only delivers to the email on your own Resend account. Use a sender on your verified domain for other recipients. |

## Proxy topology instrumentation (optional)

Opt-in request-lineage coalescing uses a trusted edge-generated ID logged by both proxy and backend. Leave `LINEAGE_ANCHOR_SOURCES` empty to disable it. In v1.5.1, matching strips an optional `docker:` prefix and Swarm `.N.<taskid>` suffix on both configured and observed names. IDs must be 32 lowercase hex characters in a trailing `vgrid=` field; overwrite client-supplied headers at the edge and restrict backend access to that edge.

The settle window is about three seconds from the first final verdict at the sink. Missing IDs, anchor conflicts, late siblings and bypass routes can leave duplicates. Notifications are not delayed for settlement; one coalesced finding does **not** guarantee one notification. See [the README instrumentation example](../README.md#proxy-topology-instrumentation-optional).
| Variable | Default | Description |
|---|---|---|
| `LINEAGE_ANCHOR_SOURCES` | (none) | Comma-separated source/container names that generate the trusted ingress ID (your edge proxy, e.g. `captain-nginx`). Empty = feature entirely off. |

Adoption/health signals live in `/api/stats` under `pipeline_health.correlation`: `multi_observation_groups_total` and `observations_absorbed_total` rising indicate proxy-topology duplicates being removed; `anchor_conflicts_total` and `invalid_ids_total` must stay near zero. `pipeline_health.coordinator.hostless_keys` is a lifetime cumulative counter (a parser-health signal that cannot fall), not an adoption gauge.

**REC-disabled boundary:** coalescing engages only on the finding paths that flow through the sink (the recon/status/bare-IP shortcuts and the coordinator dispatch). With REC disabled, an HTTP finding takes the direct-dispatch branch, which bypasses the sink and is not coalesced. The feature targets REC-enabled deployments.

## Response Evidence Capture (REC)

REC captures supported plaintext HTTP responses visible on its selected interfaces. A Docker reverse proxy that terminates TLS and forwards plaintext to the backend is the demonstrated topology. With `REC_NS_CONTAINER` unset, Observer discovers public-facing Docker namespaces (up to `REC_MAX_NAMESPACES`) and rescans. An explicit container selects that namespace. Discovery/namespace failure can fall back to host capture with reduced visibility. Host networking, encrypted backend hops, unobserved interfaces, incomplete streams, and unsupported parsing can leave evidence unavailable. Check `vaultguardian rec status` or `/api/rec/coverage`.

Raw response preview bytes are retained temporarily in bounded memory. Supported bodies are structurally redacted before evidence review/persistence; previews are not a guarantee that all sensitive material is removed. XML handling fails closed to metadata for unsupported/incomplete forms, and served PHP source is metadata-only. These limits are not a whole-process memory cap.
### Core

| Variable | Default | Description |
|---|---|---|
| `REC_ENABLED` | `false` | Master switch for REC |
| `REC_INTERFACE` | (auto) | Interface to sniff; auto-detected if unset |
| `REC_NS_CONTAINER` | (none) | Explicit container namespace override; unset enables discovery with host fallback |
| `REC_PORTS` | `80,8080` | Comma-separated HTTP ports REC always sniffs |
| `REC_LEARNED_PORT_CAP` | `64` | Cap on runtime-learned ports (`0` disables learning) |
| `REC_VXLAN_PORT` | (auto) | VXLAN port override; auto-detected if unset |
| `REC_VERBOSE` | `false` | Verbose REC diagnostics (debug only) |
| `REC_MAX_NAMESPACES` | `16` | Maximum discovered namespaces |
| `REC_RESCAN_INTERVAL` | `60s` | Namespace discovery rescan interval |
| `REC_EXCLUDE_CONTAINERS` | (none) | Additional container exclusions for REC discovery |

### Evidence buffer

| Variable | Default | Description |
|---|---|---|
| `REC_BUFFER_MAX_ENTRIES` | `32768` | Max buffered response entries |
| `REC_BUFFER_MAX_BYTES` | `134217728` (128 MB) | Byte ceiling; effective limit is the smaller of this and `REC_BUFFER_MAX_MB` MiB (64 MiB by default). Not a process RSS cap. |
| `REC_BUFFER_MAX_MB` | `64` | Preferred MiB ceiling; combined with the byte setting using the smaller limit |
| `REC_BUFFER_MAX_AGE` | `10m` | Max age before a buffered entry is evicted |
| `REC_BUFFER_MAX_BODY` | `2048` | Max bytes of response body retained per entry |

### TCP reassembly

| Variable | Default | Description |
|---|---|---|
| `REC_REASSEMBLY_MAX_BODY` | `2048` | Max bytes reassembled per HTTP response |
| `REC_REASSEMBLY_STREAM_TTL` | `5s` | Lifetime of an idle reassembly stream |
| `REC_REASSEMBLY_IDLE_TIMEOUT` | `250ms` | Idle timeout before a stream is flushed |
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

## Transport timing

| Variable | Default | Description |
|---|---|---|
| `SLOW_RESPONSE_THRESHOLD_MS` | `3000` | Supported wire-pair timing at/above this threshold prevents the transport-only downgrade; zero/negative disables this gate. Timing alone is not proof of successful execution. |

## Hosted sync (optional)

The v1.5.1 client pairs with the hosted backend and sends records outbound. The website stores a mirror and queues signed commands. See the [README dashboard boundary](../README.md#dashboard).

| Variable | Default | Description |
|---|---|---|
| `SYNC_URL`, `SYNC_TOKEN` | (none) | Both required to enable outbound sync; provision with pairing |
| `SYNC_INSTANCE_ID`, `SYNC_VERIFY_KEY`, `SYNC_COMMAND_EPOCH` | (none) | Pairing-provisioned identity, Ed25519 public verification key, and command epoch |
| `SYNC_INTERVAL` | `15s` | Findings/decision sync cadence |
| `SYNC_SNAPSHOT_INTERVAL` | `5m` | Stats, full pattern data, trusted-IP and REC coverage snapshots |
| `SYNC_HEARTBEAT_INTERVAL` | `60s` | Outbound heartbeat cadence |
| `SYNC_COMMAND_INTERVAL` | `30s` | Signed command polling cadence |

First pair: `vaultguardian pair --url https://vaultguardian.io VG-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (flags before code). A re-pair can reuse the saved URL. A failed standalone claim leaves the daemon stopped; follow the README recovery instructions. Keep the local API bearer key distinct from the sync token. Removing sync settings and restarting stops future sync; it does not establish deletion of already transferred data.

Sync includes original attached log lines, normalized lines, decisions and redacted evidence previews; it is not a stream of every raw log line. A queued hosted correction is not yet applied: the box must verify and execute it, then acknowledge the result to the server. The hosted app retains a mirror for offline viewing. Its configured daily job prunes findings/decisions after 90 days by event time and stats after 30 days by capture time. Re-pair claim wipes that instance’s mirror and cancels pending commands before local retained data re-syncs; creating a code alone does not wipe it. These application operations do not establish deletion from backups or provider logs.

## Normalizer selection

An operator-declared shape profile is checked first. If none is configured, or the declared profile does not parse the line, selection checks exact source scope, exact source name, a source-name substring matching a registered family, collector type, then generic fallback. Collector framing and the trailing lineage token are stripped before normalization. Generic formats may retain changing values and reuse poorly; a low hit rate alone does not prove misconfiguration. Existing `[hints]` log suggestions do not install new normalization rules.

| Variable | Default | Description |
|---|---|---|
| `NORMALIZER_HINTS_JSON` | (unset) | JSON object mapping a source key to a shape profile name. Keys are `source_type:source_name` or a bare `source_name`; no other key form is recognized. A malformed document or an unknown profile name stops startup |

```
NORMALIZER_HINTS_JSON='{"docker:edge":"http-combined-v1","router":"http-combined-v1"}'
```

One profile name is available: `http-combined-v1`. It accepts the combined access-log grammar, with or without a trailing `$http_x_forwarded_for` field, and keeps the request line and status code while dropping the client address, identd/user fields, bracket timestamp, byte count, referrer and user-agent. It is strict: a line that does not satisfy the whole grammar is declined and normalized by the selection chain above instead, unchanged. Declining is also what happens to formats it does not cover, including the five-field variant that carries a leading vhost.

A hint applies because it is configured. Log content does not select a profile, change one, or turn one off.

A source that resolves to generic normalization while emitting combined access-log lines is reported once per source per process run. That message is advisory; it does not change normalization, and it is not emitted for a source that already has a hint. `/api/guidance` and `vaultguardian doctor` are not shipped interfaces in this snapshot.

## Persistence and backups

`$DATA_DIR` holds `observer.db` (SQLite WAL), `patternstore.json`, and `notifications.yaml`. Keep `/etc/vaultguardian/observer.env` and `dashboard.key` in a protected backup too. Notification routing/rate limits can be persisted in YAML; quiet-hours fields are not enforced.

For a consistent simple backup, stop Observer, verify it is stopped, copy the entire data and configuration directories with restrictive permissions (including any remaining SQLite WAL sidecars), then restart. Do not copy only `observer.db` from a running service. A live SQLite backup alone also does not make the separate pattern/config files a consistent snapshot.

Restore only with Observer stopped. Restoring/deleting a database while retaining its old sync credential can cause cursor/row-ID conflicts. Use a fresh pairing against a compatible backend before resuming sync; the client fails closed on detected rollback. This does not establish a hosted deletion guarantee.

## Debugging

| Variable | Default | Description |
|---|---|---|
| `OBSERVER_DEBUG` | (unset) | Set exactly `1` to enable pprof on localhost:6060 |
