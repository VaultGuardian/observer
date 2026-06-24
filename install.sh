#!/bin/bash
# VaultGuardian Observer - Install Script
# Usage: sudo bash install.sh
#        curl -fsSL https://raw.githubusercontent.com/VaultGuardian/observer/main/install.sh | sudo bash
set -e

REPO="VaultGuardian/observer"
BIN="/usr/local/bin/observer"
CLI="/usr/local/bin/vaultguardian"
SERVICE_FILE="/etc/systemd/system/observer.service"
DATA_DIR="/var/lib/observer"
CONFIG_DIR="/etc/vaultguardian"

# -------------------------------------------------------------------
# Colors
# -------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[vaultguardian]${NC} $1"; }
ok()    { echo -e "${GREEN}[vaultguardian]${NC} $1"; }
warn()  { echo -e "${YELLOW}[vaultguardian]${NC} $1"; }
fail()  { echo -e "${RED}[vaultguardian]${NC} $1"; exit 1; }

# -------------------------------------------------------------------
# Interactive prompts under `curl | bash`
# -------------------------------------------------------------------
# When run as `curl ... | sudo bash`, stdin (fd 0) IS the script stream, so a
# plain `read` consumes the script's own following lines instead of the user's
# answer. Open the controlling terminal on fd 3 and read prompts from there.
# If there's no tty (CI / automation), prompts are skipped and each caller's
# "${VAR:-default}" fallback supplies the default.
if { exec 3</dev/tty; } 2>/dev/null; then
    HAVE_TTY=1
else
    HAVE_TTY=0
fi

# ask PROMPT VARNAME - interactive read from the tty (fd 3) when available,
# otherwise leaves VARNAME empty so the caller's default fallback applies.
ask() {
    local __prompt="$1" __var="$2" __val=""
    if [ "$HAVE_TTY" = "1" ]; then
        printf '%s' "$__prompt" > /dev/tty
        IFS= read -r __val <&3 || __val=""
    fi
    printf -v "$__var" '%s' "$__val"
}

# -------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   VaultGuardian Observer - Installer     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Must be root
[ "$(id -u)" -eq 0 ] || fail "Please run as root: sudo bash install.sh"

# Must be Linux
[ "$(uname -s)" = "Linux" ] || fail "Observer requires Linux"

# Must have systemd
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

# Need curl to download the binary from public releases. gh CLI is an
# optional fallback for pre-releases or auth-gated repos.
command -v curl >/dev/null 2>&1 || fail "curl is required (apt-get install curl / yum install curl)"

if command -v gh >/dev/null 2>&1; then
    # When running as root via sudo, gh auth lives in the calling user's home.
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [ -d "$REAL_HOME/.config/gh" ]; then
            export GH_CONFIG_DIR="$REAL_HOME/.config/gh"
        fi
    fi
fi

# -------------------------------------------------------------------
# Check for existing installation
# -------------------------------------------------------------------
# Track whether this is an upgrade vs a fresh install. When upgrading
# AND an env file already exists, we preserve operator customizations
# (DASHBOARD_BIND_ADDR=0.0.0.0, CORS allowlist, REC tuning, manually-
# added notifier creds, etc) rather than overwriting them with prompt
# defaults. The user can use 'vaultguardian update' for binary-only
# upgrades without re-running this script at all.
EXISTING_INSTALL=false

if [ -f "$BIN" ]; then
    warn "Observer is already installed at $BIN"
    echo ""
    ask "  Reinstall / upgrade? [y/N] " REINSTALL
    case "$REINSTALL" in
        [yY]|[yY][eE][sS])
            EXISTING_INSTALL=true
            info "Upgrading..."
            if systemctl is-active --quiet observer 2>/dev/null; then
                info "Stopping running Observer..."
                systemctl stop observer
            fi
            ;;
        *)
            info "Cancelled."
            exit 0
            ;;
    esac
fi

# Decide whether to preserve the existing env file. Both conditions
# must hold: we must be in an upgrade (not first install) AND a
# config file must actually exist. A partial state (binary present
# but no env, or env present but no binary) falls through to fresh
# config collection.
PRESERVE_ENV=false
if [ "$EXISTING_INSTALL" = true ] && [ -f "$CONFIG_DIR/observer.env" ]; then
    PRESERVE_ENV=true
fi

# -------------------------------------------------------------------
# Detect environment
# -------------------------------------------------------------------
DOCKER_FOUND=false
JOURNALD_FOUND=false

if [ -S /var/run/docker.sock ]; then
    DOCKER_FOUND=true
    ok "Docker detected"
else
    warn "Docker socket not found - Docker monitoring will be disabled"
fi

if command -v journalctl >/dev/null 2>&1; then
    JOURNALD_FOUND=true
    ok "journald detected"
else
    warn "journald not found - host OS monitoring will be disabled"
fi

if [ "$DOCKER_FOUND" = false ] && [ "$JOURNALD_FOUND" = false ]; then
    fail "Neither Docker nor journald found. Observer needs at least one log source."
fi

# -------------------------------------------------------------------
# Collect configuration
# -------------------------------------------------------------------
if [ "$PRESERVE_ENV" = true ]; then
    echo ""
    info "Existing configuration found at $CONFIG_DIR/observer.env"
    info "Preserving your settings - skipping configuration prompts."
    info "To change settings: edit $CONFIG_DIR/observer.env directly, then"
    info "                    'systemctl restart observer'"
    info "To reconfigure from scratch: remove the env file and re-run this script"
    info "For binary-only upgrades next time: 'vaultguardian update'"
    echo ""
else
    echo ""
    info "Configuration"
    echo ""

# -------------------------------------------------------------------
# LLM provider - local first, cloud as opt-in.
# -------------------------------------------------------------------
# Observer's binary defaults to local Ollama (LLM_URL=http://llm:11434,
# LLM_MODEL=qwen2.5:7b). The installer mirrors that: it probes for a
# running Ollama on the loopback, recommends Local when found, and falls
# back to Cloud only when the operator explicitly chooses it. Cloud is
# never the silent default - picking it requires an explicit keystroke
# and an API key the user must paste.
# -------------------------------------------------------------------
echo "  Observer can classify events with a LOCAL LLM (Ollama) or a CLOUD LLM"
echo "  (any OpenAI-compatible endpoint: OpenAI, Together, Groq, vLLM, etc.)."
echo ""
echo "  Local  - logs never leave your network, \$0 API cost, air-gap friendly."
echo "  Cloud  - no LLM setup, but logs go to a third-party API."
echo ""

# Probe for a running Ollama on the loopback. Short timeout - we don't
# want a hanging port to stall the installer.
OLLAMA_URL=""
for url in "http://127.0.0.1:11434" "http://localhost:11434"; do
    if curl -fsS --max-time 2 "$url/api/tags" >/dev/null 2>&1; then
        OLLAMA_URL="$url"
        break
    fi
done

if [ -n "$OLLAMA_URL" ]; then
    ok "Detected Ollama running at $OLLAMA_URL"
    DEFAULT_PROVIDER="L"
else
    info "No local Ollama detected (https://ollama.com to install)."
    info "You can still pick Local and point Observer at a remote Ollama on your LAN."
    DEFAULT_PROVIDER="L"
fi

ask "  Provider - [L]ocal / [C]loud [$DEFAULT_PROVIDER]: " PROVIDER_CHOICE
PROVIDER_CHOICE="${PROVIDER_CHOICE:-$DEFAULT_PROVIDER}"

case "$PROVIDER_CHOICE" in
    [cC]*)
        # Cloud (OpenAI-compatible) branch
        echo ""
        info "Cloud LLM selected. Logs will be sent to this endpoint for classification."
        echo ""
        ask "  LLM base URL [https://api.openai.com]: " LLM_URL
        LLM_URL="${LLM_URL:-https://api.openai.com}"

        ask "  LLM model [gpt-5-mini]: " LLM_MODEL
        LLM_MODEL="${LLM_MODEL:-gpt-5-mini}"

        ask "  API key: " API_KEY
        [ -n "$API_KEY" ] || fail "API key is required for cloud LLM"
        ;;
    *)
        # Local (Ollama) branch - default
        DEFAULT_LLM_URL="${OLLAMA_URL:-http://localhost:11434}"
        echo ""
        ask "  Ollama URL [$DEFAULT_LLM_URL]: " LLM_URL
        LLM_URL="${LLM_URL:-$DEFAULT_LLM_URL}"

        ask "  Model name [qwen2.5:7b]: " LLM_MODEL
        LLM_MODEL="${LLM_MODEL:-qwen2.5:7b}"

        # Ollama does not require an API key. Leave LLM_API_KEY empty in
        # the env file so the binary doesn't send an Authorization header.
        API_KEY=""

        if [ -z "$OLLAMA_URL" ]; then
            warn "Ollama wasn't reachable during install. Make sure $LLM_URL is up"
            warn "and that '$LLM_MODEL' is pulled (ollama pull $LLM_MODEL) before traffic arrives."
        fi
        ;;
esac

echo ""

# Server nickname - used in alert emails so multi-host operators can tell
# which box fired. Defaults to the system hostname. Stored as HOSTNAME in
# the env file because that's the env var the binary already reads
# (config.go: SelfID = getEnv("HOSTNAME", "")).
DEFAULT_NICK="$(hostname)"
ask "  Server nickname (used in alert emails) [$DEFAULT_NICK]: " SERVER_NICK
SERVER_NICK="${SERVER_NICK:-$DEFAULT_NICK}"

# Dashboard port
ask "  Dashboard API port [9090]: " DASHBOARD_PORT
DASHBOARD_PORT="${DASHBOARD_PORT:-9090}"

# Email alerts (optional)
echo ""
echo "  Observer can email you when it finds confirmed exploitation."
echo "  Requires a Resend API key (https://resend.com)"
ask "  Resend API key (optional, press Enter to skip): " RESEND_KEY

ALERT_EMAIL=""
ALERT_EMAIL_FROM=""
if [ -n "$RESEND_KEY" ]; then
    ask "  Alert destination email address: " ALERT_EMAIL
    if [ -z "$ALERT_EMAIL" ]; then
        warn "No destination email provided - email alerts disabled"
        RESEND_KEY=""  # don't write a half-configured email block
    else
        # The 'From' address must be verified in the USER'S Resend account.
        # Default to onboarding@resend.dev - Resend's pre-verified sandbox
        # sender - so first-time installs work immediately without domain
        # setup. Users can switch to their own verified domain later by
        # editing ALERT_EMAIL_FROM in the env file.
        echo ""
        echo "  The 'From' address must be verified in YOUR Resend account."
        echo "  Default uses Resend's sandbox sender (onboarding@resend.dev),"
        echo "  which works out of the box. Switch to your own verified"
        echo "  domain later via ALERT_EMAIL_FROM in $CONFIG_DIR/observer.env."
        DEFAULT_FROM="VaultGuardian Observer <onboarding@resend.dev>"
        ask "  Alert 'From' address [$DEFAULT_FROM]: " ALERT_EMAIL_FROM
        ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-$DEFAULT_FROM}"
    fi
fi

# Response Evidence Capture
echo ""
echo "  REC captures what your server actually sent back to attackers."
echo "  Recommended for full evidence on escalated alerts."
ask "  Enable Response Evidence Capture? [Y/n]: " REC_CHOICE
case "$REC_CHOICE" in
    [nN]|[nN][oO]) REC_ENABLED=false ;;
    *) REC_ENABLED=true ;;
esac

echo ""

fi  # end of PRESERVE_ENV check (was opened above "Configuration")

# -------------------------------------------------------------------
# Download binary
# -------------------------------------------------------------------
info "Downloading Observer binary..."

cd /tmp
rm -f observer

# Try public release URL via curl. -L follows redirects (the
# releases/latest/download URL is a 302 to the actual asset).
# Fall back to gh CLI when curl can't reach the asset - covers private
# repos, pre-release tags, and rate-limited unauthenticated requests.
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/observer"
SHA_URL="https://github.com/${REPO}/releases/latest/download/observer.sha256"
GOT_SHA=false
if curl -fsSL --retry 3 -o observer "$DOWNLOAD_URL"; then
    ok "Downloaded from public release"
    # Best-effort: fetch the published checksum alongside the binary.
    if curl -fsSL --retry 3 -o observer.sha256 "$SHA_URL" 2>/dev/null; then
        GOT_SHA=true
    fi
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    warn "Public download failed - trying gh CLI"
    if ! gh release download --repo "$REPO" --pattern "observer"; then
        fail "Download failed via both curl and gh. Check network and that the repo has a release named 'observer'."
    fi
    # Pull the checksum asset too (ignore failure - older releases may lack it).
    gh release download --repo "$REPO" --pattern "observer.sha256" 2>/dev/null && GOT_SHA=true || true
    ok "Downloaded via gh CLI"
else
    fail "Could not download Observer binary. Check network connectivity, or install + authenticate gh CLI for private/pre-release access."
fi

# Verify the binary against the published SHA256 when available. A mismatch
# means the download was corrupted or tampered with - refuse to install.
if [ "$GOT_SHA" = true ] && [ -s observer.sha256 ]; then
    EXPECTED=$(awk '{print $1}' observer.sha256)
    ACTUAL=$(sha256sum observer | awk '{print $1}')
    if [ "$EXPECTED" = "$ACTUAL" ]; then
        ok "SHA256 verified: $ACTUAL"
    else
        rm -f observer observer.sha256
        fail "SHA256 MISMATCH - refusing to install.
       expected: $EXPECTED
       actual:   $ACTUAL
       The download may be corrupted or tampered with. Aborting."
    fi
    rm -f observer.sha256
else
    warn "No published checksum found for this release - skipping verification."
    warn "(Releases from v0.55.4+ publish observer.sha256 alongside the binary.)"
fi

mv observer "$BIN"
chmod +x "$BIN"
ok "Binary installed at $BIN"

# -------------------------------------------------------------------
# Create directories
# -------------------------------------------------------------------
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
ok "Created $DATA_DIR and $CONFIG_DIR"

# -------------------------------------------------------------------
# Create systemd service
# -------------------------------------------------------------------
info "Creating systemd service..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=VaultGuardian Observer
# Wait for the network to be ACTUALLY usable (DNS + routing), not just
# the interface coming up. Without After=network-online.target, Observer
# can start before DNS resolves, fail its first LLM call, and burn a
# RestartSec cycle on every reboot.
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=$BIN
Restart=always
RestartSec=5

# Secrets and configuration are loaded from a 0600 file outside the unit
# (systemd unit files are typically world-readable, which would expose API keys
# to local users on the box).
EnvironmentFile=$CONFIG_DIR/observer.env
EOF

# Add Install section
cat >> "$SERVICE_FILE" << 'EOF'

[Install]
WantedBy=multi-user.target
EOF

ok "Service file created at $SERVICE_FILE"

# -------------------------------------------------------------------
# Create environment file (chmod 600, contains secrets)
# -------------------------------------------------------------------
ENV_FILE="$CONFIG_DIR/observer.env"

if [ "$PRESERVE_ENV" = true ]; then
    ok "Environment file preserved at $ENV_FILE"
else
    info "Writing $ENV_FILE (mode 0600)..."

    # Create the file with restrictive perms BEFORE writing any content.
    # `cat > file` preserves existing perms on an existing file, so by
    # pre-creating at 0600, the API keys never sit in a world-readable file
    # even for the microseconds between the heredoc write and a later
    # chmod. install(1) from coreutils creates atomically at the target mode.
    install -m 600 /dev/null "$ENV_FILE"

    cat > "$ENV_FILE" << EOF
# VaultGuardian Observer environment
# This file contains API keys and runtime configuration.
# Permissions: 0600 (root only). Do not chmod world-readable.

# Core
DATA_DIR=$DATA_DIR
DASHBOARD_PORT=$DASHBOARD_PORT

# Server identity (shown in alert emails).
HOSTNAME=$SERVER_NICK

# Dashboard binding.
#   127.0.0.1 = localhost only (default, safest - for self-hosted setups)
#   0.0.0.0   = all interfaces (for hosted dashboards via proxy/VPN; firewall the port)
DASHBOARD_BIND_ADDR=127.0.0.1

# Dashboard CORS allowlist (comma-separated origins). Empty = no CORS headers.
# Set this if a browser-side dashboard hits Observer directly.
DASHBOARD_ALLOWED_ORIGINS=

# LLM
LLM_URL=$LLM_URL
LLM_MODEL=$LLM_MODEL
LLM_API_KEY=$API_KEY

# Sources
DOCKER_SOCKET=/var/run/docker.sock
JOURNALD_ENABLED=$JOURNALD_FOUND
EXCLUDE_CONTAINERS=

# Evidence capture
REC_ENABLED=$REC_ENABLED
EOF

    # Add email config if provided
    if [ -n "$RESEND_KEY" ] && [ -n "$ALERT_EMAIL" ]; then
        cat >> "$ENV_FILE" << EOF

# Email alerts
RESEND_API_KEY=$RESEND_KEY
ALERT_EMAIL_TO=$ALERT_EMAIL
ALERT_EMAIL_FROM=$ALERT_EMAIL_FROM
EOF
    fi

    chmod 600 "$ENV_FILE"
    ok "Environment file written (chmod 0600)"
fi

# -------------------------------------------------------------------
# Install CLI tool
# -------------------------------------------------------------------
info "Installing CLI tool..."

cat > "$CLI" << 'CLIEOF'
#!/bin/bash
set -e

REPO="VaultGuardian/observer"
BIN="/usr/local/bin/observer"
SERVICE="observer"

# download_binary <version> - fetches observer to ./observer
# version: "latest" or a tag like "v0.53.0"
download_binary() {
    local version="$1"
    local url
    if [ "$version" = "latest" ]; then
        url="https://github.com/${REPO}/releases/latest/download/observer"
    else
        url="https://github.com/${REPO}/releases/download/${version}/observer"
    fi

    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --retry 3 -o observer "$url"; then
            return 0
        fi
    fi
    # Fall back to gh CLI for private/pre-release/auth-gated cases.
    if command -v gh >/dev/null 2>&1; then
        if [ "$version" = "latest" ]; then
            gh release download --repo "$REPO" --pattern "observer"
        else
            gh release download "$version" --repo "$REPO" --pattern "observer"
        fi
        return $?
    fi
    echo "[vaultguardian] No download method available. Install curl (preferred) or gh CLI."
    return 1
}

case "$1" in
  update)
    VERSION="${2:-latest}"
    echo "[vaultguardian] Updating Observer to ${VERSION}..."
    cd /tmp
    rm -f observer
    if ! download_binary "$VERSION"; then
        exit 1
    fi

    sudo mv observer "$BIN"
    sudo chmod +x "$BIN"
    sudo systemctl restart "$SERVICE"
    echo "[vaultguardian] Observer updated and restarted"
    sudo journalctl -u "$SERVICE" -n 20 --no-pager
    ;;
  logs)
    sudo journalctl -u "$SERVICE" -f
    ;;
  status)
    sudo systemctl status "$SERVICE" --no-pager
    echo ""
    sudo journalctl -u "$SERVICE" --no-pager | tail -5
    ;;
  stats)
    sudo journalctl -u "$SERVICE" --no-pager | grep -E "Pipeline:|Patterns:|REC:|CatchAll:" | tail -4
    ;;
  restart)
    sudo systemctl restart "$SERVICE"
    echo "[vaultguardian] Observer restarted"
    sudo journalctl -u "$SERVICE" -f
    ;;
  version)
    "$BIN" --version 2>/dev/null || echo "Observer running (no --version flag yet)"
    if command -v gh >/dev/null 2>&1; then
      gh release list --repo "$REPO" --limit 5
    else
      echo "(install gh CLI to see available versions, or check https://github.com/${REPO}/releases)"
    fi
    ;;
  uninstall)
    echo "[vaultguardian] Uninstalling Observer..."
    sudo systemctl stop "$SERVICE" 2>/dev/null || true
    sudo systemctl disable "$SERVICE" 2>/dev/null || true
    sudo rm -f /etc/systemd/system/observer.service
    sudo systemctl daemon-reload
    sudo rm -f "$BIN"
    echo "[vaultguardian] Observer removed. Data preserved in /var/lib/observer"
    echo "[vaultguardian] To remove all data: sudo rm -rf /var/lib/observer /etc/vaultguardian"
    echo "[vaultguardian] To remove this CLI: sudo rm /usr/local/bin/vaultguardian"
    ;;
  rec)
    SUB="${2:-status}"
    if [ "$SUB" != "status" ]; then
      echo "[vaultguardian] Unknown 'rec' subcommand: $SUB"
      echo "Usage: vaultguardian rec status"
      exit 1
    fi

    ENV_FILE="/etc/vaultguardian/observer.env"
    KEY_FILE="/etc/vaultguardian/dashboard.key"

    # Resolve the dashboard port at runtime from the live config. observer.env
    # is 0600 root-only, so read it with sudo - a non-sudo read silently fails
    # and would always fall back to 9090, ignoring a customized port. The
    # `|| true` keeps a missing file / no match from aborting under `set -e`.
    PORT=9090
    PORT_LINE=$(sudo grep '^DASHBOARD_PORT=' "$ENV_FILE" 2>/dev/null || true)
    if [ -n "$PORT_LINE" ]; then
      PORT="${PORT_LINE#DASHBOARD_PORT=}"
    fi

    # Read the bearer token at runtime (DASHBOARD_KEY_FILE default; root-only
    # 0600). `|| true` so a missing key prints the friendly message below
    # instead of aborting under `set -e`.
    TOKEN=$(sudo cat "$KEY_FILE" 2>/dev/null || true)
    if [ -z "$TOKEN" ]; then
      echo "[vaultguardian] Dashboard key missing or empty at $KEY_FILE"
      echo "[vaultguardian] Has Observer been installed and started at least once? Check the install."
      exit 1
    fi

    URL="http://127.0.0.1:$PORT/api/rec/coverage"
    BODY=$(curl -fsS "$URL" -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)
    if [ -z "$BODY" ]; then
      echo "[vaultguardian] Observer API not reachable on 127.0.0.1:$PORT"
      exit 1
    fi

    if command -v jq >/dev/null 2>&1; then
      echo "$BODY" | jq .
      echo ""
      # Null-guard every array: nil Go slices marshal as null, not [], so a bare
      # `.skipped | length` would error in the all-green (no blind spots) case.
      echo "$BODY" | jq -r '
        "Mode: \(.mode)  ·  active captures: \((.active // []) | length)",
        "Blind spots - skipped: \((.skipped // []) | length), excluded: \((.excluded // []) | length), dropped_by_cap: \((.dropped_by_cap // []) | length)",
        ((.skipped // [])[]        | "  skipped:        \(.name) - \(.reason)"),
        ((.excluded // [])[]       | "  excluded:       \(.name)"),
        ((.dropped_by_cap // [])[] | "  dropped_by_cap: \(.name)")
      '
    elif command -v python3 >/dev/null 2>&1; then
      echo "$BODY" | python3 -m json.tool
    else
      echo "$BODY"
    fi
    ;;
  *)
    echo "VaultGuardian Observer CLI"
    echo ""
    echo "Usage: vaultguardian <command> [args]"
    echo ""
    echo "  update [version]  Download and deploy (default: latest)"
    echo "  logs              Tail observer logs"
    echo "  status            Service status + recent logs"
    echo "  stats             Latest pipeline stats"
    echo "  rec status        REC coverage: active captures + blind spots"
    echo "  restart           Restart observer"
    echo "  version           Show current + available versions"
    echo "  uninstall         Stop and remove Observer"
    ;;
esac
CLIEOF

chmod +x "$CLI"
ok "CLI tool installed at $CLI"

# -------------------------------------------------------------------
# Start Observer
# -------------------------------------------------------------------
info "Starting Observer..."

systemctl daemon-reload
systemctl enable observer >/dev/null 2>&1
systemctl start observer

# Give it a moment to connect
sleep 2

# -------------------------------------------------------------------
# Verify
# -------------------------------------------------------------------
echo ""
if systemctl is-active --quiet observer; then
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    if [ "$EXISTING_INSTALL" = true ]; then
        echo -e "${GREEN}║   Observer upgraded - running!           ║${NC}"
    else
        echo -e "${GREEN}║   Observer is running!                   ║${NC}"
    fi
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$PRESERVE_ENV" = true ]; then
        # Upgrade with preserved config - keep the banner minimal. The
        # user already knows their config; we'd have to source the env
        # file (which has spaces in some values like ALERT_EMAIL_FROM)
        # to recap it, and that's more risk than value.
        ok "Configuration preserved: $ENV_FILE"
        info "Inspect with: sudo cat $ENV_FILE   (root-only)"
    else
        # Dashboard URL - show the actual bind address, not the box's external IP.
        # By default we bind to 127.0.0.1 (May 4 hardening), so advertising
        # `http://<hostname -I>:9090` would tell the user to visit an address
        # that won't accept connections. Show 127.0.0.1 + an SSH tunnel hint;
        # users who set DASHBOARD_BIND_ADDR=0.0.0.0 (after firewalling the
        # port) will know their LAN address already.
        ok "Dashboard API: http://127.0.0.1:$DASHBOARD_PORT (loopback only)"
        info "From another machine: ssh -L $DASHBOARD_PORT:127.0.0.1:$DASHBOARD_PORT $(whoami)@$(hostname)"
        info "To expose on LAN: set DASHBOARD_BIND_ADDR=0.0.0.0 in $ENV_FILE and firewall the port"
        case "$PROVIDER_CHOICE" in
            [cC]*) ok "LLM: cloud ($LLM_URL, model $LLM_MODEL)" ;;
            *)     ok "LLM: local ($LLM_URL, model $LLM_MODEL)" ;;
        esac
        [ "$DOCKER_FOUND" = true ] && ok "Monitoring: Docker containers"
        [ "$JOURNALD_FOUND" = true ] && ok "Monitoring: Host OS (journald)"
        [ -n "$ALERT_EMAIL" ] && ok "Alerts: $ALERT_EMAIL (via Resend)"
        [ "$REC_ENABLED" = true ] && ok "Evidence capture: enabled"
    fi

    echo ""
    info "Quick commands:"
    echo "  vaultguardian logs      - Watch live logs"
    echo "  vaultguardian status    - Check health"
    echo "  vaultguardian stats     - Pipeline statistics"
    echo "  vaultguardian update    - Update to latest version"
    echo ""
    info "First 20 log lines:"
    journalctl -u observer -n 20 --no-pager
else
    fail "Observer failed to start. Check: journalctl -u observer -n 50 --no-pager"
fi