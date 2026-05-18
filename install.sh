#!/bin/bash
# VaultGuardian Observer — Install Script
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
# Pre-flight checks
# -------------------------------------------------------------------
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   VaultGuardian Observer — Installer     ║${NC}"
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
if [ -f "$BIN" ]; then
    warn "Observer is already installed at $BIN"
    echo ""
    read -rp "  Reinstall / upgrade? [y/N] " REINSTALL
    case "$REINSTALL" in
        [yY]|[yY][eE][sS])
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

# -------------------------------------------------------------------
# Detect environment
# -------------------------------------------------------------------
DOCKER_FOUND=false
JOURNALD_FOUND=false

if [ -S /var/run/docker.sock ]; then
    DOCKER_FOUND=true
    ok "Docker detected"
else
    warn "Docker socket not found — Docker monitoring will be disabled"
fi

if command -v journalctl >/dev/null 2>&1; then
    JOURNALD_FOUND=true
    ok "journald detected"
else
    warn "journald not found — host OS monitoring will be disabled"
fi

if [ "$DOCKER_FOUND" = false ] && [ "$JOURNALD_FOUND" = false ]; then
    fail "Neither Docker nor journald found. Observer needs at least one log source."
fi

# -------------------------------------------------------------------
# Collect configuration
# -------------------------------------------------------------------
echo ""
info "Configuration"
echo ""

# API key
echo "  Observer uses an LLM API to classify log events."
echo "  Currently supported: OpenAI (recommended: gpt-5-nano)"
echo ""
read -rp "  OpenAI API key: " API_KEY
[ -n "$API_KEY" ] || fail "API key is required"

# LLM model (default to gpt-5-nano)
echo ""
read -rp "  LLM model [gpt-5-nano]: " LLM_MODEL
LLM_MODEL="${LLM_MODEL:-gpt-5-nano}"

# Dashboard port
read -rp "  Dashboard API port [9090]: " DASHBOARD_PORT
DASHBOARD_PORT="${DASHBOARD_PORT:-9090}"

# Email alerts (optional)
echo ""
echo "  Observer can email you when it finds confirmed exploitation."
echo "  Requires a Resend API key (https://resend.com)"
read -rp "  Resend API key (optional, press Enter to skip): " RESEND_KEY

ALERT_EMAIL=""
if [ -n "$RESEND_KEY" ]; then
    read -rp "  Alert email address: " ALERT_EMAIL
    [ -n "$ALERT_EMAIL" ] || warn "No email provided — email alerts disabled"
fi

# Response Evidence Capture
echo ""
echo "  REC captures what your server actually sent back to attackers."
echo "  Recommended for full evidence on escalated alerts."
read -rp "  Enable Response Evidence Capture? [Y/n]: " REC_CHOICE
case "$REC_CHOICE" in
    [nN]|[nN][oO]) REC_ENABLED=false ;;
    *) REC_ENABLED=true ;;
esac

echo ""

# -------------------------------------------------------------------
# Download binary
# -------------------------------------------------------------------
info "Downloading Observer binary..."

cd /tmp
rm -f observer

# Try public release URL via curl. -L follows redirects (the
# releases/latest/download URL is a 302 to the actual asset).
# Fall back to gh CLI when curl can't reach the asset — covers private
# repos, pre-release tags, and rate-limited unauthenticated requests.
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/observer"
if curl -fsSL --retry 3 -o observer "$DOWNLOAD_URL"; then
    ok "Downloaded from public release"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    warn "Public download failed — trying gh CLI"
    if ! gh release download --repo "$REPO" --pattern "observer"; then
        fail "Download failed via both curl and gh. Check network and that the repo has a release named 'observer'."
    fi
    ok "Downloaded via gh CLI"
else
    fail "Could not download Observer binary. Check network connectivity, or install + authenticate gh CLI for private/pre-release access."
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
After=network.target docker.service
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
info "Writing $ENV_FILE (mode 0600)..."

cat > "$ENV_FILE" << EOF
# VaultGuardian Observer environment
# This file contains API keys and runtime configuration.
# Permissions: 0600 (root only). Do not chmod world-readable.

# Core
DATA_DIR=$DATA_DIR
DASHBOARD_PORT=$DASHBOARD_PORT

# Dashboard binding.
#   127.0.0.1 = localhost only (default, safest — for self-hosted setups)
#   0.0.0.0   = all interfaces (for hosted dashboards via proxy/VPN; firewall the port)
DASHBOARD_BIND_ADDR=127.0.0.1

# Dashboard CORS allowlist (comma-separated origins). Empty = no CORS headers.
# Set this if a browser-side dashboard hits Observer directly.
DASHBOARD_ALLOWED_ORIGINS=

# LLM
LLM_URL=https://api.openai.com
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
EOF
fi

chmod 600 "$ENV_FILE"
ok "Environment file written (chmod 0600)"

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

# download_binary <version> — fetches observer to ./observer
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
  *)
    echo "VaultGuardian Observer CLI"
    echo ""
    echo "Usage: vaultguardian <command> [args]"
    echo ""
    echo "  update [version]  Download and deploy (default: latest)"
    echo "  logs              Tail observer logs"
    echo "  status            Service status + recent logs"
    echo "  stats             Latest pipeline stats"
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
    echo -e "${GREEN}║   Observer is running!                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    ok "Dashboard API: http://$(hostname -I | awk '{print $1}'):$DASHBOARD_PORT"
    [ "$DOCKER_FOUND" = true ] && ok "Monitoring: Docker containers"
    [ "$JOURNALD_FOUND" = true ] && ok "Monitoring: Host OS (journald)"
    [ -n "$ALERT_EMAIL" ] && ok "Alerts: $ALERT_EMAIL (via Resend)"
    [ "$REC_ENABLED" = true ] && ok "Evidence capture: enabled"
    echo ""
    info "Quick commands:"
    echo "  vaultguardian logs      — Watch live logs"
    echo "  vaultguardian status    — Check health"
    echo "  vaultguardian stats     — Pipeline statistics"
    echo "  vaultguardian update    — Update to latest version"
    echo ""
    info "First 20 log lines:"
    journalctl -u observer -n 20 --no-pager
else
    fail "Observer failed to start. Check: journalctl -u observer -n 50 --no-pager"
fi