#!/bin/bash
# VaultGuardian Observer — Install Script
# Usage: sudo bash install.sh
# Requires: gh CLI authenticated with access to VaultGuardian/observer
# Future (public repo): curl -fsSL https://raw.githubusercontent.com/VaultGuardian/observer/main/install.sh | sudo bash
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

# Must have gh CLI (repo is private — curl can't download without auth)
if command -v gh >/dev/null 2>&1; then
    ok "GitHub CLI detected"
else
    fail "GitHub CLI (gh) is required. Install: https://cli.github.com"
fi

# Verify gh is authenticated
# When running as root via sudo, gh auth may live in the calling user's home.
# Try to inherit it.
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -d "$REAL_HOME/.config/gh" ]; then
        export GH_CONFIG_DIR="$REAL_HOME/.config/gh"
    fi
fi

if ! gh auth status >/dev/null 2>&1; then
    fail "GitHub CLI not authenticated. Run 'gh auth login' first (as your normal user)."
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
read -rp "  Alert email (optional, press Enter to skip): " ALERT_EMAIL

echo ""

# -------------------------------------------------------------------
# Download binary
# -------------------------------------------------------------------
info "Downloading Observer binary..."

cd /tmp
rm -f observer

if ! gh release download --repo "$REPO" --pattern "observer"; then
    fail "Download failed. Check gh auth status and that the repo has releases."
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

# Core
Environment=DATA_DIR=$DATA_DIR
Environment=API_PORT=$DASHBOARD_PORT

# LLM
Environment=LLM_URL=https://api.openai.com
Environment=LLM_MODEL=$LLM_MODEL
Environment=LLM_API_KEY=$API_KEY

# Sources
Environment=DOCKER_SOCKET=/var/run/docker.sock
Environment=JOURNALD_ENABLED=$JOURNALD_FOUND
Environment=EXCLUDE_CONTAINERS=
EOF

# Add alert email if provided
if [ -n "$ALERT_EMAIL" ]; then
    echo "Environment=ALERT_EMAIL=$ALERT_EMAIL" >> "$SERVICE_FILE"
fi

# Add Install section
cat >> "$SERVICE_FILE" << 'EOF'

[Install]
WantedBy=multi-user.target
EOF

ok "Service file created at $SERVICE_FILE"

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

case "$1" in
  update)
    VERSION="${2:-latest}"
    echo "[vaultguardian] Updating Observer..."
    cd /tmp
    rm -f observer

    if command -v gh >/dev/null 2>&1; then
      if [ "$VERSION" = "latest" ]; then
        gh release download --repo "$REPO" --pattern "observer"
      else
        gh release download "$VERSION" --repo "$REPO" --pattern "observer"
      fi
    else
      echo "[vaultguardian] gh CLI not found. Install: https://cli.github.com"
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
      echo "(install gh CLI to see available versions)"
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
    [ -n "$ALERT_EMAIL" ] && ok "Alerts: $ALERT_EMAIL"
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