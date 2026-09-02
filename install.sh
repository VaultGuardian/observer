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
KEY_FILE="$CONFIG_DIR/dashboard.key"
DASHBOARD_URL="https://vaultguardian.io/dashboard"

# How long the post-start checks wait for Observer to report ready.
STARTUP_TIMEOUT=15

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

# Defaults for values the configuration prompts normally set. On the
# preserve path they are re-read from the existing env file further down.
HOSTED_DASHBOARD=false
DASHBOARD_BIND_ADDR=127.0.0.1
DASHBOARD_PORT=9090
SERVER_NICK="$(hostname)"
REC_ENABLED=""
ALERT_EMAIL=""

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

# Hosted dashboard connectivity. The hosted dashboard at vaultguardian.io
# reaches this box's API over the internet, which only works when the API
# listens on all interfaces (0.0.0.0) rather than loopback. Default Y; when
# declined, the bind address stays 127.0.0.1 and behavior is unchanged.
echo ""
echo "  The hosted dashboard at vaultguardian.io connects to this server's API"
echo "  over the internet. That requires the API to listen on all interfaces"
echo "  (0.0.0.0) on port $DASHBOARD_PORT, protected by the bearer token. If you skip this"
echo "  you can still use the API locally or over an SSH tunnel."
ask "  Connect this server to the hosted dashboard? [Y/n]: " HOSTED_CHOICE
case "$HOSTED_CHOICE" in
    [nN]|[nN][oO]) HOSTED_DASHBOARD=false; DASHBOARD_BIND_ADDR=127.0.0.1 ;;
    *) HOSTED_DASHBOARD=true; DASHBOARD_BIND_ADDR=0.0.0.0 ;;
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

# Verify the binary against the published SHA256. Fail-closed on both
# failure modes: a mismatch means the download was corrupted or tampered
# with, and a MISSING checksum means there is nothing to verify against.
# Neither one gets installed to /usr/local/bin and started as root on a
# shrug. OBSERVER_ALLOW_UNVERIFIED=1 is the deliberate opt-out for
# pre-checksum releases and local dev builds.
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
elif [ "${OBSERVER_ALLOW_UNVERIFIED:-}" = "1" ]; then
    rm -f observer.sha256
    warn "*** OBSERVER_ALLOW_UNVERIFIED=1 - installing an UNVERIFIED binary ***"
    warn "No published checksum was found for this release and the override is set,"
    warn "so this install proceeds without integrity verification. Only do this for"
    warn "pre-checksum releases or your own dev builds, on a host you trust."
else
    rm -f observer observer.sha256
    fail "No published checksum found for this release - refusing to install.
       Observer installs a root-run systemd service, so an unverified binary
       is not installed silently.
       Releases from v0.55.4+ publish observer.sha256 alongside the binary,
       so this usually means an older release, an interrupted download, or a
       network path that could not reach the checksum asset.
       To install anyway (old releases, dev builds), re-run with:
         sudo OBSERVER_ALLOW_UNVERIFIED=1 bash install.sh
       Or for the curl one-liner:
         curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo OBSERVER_ALLOW_UNVERIFIED=1 bash"
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

# -------------------------------------------------------------------
# Sandboxing
# -------------------------------------------------------------------
# Observer runs as root on purpose: REC enters other containers' network
# namespaces with setns(2), which an unprivileged user cannot do. Root
# stays. Everything below is about shrinking what that root process can
# reach, not about dropping it, so do not add User= or DynamicUser=.
#
# ReadWritePaths, one entry at a time (ProtectSystem=strict makes the
# rest of the filesystem read-only):
#   /var/lib/observer     SQLite database and its WAL.
#   /etc/vaultguardian    read-write, NOT read-only: the API server
#                         generates dashboard.key here on first boot
#                         (internal/api/server.go: loadOrGenerateToken),
#                         so a read-only /etc breaks a fresh install.
#   /var/run/docker.sock  needs write, not just read: every Docker API
#                         call is a write to the socket.
#   "-" prefix = ignore when absent, for Docker-less (journald-only) hosts.
#
# Capabilities kept, and why each is load-bearing:
#   CAP_SYS_ADMIN        setns(2) into container network namespaces.
#   CAP_NET_RAW          AF_PACKET sockets for the packet capture.
#   CAP_NET_ADMIN        promiscuous mode on the captured interface.
#   CAP_SYS_PTRACE       reading /proc/<pid>/ns/* of other processes.
#   CAP_DAC_OVERRIDE     root-only config, the key file, Docker socket.
#   CAP_DAC_READ_SEARCH  traversing /proc and container filesystems.
#
# Deliberately ABSENT, do not add:
#   RestrictNamespaces   blocks the setns(2) call REC depends on, which
#                        silently turns evidence capture into a blind
#                        spot rather than a startup error.
#   SystemCallFilter     a syscall allowlist for the capture path would
#                        be guesswork until there is adversarial test
#                        coverage proving which syscalls it needs.
#                        Deferred on purpose, not forgotten.
#   PrivateNetwork       Observer watches the host's network.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $CONFIG_DIR -/var/run/docker.sock
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
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
#   0.0.0.0   = all interfaces (required for the hosted dashboard; API is bearer-token protected)
DASHBOARD_BIND_ADDR=$DASHBOARD_BIND_ADDR

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

# On the preserve path the prompts were skipped, so pull the values the
# startup checks and closing block need straight from the existing env
# file. Plain grep/cut, no sourcing: some values contain spaces.
env_value() {
    grep "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true
}

if [ "$PRESERVE_ENV" = true ]; then
    v=$(env_value DASHBOARD_PORT);      DASHBOARD_PORT="${v:-9090}"
    v=$(env_value DASHBOARD_BIND_ADDR); DASHBOARD_BIND_ADDR="${v:-127.0.0.1}"
    v=$(env_value HOSTNAME);            SERVER_NICK="${v:-$(hostname)}"
    v=$(env_value REC_ENABLED);         REC_ENABLED="${v:-}"
    if [ "$DASHBOARD_BIND_ADDR" = "0.0.0.0" ]; then
        HOSTED_DASHBOARD=true
    fi
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
# Also fetches the published observer.sha256 from the same release location
# and sets GOT_SHA=true on success. Both branches below (latest and pinned)
# fetch the checksum from their own release URL, and both hand the result to
# the same fail-closed verify_binary gate: a release with no observer.sha256
# leaves GOT_SHA=false and the update is refused.
download_binary() {
    local version="$1"
    local url sha_url
    if [ "$version" = "latest" ]; then
        url="https://github.com/${REPO}/releases/latest/download/observer"
        sha_url="https://github.com/${REPO}/releases/latest/download/observer.sha256"
    else
        url="https://github.com/${REPO}/releases/download/${version}/observer"
        sha_url="https://github.com/${REPO}/releases/download/${version}/observer.sha256"
    fi

    GOT_SHA=false
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --retry 3 -o observer "$url"; then
            if curl -fsSL --retry 3 -o observer.sha256 "$sha_url" 2>/dev/null; then
                GOT_SHA=true
            fi
            return 0
        fi
    fi
    # Fall back to gh CLI for private/pre-release/auth-gated cases.
    if command -v gh >/dev/null 2>&1; then
        if [ "$version" = "latest" ]; then
            gh release download --repo "$REPO" --pattern "observer" || return $?
            gh release download --repo "$REPO" --pattern "observer.sha256" 2>/dev/null && GOT_SHA=true || true
        else
            gh release download "$version" --repo "$REPO" --pattern "observer" || return $?
            gh release download "$version" --repo "$REPO" --pattern "observer.sha256" 2>/dev/null && GOT_SHA=true || true
        fi
        return 0
    fi
    echo "[vaultguardian] No download method available. Install curl (preferred) or gh CLI."
    return 1
}

# verify_binary <version> - checks ./observer against ./observer.sha256.
# Fail-closed, identical to the installer and identical for both the latest
# and pinned download branches, since both route through here:
#   checksum matches  -> proceed
#   checksum mismatch -> refuse (corrupted or tampered download)
#   no checksum       -> refuse (nothing to verify an update against)
# OBSERVER_ALLOW_UNVERIFIED=1 in the environment is the deliberate opt-out
# for pre-checksum releases and local dev builds.
verify_binary() {
    local version="$1" expected actual
    if [ "$GOT_SHA" = true ] && [ -s observer.sha256 ]; then
        expected=$(awk '{print $1}' observer.sha256)
        actual=$(sha256sum observer | awk '{print $1}')
        if [ "$expected" = "$actual" ]; then
            echo "[vaultguardian] SHA256 verified: $actual"
        else
            rm -f observer observer.sha256
            echo "[vaultguardian] SHA256 MISMATCH - refusing to update."
            echo "[vaultguardian]   expected: $expected"
            echo "[vaultguardian]   actual:   $actual"
            echo "[vaultguardian] The download may be corrupted or tampered with. Aborting."
            return 1
        fi
        rm -f observer.sha256
        return 0
    fi

    rm -f observer.sha256
    if [ "${OBSERVER_ALLOW_UNVERIFIED:-}" = "1" ]; then
        echo "[vaultguardian] *** OBSERVER_ALLOW_UNVERIFIED=1 - deploying an UNVERIFIED binary ***"
        echo "[vaultguardian] No published checksum was found for ${version} and the override"
        echo "[vaultguardian] is set, so this update proceeds without integrity verification."
        return 0
    fi

    rm -f observer
    echo "[vaultguardian] No published checksum found for ${version} - refusing to update."
    echo "[vaultguardian] Observer runs as a root systemd service, so an unverified binary"
    echo "[vaultguardian] is not deployed silently."
    echo "[vaultguardian] Releases from v0.55.4+ publish observer.sha256 alongside the binary,"
    echo "[vaultguardian] so this usually means an older release, an interrupted download, or"
    echo "[vaultguardian] a network path that could not reach the checksum asset."
    echo "[vaultguardian] To update anyway (old releases, dev builds), re-run with:"
    echo "[vaultguardian]   OBSERVER_ALLOW_UNVERIFIED=1 vaultguardian update ${version}"
    return 1
}

case "$1" in
  update)
    VERSION="${2:-latest}"
    echo "[vaultguardian] Updating Observer to ${VERSION}..."
    cd /tmp
    rm -f observer observer.sha256
    if ! download_binary "$VERSION"; then
        exit 1
    fi
    if ! verify_binary "$VERSION"; then
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
# Startup checks and closing walkthrough (helpers)
# -------------------------------------------------------------------

# journal_snapshot - the current service invocation's log, timestamps
# stripped, so an upgrade does not match markers from the previous run.
journal_snapshot() {
    local inv
    inv=$(systemctl show -p InvocationID --value observer 2>/dev/null || true)
    if [ -n "$inv" ]; then
        journalctl -u observer "_SYSTEMD_INVOCATION_ID=$inv" --no-pager -o cat 2>/dev/null || true
    else
        journalctl -u observer --since "-2min" --no-pager -o cat 2>/dev/null || true
    fi
}

# api_listening - true when the dashboard API socket is bound on the
# address and port the env file asked for.
api_listening() {
    local pat addr
    if [ "$DASHBOARD_BIND_ADDR" = "0.0.0.0" ]; then
        pat="(0\.0\.0\.0|\*|\[::\]):${DASHBOARD_PORT}[[:space:]]"
    else
        addr=$(printf '%s' "$DASHBOARD_BIND_ADDR" | sed 's/\./\\./g')
        pat="$addr:${DASHBOARD_PORT}[[:space:]]"
    fi
    ss -ltn 2>/dev/null | grep -qE "$pat"
}

# run_startup_checks - poll the journal for up to STARTUP_TIMEOUT seconds
# and report each readiness marker as it appears. Never dumps raw log
# lines; anything unconfirmed points at 'vaultguardian logs'.
run_startup_checks() {
    local deadline=$((SECONDS + STARTUP_TIMEOUT))
    local snap n
    local c_pipeline=false c_docker=false c_rec=false c_journal=false
    local c_llm=false c_api=false c_key=false

    # Checks that do not apply on this box start out as done.
    [ "$DOCKER_FOUND" = true ]    || c_docker=true
    [ "$REC_ENABLED" = true ]     || c_rec=true
    [ "$JOURNALD_FOUND" = true ]  || c_journal=true
    command -v ss >/dev/null 2>&1 || c_api=true

    while [ "$SECONDS" -lt "$deadline" ]; do
        snap=$(journal_snapshot)

        if [ "$c_pipeline" = false ] && grep -q "Pipeline ready" <<<"$snap"; then
            ok "Pipeline ready"
            c_pipeline=true
        fi

        if [ "$c_docker" = false ]; then
            if grep -q "Found [0-9]* running containers" <<<"$snap"; then
                n=$(grep -o "Found [0-9]* running containers" <<<"$snap" | tail -1 | grep -o "[0-9]*" || true)
                ok "Docker: ${n:-?} containers streaming"
                c_docker=true
            elif grep -q "Docker watcher error" <<<"$snap"; then
                warn "Docker: $(grep "Docker watcher error" <<<"$snap" | tail -1)"
                c_docker=true
            fi
        fi

        if [ "$c_rec" = false ] && grep -q "Response Evidence Capture started" <<<"$snap"; then
            ok "Evidence capture: active"
            c_rec=true
        fi

        if [ "$c_journal" = false ] && grep -q "Streaming journal entries" <<<"$snap"; then
            ok "Host OS: journald streaming"
            c_journal=true
        fi

        if [ "$c_llm" = false ]; then
            if grep -q "LLM inference server connected" <<<"$snap"; then
                ok "LLM: connected"
                c_llm=true
            elif grep -qE "LLM not ready|LLM_ERROR" <<<"$snap"; then
                warn "LLM: not reachable yet (check LLM_URL / API key)"
                c_llm=true
            fi
        fi

        if [ "$c_api" = false ] && api_listening; then
            ok "Dashboard API: listening on $DASHBOARD_BIND_ADDR:$DASHBOARD_PORT"
            c_api=true
        fi

        if [ "$c_key" = false ] && [ -s "$KEY_FILE" ]; then
            ok "Dashboard token: ready"
            c_key=true
        fi

        if [ "$c_pipeline" = true ] && [ "$c_docker" = true ] && [ "$c_rec" = true ] \
            && [ "$c_journal" = true ] && [ "$c_llm" = true ] && [ "$c_api" = true ] \
            && [ "$c_key" = true ]; then
            break
        fi
        sleep 1
    done

    local hint="not confirmed in ${STARTUP_TIMEOUT}s, check 'vaultguardian logs'"
    [ "$c_pipeline" = true ] || warn "Pipeline ready: $hint"
    [ "$c_docker" = true ]   || warn "Docker: $hint"
    [ "$c_rec" = true ]      || warn "Evidence capture: $hint"
    [ "$c_journal" = true ]  || warn "Host OS journald: $hint"
    [ "$c_llm" = true ]      || warn "LLM: $hint"
    [ "$c_key" = true ]      || warn "Dashboard token: not written yet, check 'vaultguardian logs'"
    if [ "$c_api" = false ]; then
        if [ "$HOSTED_DASHBOARD" = true ]; then
            warn "Dashboard API: not listening on 0.0.0.0:$DASHBOARD_PORT after ${STARTUP_TIMEOUT}s. The hosted dashboard cannot reach it. Check 'vaultguardian logs'"
        else
            warn "Dashboard API: not listening on $DASHBOARD_BIND_ADDR:$DASHBOARD_PORT after ${STARTUP_TIMEOUT}s. Check 'vaultguardian logs'"
        fi
    fi
}

# firewall_hint - warn when ufw is active and the API port is not allowed.
# Cloud security groups cannot be detected from inside the box, so the
# walkthrough always mentions them too.
firewall_hint() {
    local status
    command -v ufw >/dev/null 2>&1 || return 0
    status=$(ufw status 2>/dev/null || true)
    if grep -q "^Status: active" <<<"$status" \
        && ! grep -qE "^$DASHBOARD_PORT(/tcp)?[[:space:]]+ALLOW" <<<"$status"; then
        warn "ufw is active and port $DASHBOARD_PORT is not open. Run: ufw allow $DASHBOARD_PORT/tcp"
    fi
}

# print_connect_steps - the final screen for hosted-dashboard installs.
# Everything the Add Instance form asks for, ready to copy.
print_connect_steps() {
    local token public_ip
    token=$(cat "$KEY_FILE" 2>/dev/null || true)
    public_ip=$(curl -4fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
    if [ -z "$public_ip" ]; then
        public_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    fi
    public_ip="${public_ip:-<this-server-public-ip>}"

    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    info "Next step: connect this server to your dashboard"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  1. Open $DASHBOARD_URL and click Add Instance"
    echo ""
    echo "  2. Enter these values:"
    echo ""
    echo -e "       Name:     ${GREEN}$SERVER_NICK${NC}"
    echo -e "       API URL:  ${GREEN}http://$public_ip:$DASHBOARD_PORT${NC}"
    if [ -n "$token" ]; then
        echo -e "       Token:    ${GREEN}$token${NC}"
    else
        echo "       Token:    (not written yet) get it with: sudo cat $KEY_FILE"
    fi
    echo ""
    echo "  3. Click Connect. $SERVER_NICK should show as online within a few seconds."
    echo ""
    echo "  Not connecting? Allow inbound TCP $DASHBOARD_PORT in your firewall and in"
    echo "  your cloud provider's security group, then try again."
    echo ""
    echo "  The token is this server's API password. It is stored root-only at"
    echo "  $KEY_FILE and you can print it again with: sudo cat $KEY_FILE"
    firewall_hint
    echo ""
}

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
# Order matters here: the hosted-dashboard walkthrough is the last thing
# printed so it is on screen when the script exits. No raw log dump.
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

    info "Startup checks (up to ${STARTUP_TIMEOUT}s):"
    run_startup_checks
    echo ""

    if [ "$PRESERVE_ENV" = true ]; then
        # Upgrade with preserved config - keep the summary minimal. The
        # user already knows their config; we'd have to source the env
        # file (which has spaces in some values like ALERT_EMAIL_FROM)
        # to recap it, and that's more risk than value.
        ok "Configuration preserved: $ENV_FILE"
        info "Inspect with: sudo cat $ENV_FILE   (root-only)"
    else
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

    # Dashboard block, always last.
    if [ "$PRESERVE_ENV" = true ]; then
        echo ""
        if [ "$HOSTED_DASHBOARD" = true ]; then
            info "Hosted dashboard: this server is set up for it (DASHBOARD_BIND_ADDR=0.0.0.0)."
            info "Token for $DASHBOARD_URL: sudo cat $KEY_FILE"
        else
            info "To connect the hosted dashboard: set DASHBOARD_BIND_ADDR=0.0.0.0 in $ENV_FILE, run 'vaultguardian restart', then add the server at $DASHBOARD_URL"
        fi
    elif [ "$HOSTED_DASHBOARD" = true ]; then
        print_connect_steps
    else
        # Bound to 127.0.0.1 (May 4 hardening): show the loopback + SSH
        # tunnel path so we never advertise an address that won't accept
        # connections, plus how to opt in to the hosted dashboard later.
        echo ""
        ok "Dashboard API: http://127.0.0.1:$DASHBOARD_PORT (loopback only)"
        info "From another machine: ssh -L $DASHBOARD_PORT:127.0.0.1:$DASHBOARD_PORT $(whoami)@$(hostname)"
        info "To expose on LAN: set DASHBOARD_BIND_ADDR=0.0.0.0 in $ENV_FILE and firewall the port"
        info "To connect the hosted dashboard later: set DASHBOARD_BIND_ADDR=0.0.0.0 in $ENV_FILE, run 'vaultguardian restart', then add the server at $DASHBOARD_URL"
        echo ""
    fi
else
    fail "Observer failed to start. Check: journalctl -u observer -n 50 --no-pager"
fi