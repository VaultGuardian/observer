#!/usr/bin/env bash
#
# release.sh — build, checksum, and publish an Observer release.
#
# Usage:
#   ./release.sh vX.Y.Z "Release title" "Release notes"
#
# Builds the linux/amd64 binary with the version baked in, generates
# observer.sha256 so install.sh can verify the download, and publishes both
# as assets on a GitHub release. Runs the same gofmt/vet/test gate as CI
# first so a broken build never ships.
#
# Commit/push and server deploy (`vaultguardian update vX.Y.Z`) stay manual —
# this script only cuts the release.
set -euo pipefail
VERSION="${1:-}"
TITLE="${2:-}"
NOTES="${3:-}"
REPO="VaultGuardian/observer"
# --- args ---
if [ -z "$VERSION" ]; then
  echo "usage: ./release.sh vX.Y.Z \"Release title\" \"Release notes\""
  exit 1
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo "version must look like vX.Y.Z (got: $VERSION)"
  exit 1
fi
command -v gh >/dev/null 2>&1 || { echo "gh CLI not found — install + 'gh auth login'"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated — run 'gh auth login'"; exit 1; }
# --- pre-release gate (same as CI) ---
echo "==> gofmt / vet / test"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "gofmt issues — fix before releasing:"; echo "$unformatted"; exit 1
fi
go vet ./...
go test ./... -count=1
# --- build ---
echo "==> building $VERSION (linux/amd64)"
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$VERSION" -o observer .
# Confirm the version actually baked in by running the real artifact (the
# build target is linux/amd64; if this host can execute it, verify — otherwise
# skip rather than false-alarm). NOTE: `go run .` would recompile WITHOUT the
# ldflags and always report "dev", so we must run the built binary itself.
if BUILT_VER=$(./observer --version 2>/dev/null | awk '{print $2}'); then
  if [ -n "$BUILT_VER" ] && [ "$BUILT_VER" != "$VERSION" ]; then
    echo "warning: built binary reports '$BUILT_VER', expected '$VERSION'"
  fi
fi
# --- checksum ---
sha256sum observer > observer.sha256
echo "==> sha256: $(awk '{print $1}' observer.sha256)"
# --- publish ---
echo "==> creating GitHub release $VERSION"
gh release create "$VERSION" ./observer ./observer.sha256 \
  --repo "$REPO" \
  --title "${TITLE:-Observer $VERSION}" \
  --notes "${NOTES:-Release $VERSION}"
# --- cleanup local artifacts (they're published now) ---
rm -f observer observer.sha256
echo "==> done."
echo "    install.sh will now fetch observer.sha256 for $VERSION and verify the binary."
echo "    Deploy to a server with: vaultguardian update $VERSION"
