#!/usr/bin/env bash
set -euo pipefail
eval "$("$HOME/.local/bin/mise" activate bash)"

# Required for systemctl --user to reach the session bus when invoked from
# non-login shells (e.g. agent/CI invocations).
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR}/bus}"

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/bin/auth-store"
UNIT_NAME="auth-store.service"
UNIT_DIR="$HOME/.config/systemd/user"

cd "$REPO_DIR"

echo "==> Compiling auth-store..."
go build -o /tmp/auth-store-build ./cmd/auth-store/

echo "==> Pushing..."
git push 2>/dev/null || echo "    (no remote or already up-to-date)"

echo "==> Stopping service..."
systemctl --user stop "$UNIT_NAME" 2>/dev/null || true
sleep 1

echo "==> Installing binary to $BIN..."
cp /tmp/auth-store-build "$BIN.new"
mv -f "$BIN.new" "$BIN"

echo "==> Installing systemd unit..."
mkdir -p "$UNIT_DIR"
cp "$REPO_DIR/auth-store.service" "$UNIT_DIR/$UNIT_NAME"
systemctl --user daemon-reload
systemctl --user enable "$UNIT_NAME" 2>/dev/null || true

echo "==> Starting service..."
systemctl --user start "$UNIT_NAME"

echo "==> Verifying..."
sleep 2
systemctl --user is-active "$UNIT_NAME"

echo "==> Health check..."
curl -fsS http://127.0.0.1:8303/health || {
  echo "FAILED — health check did not respond"
  exit 1
}
echo

echo "==> Done. auth-store is live on :8303."
