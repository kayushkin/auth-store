#!/usr/bin/env bash
set -euo pipefail

# One shared gate decides whether this tree may be deployed (main clone, default
# branch, clean, pushed, not behind, and the same for every tree the build reads).
# It lives in healthcheck/scripts/deploy-gate.sh. Do not inline or copy it.
( cd "$(dirname "$0")" && "$HOME/bin/deploy-gate" check )
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

# A set AUTHSTORE_ variable that settings.go does not declare stops the new
# binary at boot. Ask before the old one is stopped: build the registry from the
# running service's own environment. The test prints a verdict, never a value.
echo "==> Checking the running service's environment against the declared settings..."
live_pid="$(systemctl --user show -p MainPID --value "$UNIT_NAME")"
if [ -n "$live_pid" ] && [ "$live_pid" != "0" ]; then
  go test -count=1 -run '^TestTheLiveProcessEnvironmentBuildsARegistry$' . -args -live-environment-file="/proc/$live_pid/environ"
else
  echo "    $UNIT_NAME is not running, so there is no environment to check"
fi

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

# Last act: write this deploy to repo-store's ledger, so the next agent sees what is live.
( cd "$(dirname "$0")" && "$HOME/bin/deploy-gate" record )
