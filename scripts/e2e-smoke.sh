#!/usr/bin/env bash
# Boot-and-answer smoke test for auth-store.
#
# Builds cmd/auth-store from THIS checkout, boots it against a throwaway SQLite
# file on a throwaway port, and drives real HTTP routes. Proves the committed
# tree produces a binary that BOOTS (a Go 1.22+ ServeMux route conflict panics
# at registration time — it compiles green and dies on start) and ANSWERS.
#
# auth-store is the credential vault, so this smoke asserts the three invariants
# that make it one, not merely that it returns 200:
#
#   1. AUTH IS ENFORCED.       /api/* without the bearer token is 401, and the
#                              secret-bearing routes additionally demand
#                              X-Auth-App + X-Auth-Reason (400 without them).
#   2. SECRETS ARE MASKED.     GET /api/credentials and /api/credentials/{id}
#                              return MaskSecret'd values. The plaintext secret
#                              must not appear ANYWHERE in those response bodies
#                              — a regression here is a credential leak.
#   3. ACCESS IS AUDITED.      A successful /resolve — the one route that does
#                              hand back plaintext — lands in /api/audit with the
#                              app and reason that asked for it.
#
# NEVER TOUCHES THE LIVE VAULT. The live service runs on :8303 against
# ~/.config/auth-store/auth.db. Passing --db is MANDATORY: authstore.Open("")
# falls back to that path and unconditionally runs migrate() (CREATE/ALTER) on
# it, so an omitted flag does not read the live vault, it MUTATES it. This
# script always passes an explicit --db under $TMP_DIR, and asserts afterwards
# that no live DB path was created under the sandboxed HOME.
#
# The credential written here is a fake ("sk-smoke-..."), lives only in the temp
# DB, and is deleted before exit. No real provider is ever contacted: an empty
# DB has no OAuth credential to refresh, and refresh is lazy (only Resolve on an
# expired refresh_mode=server OAuth cred dials out — this smoke stores an
# api_key, never an OAuth token).
#
# Exits 0 on success, non-zero on the first failing assertion; dumps the server
# log to stderr on failure.
#
# Tunables:
#   E2E_PORT — auth-store listen port (default 19112)
#   E2E_KEEP — set to "1" to leave $TMP_DIR around after the run

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${E2E_PORT:-19112}"
BASE="http://127.0.0.1:$PORT"

# auth-store uses modernc.org/sqlite (pure Go) — no cgo, no C compiler needed.
for bin in go curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: required tool '$bin' not found on PATH" >&2
    exit 2
  fi
done

TMP_DIR="$(mktemp -d -t auth-store-e2e.XXXXXX)"
BIN_DIR="$TMP_DIR/bin"
DATA_DIR="$TMP_DIR/data"
DB_PATH="$DATA_DIR/auth.db"
BODY="$TMP_DIR/body.json"
mkdir -p "$BIN_DIR" "$DATA_DIR"

# The one secret this smoke writes. Longer than 12 chars so MaskSecret takes its
# first4 + "..." + last4 branch rather than the all-asterisks one — that is the
# branch the real credentials take, so it is the one worth pinning.
SECRET="sk-smoke-not-a-real-key-0000-abcd1234"
MASKED="sk-s...1234"
TOKEN="smoke-token-$$"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ "${E2E_KEEP:-}" = "1" ]; then
    echo "[e2e] keeping $TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  if [ -f "$TMP_DIR/server.log" ]; then
    echo "----- server.log -----" >&2
    cat "$TMP_DIR/server.log" >&2
  fi
  exit 1
}

# req METHOD PATH [JSON] [EXTRA_CURL_ARGS...] — prints the HTTP status; body → $BODY.
# No -f: 4xx/5xx are expected outcomes for the auth assertions and must not abort.
req() {
  local method="$1" path="$2" data="${3:-}"
  shift 3 2>/dev/null || shift $#
  local args=(-sS -o "$BODY" -w '%{http_code}' --max-time 15 -X "$method" "$BASE$path")
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' -d "$data")
  fi
  args+=("$@")
  curl "${args[@]}"
}

# areq — req, with the bearer token attached. The normal case for /api/*.
# Forwards any trailing curl args (the X-Auth-App / X-Auth-Reason headers).
areq() {
  local method="$1" path="$2" data="${3:-}"
  shift 3 2>/dev/null || shift $#
  req "$method" "$path" "$data" -H "Authorization: Bearer $TOKEN" "$@"
}

expect() {
  local want="$1" got="$2" what="$3"
  if [ "$want" != "$got" ]; then
    echo "----- response body -----" >&2
    cat "$BODY" >&2
    echo >&2
    fail "$what: expected HTTP $want, got $got"
  fi
}

jget() { jq -r "$1" "$BODY"; }

assert_eq() {
  [ "$1" = "$2" ] || fail "$3: expected '$1', got '$2'"
}

# The leak guard. Greps the RAW response bytes, not a parsed field — a secret
# leaking through some field this smoke never thought to check is exactly the
# regression worth catching.
assert_no_plaintext() {
  if grep -qF "$SECRET" "$BODY"; then
    echo "----- response body -----" >&2
    cat "$BODY" >&2
    echo >&2
    fail "$1: the PLAINTEXT SECRET appeared in the response body"
  fi
}

# ============================================================================
step "build cmd/auth-store from $REPO_DIR"
cd "$REPO_DIR"
go build -o "$BIN_DIR/auth-store" ./cmd/auth-store
echo "    binary: $(ls -lh "$BIN_DIR/auth-store" | awk '{print $5}')"

# ============================================================================
step "boot auth-store on :$PORT against a throwaway db"
# --db is load-bearing: without it, Open("") resolves to ~/.config/auth-store/auth.db
# — the LIVE VAULT — and migrates it. HOME is redirected too so that even a
# regression that ignores --db cannot reach the real path.
AUTHSTORE_TOKEN="$TOKEN" \
HOME="$TMP_DIR/home" \
  "$BIN_DIR/auth-store" --db "$DB_PATH" --port "$PORT" \
  >>"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "    pid: $SERVER_PID  db: $DB_PATH"

# Poll — never sleep-and-hope. Abort the instant the pid dies, so a route
# registration panic surfaces as a clear failure instead of a mystery timeout.
OK=""
for _ in $(seq 1 75); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "auth-store exited during startup (route-registration panic? db migration?)"
  fi
  if curl -fsS --max-time 2 -o /dev/null "$BASE/health" 2>/dev/null; then OK=1; break; fi
  sleep 0.2
done
[ -n "$OK" ] || fail "auth-store did not answer /health on $BASE within ~15s"

step "GET /health — public, no bearer required"
CODE=$(req GET /health); expect 200 "$CODE" "/health"
assert_eq ok "$(jget '.status')" "health status"

# ============================================================================
# INVARIANT 1 — auth is enforced.
# ============================================================================
step "GET /api/credentials with NO bearer — 401"
CODE=$(req GET /api/credentials); expect 401 "$CODE" "/api/credentials unauthenticated"

step "GET /api/credentials with a WRONG bearer — 401"
CODE=$(req GET /api/credentials "" -H "Authorization: Bearer not-the-token")
expect 401 "$CODE" "/api/credentials with a bad token"

step "GET /api/credentials with the bearer — 200, and the fresh vault is empty"
CODE=$(areq GET /api/credentials); expect 200 "$CODE" "/api/credentials"
assert_eq 0 "$(jget 'length')" "fresh vault credential count"

# ============================================================================
# INVARIANT 2 — secrets are masked on the listing routes.
# ============================================================================
step "POST /api/credentials — store a (fake) api_key credential"
CODE=$(areq POST /api/credentials \
  "{\"provider\":\"smoke\",\"owner\":\"e2e\",\"auth_type\":\"api_key\",\"api_key\":\"$SECRET\",\"label\":\"e2e smoke\",\"intended_app\":\"e2e-smoke\"}")
expect 201 "$CODE" "POST /api/credentials"
CRED_ID="$(jget '.id')"
[ -n "$CRED_ID" ] && [ "$CRED_ID" != "null" ] || fail "POST /api/credentials returned no id"
assert_eq smoke "$(jget '.provider')" "created credential provider"
assert_no_plaintext "POST /api/credentials response"
echo "    credential id: $CRED_ID"

step "POST /api/credentials — required fields are validated"
CODE=$(areq POST /api/credentials '{"owner":"e2e","auth_type":"api_key"}')
expect 400 "$CODE" "POST /api/credentials with no provider"
CODE=$(areq POST /api/credentials '{"provider":"smoke","auth_type":"api_key"}')
expect 400 "$CODE" "POST /api/credentials with no owner"
CODE=$(areq POST /api/credentials '{"provider":"smoke","owner":"e2e"}')
expect 400 "$CODE" "POST /api/credentials with no auth_type"

step "GET /api/credentials — the secret comes back MASKED, never in plaintext"
CODE=$(areq GET /api/credentials); expect 200 "$CODE" "GET /api/credentials"
assert_eq 1 "$(jget 'length')" "vault credential count"
assert_no_plaintext "GET /api/credentials (list)"
assert_eq "$MASKED" "$(jget ".[] | select(.id==\"$CRED_ID\") | .api_key")" \
  "listed api_key is MaskSecret'd"

step "GET /api/credentials/{id} — same, on the single-credential route"
CODE=$(areq GET "/api/credentials/$CRED_ID"); expect 200 "$CODE" "GET /api/credentials/{id}"
assert_no_plaintext "GET /api/credentials/{id}"
assert_eq "$MASKED" "$(jget '.api_key')" "single-read api_key is MaskSecret'd"
assert_eq "e2e smoke" "$(jget '.label')" "single-read label"

step "GET /api/credentials/{id} — unknown id is a 404, not a panic"
CODE=$(areq GET /api/credentials/does-not-exist)
expect 404 "$CODE" "GET unknown credential"

# ============================================================================
# INVARIANT 1 (cont.) — the secret-bearing route demands app + reason.
# ============================================================================
step "GET /api/credentials/{id}/resolve with no X-Auth-App/X-Auth-Reason — 400"
CODE=$(areq GET "/api/credentials/$CRED_ID/resolve")
expect 400 "$CODE" "/resolve without app+reason"
assert_no_plaintext "/resolve rejected for missing app+reason"

step "GET /api/credentials/{id}/resolve with no bearer at all — 401"
CODE=$(req GET "/api/credentials/$CRED_ID/resolve" "" \
  -H 'X-Auth-App: e2e-smoke' -H 'X-Auth-Reason: smoke test')
expect 401 "$CODE" "/resolve without a bearer"
assert_no_plaintext "/resolve rejected for missing bearer"

# ============================================================================
# The vault's actual job: resolve DOES hand back the plaintext, to a caller that
# named itself and said why.
# ============================================================================
step "GET /api/credentials/{id}/resolve with app+reason — returns the PLAINTEXT"
CODE=$(areq GET "/api/credentials/$CRED_ID/resolve" "" \
  -H 'X-Auth-App: e2e-smoke' -H 'X-Auth-Reason: boot-and-answer smoke')
expect 200 "$CODE" "/resolve with app+reason"
assert_eq "$SECRET" "$(jget '.api_key')" "resolved api_key is the plaintext we stored"
assert_eq api_key "$(jget '.auth_type')" "resolved auth_type"

step "GET /api/resolve/{provider} — resolve by provider works too"
CODE=$(areq GET "/api/resolve/smoke" "" \
  -H 'X-Auth-App: e2e-smoke' -H 'X-Auth-Reason: boot-and-answer smoke')
expect 200 "$CODE" "/api/resolve/{provider}"
assert_eq "$SECRET" "$(jget '.api_key')" "provider-resolved api_key"
assert_eq "$CRED_ID" "$(jget '.id')" "provider-resolved credential id"

# ============================================================================
# INVARIANT 3 — every resolve is audited.
# ============================================================================
step "GET /api/audit — the resolves were recorded with their app and reason"
CODE=$(areq GET "/api/audit?credential_id=$CRED_ID&action=resolve")
expect 200 "$CODE" "GET /api/audit"
AUDIT_N="$(jget 'length')"
[ "$AUDIT_N" -ge 2 ] || fail "expected >=2 audited resolves for $CRED_ID, got $AUDIT_N"
assert_eq e2e-smoke "$(jget '.[0].app')" "audited app"
assert_eq "boot-and-answer smoke" "$(jget '.[0].reason')" "audited reason"
assert_eq true "$(jget '.[0].ok')" "audited ok"
assert_no_plaintext "GET /api/audit"
echo "    $AUDIT_N resolve entries audited"

step "GET /api/audit — the CREATE was audited too"
CODE=$(areq GET "/api/audit?credential_id=$CRED_ID&action=create")
expect 200 "$CODE" "GET /api/audit?action=create"
[ "$(jget 'length')" -ge 1 ] || fail "the credential create was not audited"

# ============================================================================
step "DELETE /api/credentials/{id} — and it is really gone"
CODE=$(areq DELETE "/api/credentials/$CRED_ID"); expect 204 "$CODE" "DELETE credential"
CODE=$(areq GET "/api/credentials/$CRED_ID"); expect 404 "$CODE" "GET deleted credential"
CODE=$(areq GET /api/credentials); expect 200 "$CODE" "GET /api/credentials after delete"
assert_eq 0 "$(jget 'length')" "vault is empty again"

step "the server is still alive after all those rejections"
CODE=$(req GET /health); expect 200 "$CODE" "/health at end of run"

# ============================================================================
# Hermeticity — prove we never went near the real vault.
# ============================================================================
step "hermeticity: no vault was created under the sandboxed HOME"
if [ -e "$TMP_DIR/home/.config/auth-store" ]; then
  fail "auth-store wrote to \$HOME/.config/auth-store despite an explicit --db — the --db flag is being ignored"
fi
[ -f "$DB_PATH" ] || fail "the throwaway db was never created at $DB_PATH"
echo "    only $DB_PATH was written"

step "SUCCESS — auth-store boots and answers from this tree"
echo "    server log: $TMP_DIR/server.log"
