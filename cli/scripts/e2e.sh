#!/usr/bin/env bash
# End-to-end check of the built CLI against a real Worker (wrangler dev, local
# D1): the contract between cli/ and worker/, which neither side's own tests
# can see. Needs `npm ci` done in both worker/ and cli/. Used by CI; runnable
# by hand:  bash cli/scripts/e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${PORT:-8791}"
URL="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d)"
DEV_PID=""
FAILED=0

# All descendants of $1, deepest last.
descendants() { local c; for c in $(pgrep -P "$1" 2>/dev/null); do echo "$c"; descendants "$c"; done; }

cleanup() {
  # wrangler dev is npx -> node -> workerd, and wrangler restarts workerd if
  # only that is killed. So take the list first, stop the parent, then the rest.
  if [ -n "$DEV_PID" ]; then
    local kids; kids="$(descendants "$DEV_PID")"
    kill "$DEV_PID" 2>/dev/null || true
    # shellcheck disable=SC2086
    [ -n "$kids" ] && kill $kids 2>/dev/null || true
    wait "$DEV_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILED=1; }
# check "label" "expected" "actual"
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: expected [$2], got [$3]"; fi; }
# has "label" "needle" "haystack"
has() { case "$3" in *"$2"*) pass "$1";; *) fail "$1: [$2] not in [$3]";; esac; }

echo "== build the CLI"
(cd "$ROOT/cli" && npm run build >/dev/null)
HUSH="node $ROOT/cli/dist/hush.mjs"

echo "== start a local Worker with a fresh database"
MASTER_KEY="$(openssl rand -base64 32)"
cd "$ROOT/worker"
npx wrangler d1 migrations apply DB --local --persist-to "$TMP/state" >/dev/null
ADMIN="$(node scripts/bootstrap-admin.mjs --name owner --expires 1d --local --persist-to "$TMP/state" 2>/dev/null)"
npx wrangler dev --port "$PORT" --ip 127.0.0.1 --persist-to "$TMP/state" --var "MASTER_KEY:$MASTER_KEY" >"$TMP/dev.log" 2>&1 &
DEV_PID=$!
for _ in $(seq 1 90); do curl -fsS "$URL/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$URL/healthz" >/dev/null || { echo "worker did not start:"; tail -30 "$TMP/dev.log"; exit 1; }

export HUSH_CONFIG_DIR="$TMP/cfg" HUSH_URL="$URL" HUSH_TOKEN="$ADMIN"
run() { set +e; OUT="$("$@" 2>&1)"; CODE=$?; set -e; }

echo "== admin: health, put, get, list, delete"
run $HUSH health;                          check "health exit" 0 "$CODE"; has "health auth" "auth: ok" "$OUT"
run $HUSH put llm.openai "sk-値-✓";        check "put exit" 0 "$CODE";    check "put output" "llm.openai: saved" "$OUT"
run $HUSH get llm.openai;                  check "get exit" 0 "$CODE";    check "get value" "sk-値-✓" "$OUT"
printf 'line1\nline2\n' | $HUSH put file.val --from-stdin >/dev/null
run $HUSH get file.val;                    check "stdin value keeps inner newline, drops the last" "$(printf 'line1\nline2')" "$OUT"
run $HUSH list;                            has "list shows names" "llm.openai" "$OUT"; has "list shows names (2)" "file.val" "$OUT"
run $HUSH list --json;                     has "list --json" '"name": "llm.openai"' "$OUT"
run $HUSH delete file.val;                 check "delete" "file.val: deleted" "$OUT"
run $HUSH delete file.val;                 check "delete is idempotent" 0 "$CODE"
run $HUSH get file.val;                    check "get after delete exits 1" 1 "$CODE"; has "get after delete says 404" "404" "$OUT"

echo "== errors"
run env HUSH_TOKEN=hush_wrong $HUSH get llm.openai; check "bad token exits 1" 1 "$CODE"; has "bad token says 401" "401" "$OUT"
run $HUSH get "bad name";                  check "invalid name rejected locally" 1 "$CODE"; has "invalid name message" "invalid name" "$OUT"

echo "== an agent token created through the admin API, used through the CLI"
AGENT="$(curl -fsS -X POST "$URL/v1/admin/tokens" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"llm-agent","role":"agent","prefixes":["llm."],"write_prefixes":["crawler."]}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$AGENT" ] || { fail "could not create an agent token"; }
run env HUSH_TOKEN="$AGENT" $HUSH get llm.openai;     check "agent reads inside its prefix" "sk-値-✓" "$OUT"
run env HUSH_TOKEN="$AGENT" $HUSH put other.x v;      check "agent write outside its prefix exits 1" 1 "$CODE"; has "agent write outside: 403" "403" "$OUT"
run env HUSH_TOKEN="$AGENT" $HUSH put crawler.t v1;   check "agent creates under its write prefix" "crawler.t: saved" "$OUT"
run env HUSH_TOKEN="$AGENT" $HUSH put crawler.t v2;   check "agent cannot overwrite" 1 "$CODE"; has "agent overwrite: 409" "409" "$OUT"
run env HUSH_TOKEN="$AGENT" $HUSH delete llm.openai;  check "agent cannot delete" 1 "$CODE"; has "agent delete: 403" "403" "$OUT"

echo "== /llm.html for agents"
PAGE="$(curl -fsS "$URL/llm.html")"
has "llm.html carries the real base URL" "$URL/v1/secrets/llm.openai" "$PAGE"
has "llm.html is instructions for agents" "instructions for LLM agents" "$PAGE"

echo
if [ "$FAILED" -ne 0 ]; then echo "E2E FAILED"; echo "--- worker log tail:"; tail -20 "$TMP/dev.log"; exit 1; fi
echo "E2E PASSED"
