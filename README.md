# hush-hush

[![CI](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml/badge.svg)](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cjunks94/hush-hush?v=2)](https://goreportcard.com/report/github.com/cjunks94/hush-hush)
[![codecov](https://codecov.io/gh/cjunks94/hush-hush/branch/main/graph/badge.svg)](https://codecov.io/gh/cjunks94/hush-hush)
[![Go Version](https://img.shields.io/github/go-mod/go-version/cjunks94/hush-hush)](go.mod)
[![License: MIT](https://img.shields.io/github/license/cjunks94/hush-hush)](LICENSE)

A minimal self-hosted secret keeper. Single Go binary, SQLite, HTTPS API, AES-256-GCM at rest, per-agent tokens with read scopes (plus optional create-only write scopes) and an audit log. Made to run on a small Linux VPS under systemd behind Caddy; still runs anywhere a Go binary can run.

Built as a personal portfolio project — small enough to read in one sitting (~3k lines + tests), real enough to actually use.

## What this is

A tiny HTTPS API for storing your own API keys, database URLs, and OAuth secrets across personal projects. You `PUT` a value, you `GET` it back.

It is built for one human and a handful of automated agents (LLM tools, CI jobs, scripts) on one host. You hold an admin token; each agent gets its own token limited to the name prefixes it needs (read-only by default, optionally allowed to create new secrets in its own namespace), and every access is logged.

## What this isn't

- A team password manager (use [Vaultwarden](https://github.com/dani-garcia/vaultwarden))
- A Vault replacement (no policy language, no dynamic secrets, no PKI)
- Audited or compliant storage for customer data

## Threat model

Two encryption modes, intentionally layered. **v1 is the default**; v2 is opt-in and stacks on top.

### v1 — server-side AES-256-GCM (always on)

The master key is handed to the running process as a systemd credential file (or, for compatibility, the `MASTER_KEY` environment variable). AAD binds both the secret name and a version byte into the AEAD tag.

**Protects against:** stolen DB backups, leaked volume snapshots.
**Does not protect against:** host compromise — if an attacker gets a shell as the service user or root, key and ciphertext are both there. Same reason agents must run as a different Linux user than the server; see the [deployment guide](deploy/README.md#1-threat-model-in-one-page).

### v2 — client-side XChaCha20-Poly1305 (opt-in via `hush init`)

When a user runs `hush init`, the CLI creates a local vault file (`~/.config/hush/vault.json`, 0600) containing an Argon2id-derived passphrase verifier. From then on, `hush put` / `hush get` / `hush migrate` transparently encrypt and decrypt values with the user's passphrase. The server stores opaque ciphertext under v1's existing layer — two independent layers, two independent keys.

**Protects against:** host compromise. The user's passphrase never touches the server.
**Does not protect against:** client-side compromise (laptop + passphrase stolen). Same caveat any client-side-crypto system has.

**Catch:** non-CLI consumers (raw `curl` against `/v1/secrets/foo`) receive `hh2:base64...` for v2-encrypted secrets and can't decrypt them. v2 is for setups where every consumer either uses the `hush` CLI or vendors the vault decryption code.

The design decisions behind v2 — KDF choice, AEAD choice, wire format, why no server-side automation — are recorded in [`docs/adr/0001-client-side-encryption.md`](docs/adr/0001-client-side-encryption.md).

### Access control

**One owner, many agents.** Every caller has its own bearer token. Admin tokens read and write everything; agent tokens read only names under their prefixes and, if granted write prefixes, may create (never overwrite or delete) names under those. Tokens are stored as SHA-256 hashes and checked against the database on every request, so revocation takes effect immediately. Every `/v1/secrets` request lands in an audit log (names and outcomes, never values). None of this stops someone who can read the database file and master key directly, which is why the server runs as its own Linux user. Details in [Multi-agent access](#multi-agent-access).

## Architecture

```
agents / you               Linux VPS
  │           ┌─────────────────────────────────────────┐
  └── HTTPS ─►│ Caddy (TLS, automatic certificates)     │
              │   │  reverse_proxy 127.0.0.1:8080       │
              │   ▼                                     │
              │ hush-hush serve  (systemd, user `hush`) │
              │   │                                     │
              │   ▼                                     │
              │ SQLite + WAL   /var/lib/hush  (0700)    │
              │ master key     systemd credential       │
              └─────────────────────────────────────────┘
```

- TLS terminated by Caddy on the same host; the Go process listens on loopback only (`127.0.0.1:8080` by default) and speaks plain HTTP.
- AES-256-GCM with `(version_byte || name)` bound as AAD — defeats algorithm-downgrade and cross-name ciphertext rebinding.
- Random 12-byte nonce per write. Ciphertext stored as `version_byte || sealed_payload`.
- Per-caller bearer tokens (`hush_` + 64 hex chars), stored only as SHA-256, looked up by hash and re-compared with `subtle.ConstantTimeCompare` (no length oracle).
- Token and audit administration (`hush-hush token ...`, `hush-hush audit`) works directly on the database file. There is no management API to attack over the network.
- SQLite via `modernc.org/sqlite` — pure Go, no CGO, static binary. Schema migrations run automatically on startup.
- Structured logging via `log/slog` with a request-ID middleware that honors valid inbound `X-Request-ID` for end-to-end correlation.

## Deploy

**The supported path is a Linux VPS with systemd and Caddy: follow [`deploy/README.md`](deploy/README.md).** It covers the threat model, first install, token management, backups, upgrades and day-to-day operation, and ships a hardened [systemd unit](deploy/hush-hush.service) and a [Caddyfile](deploy/Caddyfile).

The short version, from a checkout of this repo:

```bash
sudo useradd --system --home /var/lib/hush --shell /usr/sbin/nologin hush
CGO_ENABLED=0 go build -trimpath -o hush-hush .
sudo install -o root -g root -m 0755 hush-hush /usr/local/bin/hush-hush
sudo install -d -o root -g root -m 0700 /etc/hush
sudo sh -c 'umask 077; openssl rand -base64 32 | tr -d "\n" > /etc/hush/master_key'
sudo install -m 0644 deploy/hush-hush.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hush-hush
curl -fsS http://127.0.0.1:8080/healthz   # server is up and has created the DB
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name admin-laptop --role admin
```

**Back up the master key somewhere offline** (password manager, paper). Lose it and every secret in the DB is unrecoverable, since the DB itself is just ciphertext. Keep it apart from your DB backups.

### Railway (compatibility only)

v0.1.0 was Railway-first and still runs there, but you lose the Linux-user separation the multi-agent model relies on, and there's no systemd credential for the key. Existing deployments keep working after two changes; new deployments should use the VPS path.

- The server now listens on `127.0.0.1` by default, which Railway's router can't reach, and `PORT` alone now means `127.0.0.1:$PORT`. Set `LISTEN_ADDR=0.0.0.0:8080` and also set `PORT=8080` explicitly so Railway routes to the same port.
- `AUTH_TOKEN` is deprecated. It still works as an admin token (named `env:AUTH_TOKEN` in the audit log). Named tokens need `hush-hush token create` run against the volume's DB file as its owner, which is awkward on Railway; the practical options are to keep `AUTH_TOKEN` or to create tokens on a downloaded copy of the DB and upload it back. Leave `TRUST_PROXY_HEADERS` unset: Railway's proxy isn't on loopback, so it would have no effect.

```
MASTER_KEY=<openssl rand -base64 32>
AUTH_TOKEN=<openssl rand -hex 32>        # deprecated, see above
DB_PATH=/data/hush.db                    # Railway Volume mounted at /data
LISTEN_ADDR=0.0.0.0:8080
PORT=8080
```

Verify with `curl https://<your-app>.up.railway.app/healthz` → `{"status":"ok"}`.

## API

All routes except `/healthz` require `Authorization: Bearer <token>`, with a token from `hush-hush token create`. What a token may do depends on its role; see [Multi-agent access](#multi-agent-access). All responses are JSON; all carry `Cache-Control: no-store` and `X-Request-ID`.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/healthz` | — | `{"status":"ok"}` |
| `GET` | `/v1/secrets` | — | `{"secrets":[{name, created_at, updated_at}, ...]}` (values omitted; capped at 1000 entries; agents only see names in scope) |
| `GET` | `/v1/secrets/{name}` | — | `{name, value, created_at, updated_at}` |
| `PUT` | `/v1/secrets/{name}` | `{"value":"..."}` | `{name, created_at, updated_at}` (admin only) |
| `DELETE` | `/v1/secrets/{name}` | — | `204` (admin only; idempotent — repeat calls and missing names also return 204) |

**Constraints:**
- Name: `^[a-zA-Z0-9_.-]{1,128}$` — no slashes or spaces. Use dots or underscores for hierarchy: `AWS_PROD.db.password`.
- Value: opaque string, max 64 KiB.
- `PUT` requires `Content-Type: application/json` (415 otherwise). Strict JSON parsing rejects unknown fields and trailing data.
- Auth errors: `401 {"error":"unauthorized"}` for a missing, unknown, revoked or expired token; `403 {"error":"forbidden"}` when the token's role or scope doesn't allow the request; `429 {"error":"rate_limited"}` with `Retry-After` when over the rate limit.

### Examples

```bash
URL=https://secrets.example.com
TOKEN='hush_<64 hex>'   # an admin token

# Store a secret
curl -X PUT $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"sk-..."}'

# Retrieve
curl $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN"

# List (names only, no values)
curl $URL/v1/secrets \
  -H "Authorization: Bearer $TOKEN"

# Delete
curl -X DELETE $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN"
```

## Multi-agent access

### Roles

| Role | Read | Write / delete | Scope |
|---|---|---|---|
| `admin` | yes | yes | every secret |
| `agent` | yes | create-only, never overwrite or delete | reads: names under its `--prefix` list; creates: names under its `--write-prefix` list (none by default) |

Prefixes must end in `.` or `_`, so `llm.` matches `llm.openai` but not `llmx.key`. A lone `*` prefix gives an agent read access to everything, including secrets added later; the CLI makes you retype the token name to confirm it. Name secrets hierarchically (`llm.openai`, `github.deploy_key`) and scoping falls out naturally.

**Create-only writes.** An agent given `--write-prefix crawler.` can `PUT` a *new* name under `crawler.`; if the name already exists it gets `409` and nothing changes, so it can't overwrite (or poison) a value someone else relies on. It can never `DELETE`. Write prefixes follow the same rules as read prefixes, except `*` is not allowed. A write grant doesn't imply read: add the same prefix with `--prefix` if the agent should read back what it creates. Give each agent its own namespace (`token create` warns when write prefixes of two agents overlap).

### What callers see

| Situation | Response |
|---|---|
| Missing, unknown, revoked or expired token | `401 {"error":"unauthorized"}` |
| Agent `DELETE`, or `PUT` outside its write prefixes | `403 {"error":"forbidden"}` |
| Agent `PUT` under a write prefix, name already exists | `409 {"error":"already exists"}` |
| Agent `GET` outside its prefixes, whether or not the name exists | `403 {"error":"forbidden"}` |
| In scope but not stored | `404 {"error":"not found"}` |
| Over the rate limit (default 60/min per token; 10/min per IP for failed auth) | `429 {"error":"rate_limited"}` + `Retry-After` |
| Agent `GET /v1/secrets` | `200`, filtered to its scope |

Every `/v1/secrets` request writes one `audit_log` row: time, token name, action, secret name, result, request ID and client IP. Never values, never tokens. Requests that match no route (wrong method, nested path) are recorded too, with action `other`. If the row can't be written, reads fail closed with 500, and PUT/DELETE are rolled back and return 500: a write and its audit row commit in the same transaction.

### Admin commands

These run on the server and open the database file directly. They must run as the user that owns the DB (they refuse otherwise) and won't create a missing DB, so start the service once first. `sudo` drops the environment, so pass `DB_PATH` (or `--db PATH`):

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name admin-laptop --role admin
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name llm-agent --role agent --prefix llm. --prefix github. --expires 90d
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token list
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name crawler --role agent --prefix crawler. --write-prefix crawler.
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token update --name llm-agent --prefix llm.
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token update --name crawler --no-write
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token revoke --name llm-agent
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --token llm-agent --result denied --since 7d
```

`token create` prints the token (`hush_` + 64 hex chars) once; only its hash is kept. Token names are never reused, even after a revoke. `audit` prints newest first and filters on `--token`, `--secret`, `--action get|list|put|delete|other`, `--result allowed|denied|not_found|conflict|unauthenticated|rate_limited|bad_request|error`, `--since` / `--until` (`7d`, `24h` or RFC3339) and `--limit` (default 100).

Rotation, backups, audit pruning and moving off `AUTH_TOKEN` are covered in [`deploy/README.md`](deploy/README.md).

If you are writing an agent or script that consumes secrets, hand it [`docs/agent-guide.md`](docs/agent-guide.md): endpoints, status-code handling, retry rules, code samples and a system-prompt snippet for LLM agents (in Chinese).

## CLI

A thin client lives in [`cmd/hush`](cmd/hush). Install:

```bash
go install github.com/cjunks94/hush-hush/cmd/hush@latest
```

Configure once, then forget the URL and token exist:

```bash
hush login --url https://secrets.example.com --token 'hush_<64 hex>'
# writes ~/.config/hush/config.json (mode 0600)

hush health
# https://...: reachable
# auth: ok
```

Day-to-day use:

```bash
# Write
hush put openai-key "sk-..."          # positional value
hush put openai-key --from-file ./key # from a file
echo "sk-..." | hush put openai-key --from-stdin
hush put openai-key                   # interactive no-echo prompt (TTY only)

# Read — value-only output, pipe-friendly
hush get openai-key
hush get openai-key | clip            # Windows
hush get openai-key | pbcopy          # macOS

# List
hush list                             # table
hush list --json                      # machine-readable

# Delete
hush delete openai-key                # idempotent
```

The CLI works with any token. With an agent token, `hush list` shows only in-scope names, `hush delete` gets a 403, and `hush put` works only for new names under the token's write prefixes (409 if the name exists, 403 elsewhere).

**Config precedence:** `--url`/`--token` flag > `HUSH_URL`/`HUSH_TOKEN` env > config file. Useful for one-off invocations against a non-default server without re-running `login`.

### Opt-in to client-side encryption (v2)

Once `hush init` is run, every `hush put` encrypts the value with the user's passphrase before sending. `hush get` reverses it. The server never sees plaintext.

```bash
hush init
# vault passphrase: ********
# confirm passphrase: ********
# vault initialized at ~/.config/hush/vault.json (mode 0600)
#
# IMPORTANT: back up this passphrase somewhere safe.
# If you lose it, every v2-encrypted secret in your vault is unrecoverable.

# Existing v1 secrets show this hint until migrated:
hush get legacy-secret
# error: get: "legacy-secret" is a v1 plaintext secret; run `hush migrate` to convert it

# Preview the migration scope:
hush migrate --dry-run
# vault passphrase: ********
# would migrate: legacy-secret
# done: 1 would migrate, 0 skipped (already v2), 0 errors

# Do it:
hush migrate
# vault passphrase: ********
# migrated: legacy-secret
# done: 1 migrated, 0 skipped (already v2), 0 errors
```

**Before activating v2 on a deployment with non-CLI consumers**, see the threat-model "Catch" above — raw HTTP consumers can't decrypt `hh2:`-prefixed values.

## Local development

```bash
# Generate a key for local use
export MASTER_KEY=$(openssl rand -base64 32)
export DB_PATH=./hush.db

# Run the server (listens on 127.0.0.1:8080)
go run .

# In another shell, same DB_PATH: create a token
go run . token create --name dev --role admin

# Test
go test ./...
go test -cover ./...
```

Requires Go 1.24+ (set in `go.mod`).

## Security tooling

CI runs on every push, every PR, and a weekly Mon 06:00 UTC cron:

| Tool | Purpose |
|---|---|
| `go vet` + `go build` + `go test` | Compile + correctness |
| `go mod verify` | Module checksum integrity |
| [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Stdlib + dependency CVE scan against the live Go vuln DB |
| [`gosec`](https://github.com/securego/gosec) | Static security analysis (medium+ severity) |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Scans git history for committed secrets |
| Dependabot | Weekly grouped updates for `gomod` and `github-actions` ecosystems |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review with project-specific instructions |

Tool versions are pinned to specific tags / commit SHAs to defeat `@latest` supply-chain drift; Dependabot opens PRs to bump them as new releases ship.

## Limitations

- **Client-side encryption requires CLI consumers.** v2 (`hush init` + `hush migrate`) protects against host compromise, but raw-HTTP consumers can't decrypt `hh2:` values. Either every consumer uses the CLI / vendors the vault code, or v2 stays off for that deployment. See [`docs/adr/0001-client-side-encryption.md`](docs/adr/0001-client-side-encryption.md) for the full design discussion.
- **No passphrase caching.** v2 prompts every command. OS keychain integration (`--remember` flag) is plausible future work, deferred for now to keep the trust surface minimal.
- **No key-rotation tooling.** If the v1 master key leaks, recovery is manual: rotate, decrypt all rows under old key, re-encrypt under new key, swap env var. If the v2 passphrase leaks: change passphrase via re-init + manual re-puts (no automated re-key yet).
- **One owner, not a team tool.** Two roles only (admin, agent). No per-human accounts, no groups. Agents can at most create new secrets under their own write prefixes; they can't overwrite or delete.
- **Rate limits live in memory** and reset on restart. Fine for one process on one host.
- **The audit log grows without bound** and has no built-in retention; prune it by hand (see [operational notes](deploy/README.md#9-operational-notes)). It only sees API access: anyone who can read the DB file directly bypasses it.
- **No web UI / browser extension.**

If you need any of these, [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Infisical](https://github.com/Infisical/infisical) are good self-hosted alternatives.

## License

MIT. See [LICENSE](LICENSE).
