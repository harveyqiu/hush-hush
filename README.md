# hush-hush

[![CI](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml/badge.svg)](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cjunks94/hush-hush?v=2)](https://goreportcard.com/report/github.com/cjunks94/hush-hush)
[![codecov](https://codecov.io/gh/cjunks94/hush-hush/branch/main/graph/badge.svg)](https://codecov.io/gh/cjunks94/hush-hush)
[![Go Version](https://img.shields.io/github/go-mod/go-version/cjunks94/hush-hush)](go.mod)
[![License: MIT](https://img.shields.io/github/license/cjunks94/hush-hush)](LICENSE)

A minimal self-hosted secret keeper. Single Go binary, SQLite, HTTPS API, AES-256-GCM at rest, per-agent tokens with read scopes (plus optional create-only write scopes) and an audit log. Ships as one small Docker image with an embedded admin web UI; put it behind your own HTTPS reverse proxy.

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

The master key is handed to the container as a Docker secret file (`MASTER_KEY_FILE`), or as the `MASTER_KEY` environment variable. AAD binds both the secret name and a version byte into the AEAD tag.

**Protects against:** stolen DB backups, leaked volume snapshots.
**Does not protect against:** host compromise — anyone who can reach the Docker daemon, the data volume or the key file has both key and ciphertext. Same reason agents must never get Docker access; see the [deployment guide](docs/docker.md#1-威胁模型).

### v2 — client-side XChaCha20-Poly1305 (opt-in via `hush init`)

When a user runs `hush init`, the CLI creates a local vault file (`~/.config/hush/vault.json`, 0600) containing an Argon2id-derived passphrase verifier. From then on, `hush put` / `hush get` / `hush migrate` transparently encrypt and decrypt values with the user's passphrase. The server stores opaque ciphertext under v1's existing layer — two independent layers, two independent keys.

**Protects against:** host compromise. The user's passphrase never touches the server.
**Does not protect against:** client-side compromise (laptop + passphrase stolen). Same caveat any client-side-crypto system has.

**Catch:** non-CLI consumers (raw `curl` against `/v1/secrets/foo`) receive `hh2:base64...` for v2-encrypted secrets and can't decrypt them. v2 is for setups where every consumer either uses the `hush` CLI or vendors the vault decryption code.

The design decisions behind v2 — KDF choice, AEAD choice, wire format, why no server-side automation — are recorded in [`docs/adr/0001-client-side-encryption.md`](docs/adr/0001-client-side-encryption.md).

### Access control

**One owner, many agents.** Every caller has its own bearer token. Admin tokens read and write everything; agent tokens read only names under their prefixes and, if granted write prefixes, may create (never overwrite or delete) names under those. Tokens are stored as SHA-256 hashes and checked against the database on every request, so revocation takes effect immediately. Every `/v1/secrets` request lands in an audit log (names and outcomes, never values). None of this stops someone who can read the data volume and master key directly, which is why agents must not have access to the Docker daemon, the volume or the key file. Details in [Multi-agent access](#multi-agent-access).

## Architecture

```
agents / you              your host
  │          ┌──────────────────────────────────────────────┐
  └─ HTTPS ─►│ your reverse proxy (TLS)                     │
             │   │  proxy_pass 127.0.0.1:8080               │
             │   ▼                                          │
             │ ┌── container: hush-hush (uid 65532) ──────┐ │
             │ │ API /v1/*  ·  admin UI /ui/              │ │
             │ │ SQLite + WAL on volume /data  (0700)     │ │
             │ │ master key from /run/secrets/master_key  │ │
             │ └──────────────────────────────────────────┘ │
             └──────────────────────────────────────────────┘
```

- One distroless image (~22 MB): static Go binary, no shell, non-root, read-only root filesystem in the provided compose file.
- TLS is your reverse proxy's job. The container listens on `0.0.0.0:8080` inside its network; the compose file publishes it on the host's `127.0.0.1` only.
- AES-256-GCM with `(version_byte || name)` bound as AAD — defeats algorithm-downgrade and cross-name ciphertext rebinding.
- Random 12-byte nonce per write. Ciphertext stored as `version_byte || sealed_payload`.
- Per-caller bearer tokens (`hush_` + 64 hex chars), stored only as SHA-256, looked up by hash and re-compared with `subtle.ConstantTimeCompare` (no length oracle).
- Tokens and the audit log can be managed from the web UI / admin API (admin tokens only, every call audited) or from the CLI inside the container. `ADMIN_API=false` removes the HTTP management surface entirely.
- SQLite via `modernc.org/sqlite` — pure Go, no CGO, static binary. Schema migrations run automatically on startup.
- Structured logging via `log/slog` to stdout (`docker logs`) with a request-ID middleware that honors valid inbound `X-Request-ID` for end-to-end correlation.

## Deploy (Docker)

Full guide, in Chinese: [`docs/docker.md`](docs/docker.md). The short version, from a checkout of this repo:

```bash
openssl rand -base64 32 > master_key                  # back this up offline, apart from data backups
sudo chown 65532:65532 master_key && sudo chmod 400 master_key
docker compose up -d                                  # builds the image, starts on 127.0.0.1:8080
docker compose exec hush hush-hush token create --name admin --role admin --expires 30d
```

Point your HTTPS reverse proxy at `127.0.0.1:8080`, open `https://<your-host>/ui/` and log in with the admin token.

**Traefik:** `compose.traefik.yaml` is an overlay that drops the host port, attaches the container to Traefik's network with router labels, trusts only Traefik for `X-Forwarded-For`, and restricts `/ui` and `/v1/admin` to an IP allowlist while `/v1/secrets` stays reachable for agents. Copy `.env.example` to `.env`, fill it in, `docker compose up -d`. Needs Traefik ≥ v3.6 on Docker 29+. Details in [`docs/docker.md`](docs/docker.md).

Without compose:

```bash
docker build -t hush-hush .
docker volume create hush-data
docker run -d --name hush --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v hush-data:/data \
  -v "$PWD/master_key:/run/secrets/master_key:ro" -e MASTER_KEY_FILE=/run/secrets/master_key \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges hush-hush
```

**Lose the master key and every secret in the DB is unrecoverable**, since the DB itself is just ciphertext.

| Variable | Default | Meaning |
|---|---|---|
| `MASTER_KEY_FILE` | – | Path to a file holding the base64 32-byte key (Docker secret). Preferred. |
| `MASTER_KEY` | – | The key itself. Use one of the two, not both. |
| `DB_PATH` | `/data/hush.db` in the image | SQLite file. |
| `LISTEN_ADDR` | `0.0.0.0:8080` in the image (`127.0.0.1:8080` for the bare binary) | Bind address. |
| `TRUSTED_PROXIES` | none | CIDRs/IPs whose `X-Forwarded-For` is believed (the compose file trusts its network gateway). |
| `RATE_LIMIT_PER_MINUTE` | 60 | Per token. |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | 10 | Per client IP, failed authentication only. |
| `ADMIN_API` | `true` | `false` disables `/v1/admin/*` and the web UI. |

## API

All routes except `/healthz` require `Authorization: Bearer <token>`, with a token from `hush-hush token create`. What a token may do depends on its role; see [Multi-agent access](#multi-agent-access). All responses are JSON; all carry `Cache-Control: no-store` and `X-Request-ID`.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/healthz` | — | `{"status":"ok"}` |
| `GET` | `/v1/secrets` | — | `{"secrets":[{name, created_at, updated_at}, ...]}` (values omitted; capped at 1000 entries; agents only see names in scope) |
| `GET` | `/v1/secrets/{name}` | — | `{name, value, created_at, updated_at}` |
| `PUT` | `/v1/secrets/{name}` | `{"value":"..."}` | `{name, created_at, updated_at}` (admin upserts; an agent may only create new names under its write prefixes) |
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

### Web UI

`https://<your-host>/ui/` (the root path redirects there). Log in by pasting an **admin** token; agent tokens are refused. The header shows when your token expires and warns in its last 7 days.

- **Secrets:** list and filter, view (value shown only inside the dialog), create, overwrite, delete.
- **Tokens:** list with status and last use, create (plaintext shown once), change read/write prefixes, revoke.
- **Audit log:** filter by token, target, action, result and age.

The token is kept in `sessionStorage` for that tab only and sent as a bearer header; there are no cookies, so no CSRF. The page runs under a strict CSP (no inline code, no third-party origins) and logs out after 15 idle minutes. Revoking the token you're logged in with is refused, so you can't lock yourself out mid-session.

### Admin API

Used by the UI; admin tokens only, rate limited and audited like everything else. Changes commit in the same transaction as their audit row.

| Method | Path | Body / query | Response |
|---|---|---|---|
| `GET` | `/v1/admin/tokens` | — | `{"tokens":[{name, role, prefixes, write_prefixes, status, expires_at, last_used_at, revoked_at, created_at}]}` (never hashes) |
| `POST` | `/v1/admin/tokens` | `{name, role, prefixes, write_prefixes, expires: "30d", confirm_all}` (admin: `expires` required, ≤ 90d) | `201 {name, token, warnings}`, the only time the token is shown |
| `PATCH` | `/v1/admin/tokens/{name}` | `{prefixes?, write_prefixes?, confirm_all}` | new lists; a missing field keeps its list |
| `DELETE` | `/v1/admin/tokens/{name}` | — | revokes (permanent) |
| `GET` | `/v1/admin/me` | — | `{name, role, expires_at}` of the calling token (the UI shows its expiry) |
| `GET` | `/v1/admin/audit` | `?token=&secret=&action=&result=&since=24h&until=&limit=100` | `{"records":[...]}` newest first |

A `*` read prefix needs `"confirm_all": true`.

### Admin commands

The same operations are available as CLI subcommands inside the container. They open the database file directly, so they work even with `ADMIN_API=false` or the server stopped:

```bash
docker compose exec hush hush-hush token create --name admin-laptop --role admin --expires 30d
docker compose exec hush hush-hush token create --name llm-agent --role agent --prefix llm. --prefix github. --expires 90d
docker compose exec hush hush-hush token create --name crawler --role agent --prefix crawler. --write-prefix crawler.
docker compose exec hush hush-hush token list
docker compose exec hush hush-hush token update --name llm-agent --prefix llm.
docker compose exec hush hush-hush token update --name crawler --no-write
docker compose exec hush hush-hush token revoke --name llm-agent
docker compose exec hush hush-hush audit --token llm-agent --result denied --since 7d
docker compose exec hush hush-hush audit-prune --older-than 180d
docker compose exec -T hush hush-hush backup --out - > backup-$(date +%F).db
```

`token create` prints the token (`hush_` + 64 hex chars) once; only its hash is kept. Token names are never reused, even after a revoke. **Admin tokens are for humans and must expire** (`--expires`, at most 90d); rotate them by creating a new one and revoking the old. Agent tokens may be permanent. `audit` prints newest first; see `hush-hush help` for every flag.

Backups, restore and token rotation are covered in [`docs/docker.md`](docs/docker.md).

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
go run . token create --name dev --role admin --expires 30d

# Test
go test ./...
go test -cover ./...

# Container image
docker build -t hush-hush .
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
| Dependabot | Weekly grouped updates for `gomod`, `github-actions` and `docker` ecosystems |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review with project-specific instructions |

Tool versions are pinned to specific tags / commit SHAs to defeat `@latest` supply-chain drift; Dependabot opens PRs to bump them as new releases ship.

## Limitations

- **Client-side encryption requires CLI consumers.** v2 (`hush init` + `hush migrate`) protects against host compromise, but raw-HTTP consumers can't decrypt `hh2:` values. Either every consumer uses the CLI / vendors the vault code, or v2 stays off for that deployment. See [`docs/adr/0001-client-side-encryption.md`](docs/adr/0001-client-side-encryption.md) for the full design discussion.
- **No passphrase caching.** v2 prompts every command. OS keychain integration (`--remember` flag) is plausible future work, deferred for now to keep the trust surface minimal.
- **No key-rotation tooling.** If the v1 master key leaks, recovery is manual: rotate, decrypt all rows under old key, re-encrypt under new key, swap env var. If the v2 passphrase leaks: change passphrase via re-init + manual re-puts (no automated re-key yet).
- **One owner, not a team tool.** Two roles only (admin, agent). No per-human accounts, no groups. Agents can at most create new secrets under their own write prefixes; they can't overwrite or delete.
- **Rate limits live in memory** and reset on restart. Fine for one process on one host.
- **The audit log has no automatic retention.** Prune it with `hush-hush audit-prune --older-than 180d` (a cron job on the host works). It only sees API access: anyone who can read the volume directly bypasses it.
- **The web UI is admin-only** and deliberately minimal; no browser extension.

If you need any of these, [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Infisical](https://github.com/Infisical/infisical) are good self-hosted alternatives.

## License

MIT. See [LICENSE](LICENSE).
