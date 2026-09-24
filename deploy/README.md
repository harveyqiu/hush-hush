# Deploying hush-hush on a Linux VPS

This is the primary way to run hush-hush: one small Linux host, the server under systemd as a dedicated `hush` user, Caddy in front for TLS, and one bearer token per agent.

Files in this directory:

| File | Goes to | Purpose |
|---|---|---|
| [`hush-hush.service`](hush-hush.service) | `/etc/systemd/system/hush-hush.service` | Hardened systemd unit |
| [`Caddyfile`](Caddyfile) | `/etc/caddy/Caddyfile` (site block) | TLS reverse proxy |

All commands below assume a Debian/Ubuntu-style host with `sudo`. Replace `secrets.example.com` with your domain throughout.

Contents:

1. [Threat model in one page](#1-threat-model-in-one-page)
2. [First deployment](#2-first-deployment)
3. [Tokens: create, use, rotate, revoke](#3-tokens-create-use-rotate-revoke)
4. [Audit log](#4-audit-log)
5. [File permissions](#5-file-permissions)
6. [Backups](#6-backups)
7. [Migrating from `AUTH_TOKEN`](#7-migrating-from-auth_token)
8. [Upgrading from v0.1.0](#8-upgrading-from-v010)
9. [Operational notes](#9-operational-notes)
10. [Configuration reference](#10-configuration-reference)

---

## 1. Threat model in one page

hush-hush enforces access in the HTTP API: each caller has its own token, agent tokens are limited to name prefixes (read-only unless given create-only write prefixes), and every request to `/v1/secrets` is written to an audit log. **All of that only holds for callers that go through the API.**

The database file (`/var/lib/hush/hush.db`) and the master key are the real secrets. Anyone who can read both can decrypt every value offline, with no token, no prefix check and no audit row. That includes:

- the `hush` Linux user (it owns the DB, and the running server holds the key in memory),
- root, and anyone with `sudo` (including `sudo -u hush`),
- members of the `docker` group, or anything else that is root-equivalent on the host.

So the one hard rule is:

> **Agents must run as a different Linux user than `hush`, without root, without sudo, and without membership in the `hush` group.**

If an agent runs as `hush` or root, the token system is decoration: it can open the DB, read the master key from `/etc/hush` or the process, and read or change anything, and the audit log will not show it.

Practical consequences:

- Give each agent (or each group of agents that may see the same secrets) its own Linux user, for example `agent-llm`, `agent-ci`. Agents running as the same user can read each other's token files, so they effectively share a scope.
- Store each agent's token in a file only that agent's user can read (0600), or pass it in as a systemd credential if the agent is itself a systemd service.
- Admin tokens are for you, not for agents. An agent that needs to write should not exist in this model; put the secret in yourself.
- The server listens on `127.0.0.1:8080` only. Remote clients go through Caddy over HTTPS. Local agents on the same host may use `https://secrets.example.com` (recommended) or `http://127.0.0.1:8080` directly.
- The audit log records a client IP. With `TRUST_PROXY_HEADERS=true`, a process on the same host that talks to `127.0.0.1:8080` directly can put anything in `X-Forwarded-For`, so treat `remote_addr` for local callers as advisory. The token name in each audit row is not spoofable.

What the at-rest encryption buys you: a stolen DB backup is useless without the master key, and a stolen master key is useless without the DB. That is why [backups](#6-backups) keep them apart.

---

## 2. First deployment

### 2.1 Create the service user

```bash
sudo useradd --system --home /var/lib/hush --shell /usr/sbin/nologin hush
```

`--system` does not create the home directory; systemd creates `/var/lib/hush` with the right owner and mode on first start (`StateDirectory=hush`).

### 2.2 Build and install the binary

The server binary is built from the repository root and is called `hush-hush`. (The name `hush` belongs to the HTTP client in `cmd/hush`, which you install on client machines, not here.) Go 1.24+ is required to build.

Build on the VPS or on any machine with Go, then copy the binary over:

```bash
git clone https://github.com/cjunks94/hush-hush.git
cd hush-hush
CGO_ENABLED=0 go build -trimpath -o hush-hush .
sudo install -o root -g root -m 0755 hush-hush /usr/local/bin/hush-hush
/usr/local/bin/hush-hush help
```

Cross-compiling from another machine works the same way with `GOOS=linux GOARCH=amd64` (or `arm64`) in front of `go build`. The binary is pure Go with no CGO, so it has no runtime dependencies.

### 2.3 Generate the master key

The master key is 32 random bytes, base64-encoded. It lives in a root-only file and is handed to the service by systemd (`LoadCredential=`), so it never appears in the unit file or in `systemctl show`.

```bash
sudo install -d -o root -g root -m 0700 /etc/hush
sudo sh -c 'umask 077; openssl rand -base64 32 | tr -d "\n" > /etc/hush/master_key'
sudo chmod 0600 /etc/hush/master_key
sudo stat -c '%A %U:%G %n' /etc/hush /etc/hush/master_key
# drwx------ root:root /etc/hush
# -rw------- root:root /etc/hush/master_key
```

**Now make the offline copy** (see [Backups](#6-backups)): print it once with `sudo cat /etc/hush/master_key` and put it in a password manager, on paper in a safe, or both. If you lose this key, every secret in the database is gone for good.

<details>
<summary>systemd older than 247 (no <code>LoadCredential=</code>)</summary>

Check with `systemctl --version`. If it is below 247, use an environment file instead:

```bash
sudo sh -c 'umask 077; printf "MASTER_KEY=%s\n" "$(openssl rand -base64 32)" > /etc/hush/hush.env'
sudo chmod 0600 /etc/hush/hush.env
```

Then, in `hush-hush.service`, comment out `LoadCredential=` and uncomment `EnvironmentFile=/etc/hush/hush.env`. systemd reads the file as root before starting the service, so it stays `root:root 0600`.
</details>

### 2.4 Install and start the service

```bash
sudo install -o root -g root -m 0644 deploy/hush-hush.service /etc/systemd/system/hush-hush.service
sudo systemctl daemon-reload
sudo systemctl enable --now hush-hush
```

Check it:

```bash
systemctl status hush-hush
journalctl -u hush-hush -n 50 --no-pager
curl -sS http://127.0.0.1:8080/healthz
# {"status":"ok"}
```

On first start the server creates `/var/lib/hush/hush.db` (mode 0600) and runs the schema migrations. Expect a warning that there are no active tokens yet; that goes away once you create one in step 3. If you see a warning about database or directory permissions, fix it with [section 5](#5-file-permissions).

The service must have started at least once before you create tokens, because the admin commands refuse to create a missing database.

### 2.5 Install Caddy and the site config

Install Caddy from its official repository ([instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)), point your domain's DNS at the VPS, and make sure ports 80 and 443 are open. Then add the site block from [`Caddyfile`](Caddyfile) to `/etc/caddy/Caddyfile` with your domain:

```bash
sudoedit /etc/caddy/Caddyfile      # paste the secrets.example.com { ... } block
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -sS https://secrets.example.com/healthz
# {"status":"ok"}
```

Do not open port 8080 in the firewall. It only listens on loopback anyway, but there is no reason to expose it.

### 2.6 Create tokens and test

Continue with [section 3](#3-tokens-create-use-rotate-revoke).

---

## 3. Tokens: create, use, rotate, revoke

### 3.1 How admin commands work

Token management is not an HTTP API. The `hush-hush` binary has subcommands that open the database file directly. They:

- must run as the user that owns the DB (they refuse otherwise, so root cannot accidentally leave root-owned WAL files behind),
- refuse to create a database that does not exist (protects against a typo in the path),
- read the path from `--db PATH`, else `$DB_PATH`, else `./hush.db`.

`sudo` resets the environment, so pass `DB_PATH` explicitly. Every admin command therefore looks like this:

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token list
```

Optional shell helper for your admin account (not for agents):

```bash
hh() { sudo -u hush env DB_PATH=/var/lib/hush/hush.db /usr/local/bin/hush-hush "$@"; }
hh token list
```

The examples below spell out the full command.

### 3.2 Roles and prefixes

| Role | Can do |
|---|---|
| `admin` | Read, write and delete every secret. For humans. |
| `agent` | Reads secrets whose names start with one of its `--prefix` values. By default it can't write. With `--write-prefix`, it can create *new* secrets under those prefixes (409 if the name exists, never an overwrite). `DELETE` is always 403. |

Prefixes must end in `.` or `_`, so `llm.` matches `llm.openai` but not `llmx.key`. Naming secrets with a dotted hierarchy (`llm.openai`, `llm.anthropic`, `github.deploy_key`) makes scoping easy.

**Letting an agent create secrets.** Give it its own namespace, for example `--write-prefix crawler.`, and add `--prefix crawler.` too if it should read back what it writes (a write grant doesn't imply read). `*` is not accepted as a write prefix. `token create` and `token update` print a warning when a write prefix overlaps another agent's; sharing a write namespace lets one agent squat on names the other expects.

The special prefix `*` gives an agent read access to every secret, including ones added later. It must be the only prefix, and the CLI asks you to type the token name again to confirm. Avoid it unless you really mean it.

Status codes an agent will see:

| Situation | Status | Body |
|---|---|---|
| Missing, unknown, revoked or expired token | 401 | `{"error":"unauthorized"}` |
| Agent `DELETE`, `PUT` outside its write prefixes, or `GET` of a name outside its read prefixes (whether or not it exists) | 403 | `{"error":"forbidden"}` |
| Agent `PUT` under a write prefix for a name that already exists | 409 | `{"error":"already exists"}` |
| Name inside its prefixes but not stored | 404 | `{"error":"not found"}` |
| Too many requests | 429 | `{"error":"rate_limited"}` plus `Retry-After` |

`GET /v1/secrets` (list) never returns 403 for an agent; it just returns only the names the agent is allowed to read.

### 3.3 Create the first admin token

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name admin-laptop --role admin
# created admin token "admin-laptop". Store it now; it cannot be shown again:
# hush_<64 hex>
```

The token (`hush_` followed by 64 hex characters) is printed once, on stdout. Only its SHA-256 is stored, so if you lose it, revoke it and create a new one. Put it straight into your password manager.

On your own machine, configure the CLI with it:

```bash
go install github.com/cjunks94/hush-hush/cmd/hush@latest
hush login --url https://secrets.example.com --token 'hush_<64 hex>'
hush health
```

Token names are unique forever: a revoked name cannot be reused. Pick descriptive names, and include a date or counter if you plan to rotate (`llm-agent-2026q3`).

### 3.4 Create agent tokens

Create the agent's Linux user first (if it doesn't exist) and write the token straight into a file only that user can read, so the token never touches your terminal scrollback or a world-readable file. Run `sudo -v` first so the two `sudo` calls in the pipe don't both prompt for a password at once.

```bash
sudo useradd --create-home --shell /bin/bash agent-llm   # skip if the user exists

sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token create --name llm-agent --role agent --prefix llm. --expires 90d \
  | sudo -u agent-llm sh -c 'umask 077; cat > /home/agent-llm/.hush-token'

sudo stat -c '%A %U %n' /home/agent-llm/.hush-token
# -rw------- agent-llm /home/agent-llm/.hush-token
```

More than one prefix, no expiry:

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token create --name ci-agent --role agent --prefix github. --prefix ci_
```

`--expires` takes days (`90d`) or Go durations (`12h`). Without it, the token never expires. An expired token gets 401 just like a revoked one.

For an agent that is itself a systemd service, put the token in a root-only file such as `/etc/agent-llm/hush_token` (0600 root) and give the agent's unit `LoadCredential=hush_token:/etc/agent-llm/hush_token`; the agent then reads `$CREDENTIALS_DIRECTORY/hush_token`.

The agent can use the `hush` CLI (`HUSH_URL` / `HUSH_TOKEN` env vars or `hush login`) or plain HTTP:

```bash
# as agent-llm
export HUSH_URL=https://secrets.example.com
export HUSH_TOKEN="$(cat ~/.hush-token)"
hush get llm.openai
```

### 3.5 Test with curl

Read tokens into variables without echoing them or saving them in shell history:

```bash
URL=https://secrets.example.com
read -rs ADMIN && export ADMIN     # paste the admin token, press Enter
read -rs AGENT && export AGENT     # paste the llm-agent token
```

Store a couple of secrets as admin:

```bash
curl -sS -X PUT "$URL/v1/secrets/llm.openai" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"value":"example-value-1"}'

curl -sS -X PUT "$URL/v1/secrets/github.deploy_key" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"value":"example-value-2"}'
```

As the agent:

```bash
# List: only llm.* names come back
curl -sS "$URL/v1/secrets" -H "Authorization: Bearer $AGENT"
# {"secrets":[{"name":"llm.openai",...}]}

# Get in scope: 200
curl -sS "$URL/v1/secrets/llm.openai" -H "Authorization: Bearer $AGENT"
# {"name":"llm.openai","value":"example-value-1",...}

# Get out of scope: 403, even though it exists
curl -sS -o /dev/null -w '%{http_code}\n' "$URL/v1/secrets/github.deploy_key" -H "Authorization: Bearer $AGENT"
# 403

# In scope but missing: 404
curl -sS -o /dev/null -w '%{http_code}\n' "$URL/v1/secrets/llm.nothing_here" -H "Authorization: Bearer $AGENT"
# 404

# Write attempt: 403
curl -sS -X PUT "$URL/v1/secrets/llm.openai" \
  -H "Authorization: Bearer $AGENT" -H "Content-Type: application/json" \
  -d '{"value":"nope"}'
# {"error":"forbidden"}
```

When done: `unset ADMIN AGENT`.

### 3.6 List tokens

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token list
```

Shows name, role, read prefixes, write prefixes, status (`active`, `revoked`, `expired`), expiry, last use and creation time. Token values and hashes are never shown.

### 3.7 Change an agent's scope

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token update --name llm-agent --prefix llm. --prefix embeddings.
```

Each flag replaces its own list and leaves the other alone: `--prefix` sets the read prefixes, `--write-prefix` the create-only prefixes, and `--no-write` removes all write prefixes. Changes apply from the next request.

```bash
# let the crawler create new secrets under crawler. (and read them back)
sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token update --name crawler --prefix crawler. --write-prefix crawler.
# take write access away again
sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token update --name crawler --no-write
```

### 3.8 Revoke

```bash
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token revoke --name llm-agent
```

Tokens are checked against the database on every request, so the next request with that token gets 401. No restart needed.

### 3.9 Rotate an agent token

There is no in-place rotation; create a new token, switch the agent, then revoke the old one.

```bash
# 1. New token with the same scope, straight into the agent's file (new name: names are never reused)
sudo -u hush env DB_PATH=/var/lib/hush/hush.db \
  hush-hush token create --name llm-agent-2 --role agent --prefix llm. --expires 90d \
  | sudo -u agent-llm sh -c 'umask 077; cat > /home/agent-llm/.hush-token.new'
sudo -u agent-llm mv /home/agent-llm/.hush-token.new /home/agent-llm/.hush-token

# 2. Restart or reload the agent so it picks up the new token, then confirm it is used
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --token llm-agent-2 --since 1d

# 3. Check the old token has no rows newer than the switch, then revoke it
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --token llm-agent --since 1d
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token revoke --name llm-agent
```

Rotate immediately (revoke first, then create) if a token may have leaked.

---

## 4. Audit log

Every request to `/v1/secrets` writes one row to the `audit_log` table: time, token name, action (`get`, `list`, `put`, `delete`, or `other` for a request that matches no route, such as a wrong method), secret name, result, request ID and client IP. Secret values and tokens are never stored. If the audit row cannot be written, reads fail with 500 instead of returning data that was not recorded, and writes are rolled back: a PUT or DELETE commits in the same transaction as its audit row. `/healthz` is not audited.

Results: `allowed`, `denied` (403), `not_found`, `conflict` (409), `unauthenticated` (401), `rate_limited` (429), `bad_request`, `error`.

Query it with the `audit` subcommand (newest first):

```bash
# Everything in the last day
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --since 1d

# One agent's denied requests this week
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --token llm-agent --result denied --since 7d

# Who read a given secret, ever
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --secret llm.openai --action get --limit 500

# Failed logins in a time window
sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --result unauthenticated \
  --since 2026-09-01T00:00:00Z --until 2026-09-02T00:00:00Z
```

Filters: `--token`, `--secret`, `--action`, `--result`, `--since` / `--until` (a relative age such as `24h` or `7d`, or an RFC3339 time; `--since` is inclusive, `--until` exclusive), `--limit` (default 100, maximum 10000). It reads the database file directly, so it works while the server is stopped.

The same events also go to the journal as `secret access` log lines: `journalctl -u hush-hush | grep '"secret access"'`.

Worth checking now and then: `denied` rows (an agent asking for something outside its scope may be misconfigured or compromised) and bursts of `unauthenticated`.

The audit log is tamper-evident only against API callers. Anyone who can write the DB file (the `hush` user, root) can edit it. If you need an append-only trail, ship the journal to another machine.

---

## 5. File permissions

Target state:

| Path | Owner | Mode |
|---|---|---|
| `/var/lib/hush/` | `hush:hush` | `0700` (`drwx------`) |
| `/var/lib/hush/hush.db`, `hush.db-wal`, `hush.db-shm` | `hush:hush` | `0600` (`-rw-------`) |
| `/etc/hush/` | `root:root` | `0700` |
| `/etc/hush/master_key` | `root:root` | `0600` |
| `/usr/local/bin/hush-hush` | `root:root` | `0755` |

Check:

```bash
sudo stat -c '%A %U:%G %n' /var/lib/hush /var/lib/hush/hush.db* /etc/hush /etc/hush/master_key
```

Fix:

```bash
sudo chown -R hush:hush /var/lib/hush
sudo chmod 0700 /var/lib/hush
sudo chmod 0600 /var/lib/hush/hush.db*
sudo chown -R root:root /etc/hush
sudo chmod 0700 /etc/hush
sudo chmod 0600 /etc/hush/*
```

The unit's `StateDirectoryMode=0700` and `UMask=0077` keep these right on their own; the server creates new DB files as 0600 and logs a warning at startup if the DB file is wider than 0600 or its directory wider than 0700. Problems usually come from copying a DB in by hand (`scp`, `cp` as root). Also check that the `hush` group has no members besides `hush` itself: `getent group hush`.

---

## 6. Backups

Two things to back up, and **they must never be stored together**:

1. **The database** (`/var/lib/hush/hush.db`): ciphertexts, token hashes, audit log. Back it up often.
2. **The master key** (`/etc/hush/master_key`): back it up once, when you create it. Keep **at least one offline copy** (password manager, paper in a safe). It does not change unless you rotate it.

A DB backup alone is ciphertext; the key alone decrypts nothing. Together they are every secret in plaintext. Do not put the key in the same restic repo, tarball, S3 bucket or VPS snapshot schedule as the DB. Note that a full-disk VPS snapshot contains both (`/etc/hush` and `/var/lib/hush`), so treat provider snapshots as sensitive or exclude them.

### Consistent online backup of SQLite

The server runs SQLite in WAL mode: recent writes may sit in `hush.db-wal` until a checkpoint. Copying `hush.db` alone with `cp` while the server runs can give you a stale or inconsistent file. Use SQLite's own backup instead; it is safe while the server is running.

```bash
sudo apt install sqlite3      # once
sudo install -d -o hush -g hush -m 0700 /var/backups/hush

# Option A: the .backup command
sudo -u hush sqlite3 /var/lib/hush/hush.db ".backup '/var/backups/hush/hush-$(date +%F).db'"

# Option B: VACUUM INTO (also compacts; needs SQLite 3.27+)
sudo -u hush sqlite3 /var/lib/hush/hush.db "VACUUM INTO '/var/backups/hush/hush-$(date +%F).db'"
```

Both produce a single self-contained file (no `-wal` needed). Run them as `hush` so no root-owned `-wal`/`-shm` files are left in `/var/lib/hush`. Then copy the backup off the host with whatever you use (restic, borg, rsync), and keep the destination separate from where the master key lives.

If you ever must copy the raw files instead, stop the service first (`sudo systemctl stop hush-hush`) and copy `hush.db` together with any `hush.db-wal` and `hush.db-shm`.

Check a backup:

```bash
sudo -u hush sqlite3 /var/backups/hush/hush-2026-09-24.db "PRAGMA integrity_check; SELECT COUNT(*) FROM secrets;"
```

### Restore

```bash
sudo systemctl stop hush-hush
sudo rm -f /var/lib/hush/hush.db-wal /var/lib/hush/hush.db-shm
sudo install -o hush -g hush -m 0600 /path/to/hush-2026-09-24.db /var/lib/hush/hush.db
sudo systemctl start hush-hush
```

The restored DB must be paired with the master key that was active when it was written. Tokens revoked after the backup was taken will be active again after a restore: revoke them again.

---

## 7. Migrating from `AUTH_TOKEN`

Earlier versions used a single `AUTH_TOKEN` env var. It still works, but is deprecated: it acts as an admin token named `env:AUTH_TOKEN` and the server logs a warning on startup. To move off it:

1. Deploy the new version with `AUTH_TOKEN` still set. Everything keeps working.
2. Create a named admin token for yourself:
   ```bash
   sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush token create --name admin-laptop --role admin
   ```
3. Create an agent token per non-human consumer (section 3.4), with the narrowest prefixes that work.
4. Switch each client to its new token (`hush login --token ...`, `HUSH_TOKEN`, or the consumer's own config).
5. Watch the audit log until nothing uses the old token any more:
   ```bash
   sudo -u hush env DB_PATH=/var/lib/hush/hush.db hush-hush audit --token env:AUTH_TOKEN --since 1d
   ```
6. Remove `AUTH_TOKEN` from wherever it is set (unit file, `hush.env`, Railway variables) and restart. From then on the old value gets 401.

---

## 8. Upgrading from v0.1.0

v0.1.0 databases open unchanged. On first start the new binary adds a `schema_version` table plus `tokens` and `audit_log`; the `secrets` table and its ciphertexts are not touched, and the same `MASTER_KEY` keeps decrypting them.

1. **Back up first** (section 6). Migrations run in a transaction, but a backup is what lets you roll back to the old binary cleanly.
2. Install the new binary and restart:
   ```bash
   sudo install -o root -g root -m 0755 hush-hush /usr/local/bin/hush-hush
   sudo systemctl restart hush-hush
   journalctl -u hush-hush -n 50 --no-pager
   ```
3. Follow section 7 to replace `AUTH_TOKEN` with named tokens.

Behaviour changes to be aware of:

- The server now listens on `127.0.0.1:8080` by default instead of all interfaces. `PORT` alone still works but now means `127.0.0.1:$PORT`. Set `LISTEN_ADDR` if you need something else (Railway: see the main README).
- Error bodies for auth failures are now `{"error":"unauthorized"}`.
- Requests can now be rate limited (429).

Moving a v0.1.0 database from Railway (or anywhere) to the VPS: download it, then install it with the right owner and mode before first start, and use the same master key:

```bash
sudo systemctl stop hush-hush
sudo install -o hush -g hush -m 0600 ./hush.db /var/lib/hush/hush.db
sudo systemctl start hush-hush
```

A newer database cannot be opened by an older binary that doesn't know its schema version; the server refuses to start rather than guess. Roll back by restoring the pre-upgrade backup.

---

## 9. Operational notes

**The audit log grows without limit.** Each request adds a row of roughly 150 to 300 bytes including indexes. An agent polling once a minute is about 1,440 rows a day, well under 1 MB a week; 10,000 requests a day is on the order of 1 GB a year. Check the size now and then:

```bash
sudo -u hush sqlite3 /var/lib/hush/hush.db "SELECT COUNT(*), datetime(MIN(ts),'unixepoch') FROM audit_log;"
sudo ls -lh /var/lib/hush/
```

There is no built-in retention. To prune manually, **take a backup first** (old rows may be exactly what you need in an investigation), then run as `hush`:

```bash
sudo -u hush sqlite3 /var/lib/hush/hush.db \
  "DELETE FROM audit_log WHERE ts < unixepoch('now','-180 days');"
# SQLite older than 3.38 (sqlite3 --version) has no unixepoch(); use:
#   "DELETE FROM audit_log WHERE ts < CAST(strftime('%s','now','-180 days') AS INTEGER);"

# Optional: give the freed space back to the filesystem (briefly locks the DB)
sudo -u hush sqlite3 /var/lib/hush/hush.db "VACUUM;"
```

Caution: this is a raw SQL write against the live database. Only touch `audit_log`, double-check the `WHERE` clause, and never run it as root. Deleted rows are gone.

**Rate limits are in memory.** Defaults: 60 requests per minute per token (`RATE_LIMIT_PER_MINUTE`), and 10 failed-auth requests per minute per client IP (`UNAUTH_RATE_LIMIT_PER_MINUTE`; only requests that fail authentication count). Counters reset when the service restarts. A limited request gets 429 with a `Retry-After` header and is recorded as `rate_limited` in the audit log. Behind Caddy, the per-IP limit relies on `TRUST_PROXY_HEADERS=true`; without it every remote client looks like `127.0.0.1` and shares one bucket.

**Revocation is immediate.** Tokens are looked up in the database on every request, and `token revoke` / `token update` write to the same database, so changes apply to the next request without a restart. Same for expiry.

**Restarts are cheap.** `sudo systemctl restart hush-hush` drains in-flight requests for up to 10 seconds. Agents should retry on connection errors.

**Logs.** JSON lines on stdout, collected by journald: `journalctl -u hush-hush -f`. Logs never contain secret values or tokens.

**Master key rotation** is not automated. See Limitations in the main README.

---

## 10. Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `MASTER_KEY` | (required unless the credential below is present) | Base64 of 32 random bytes |
| `$CREDENTIALS_DIRECTORY/master_key` | - | systemd credential (`LoadCredential=`); preferred over `MASTER_KEY` when present. If the file exists but is unreadable or invalid, startup fails instead of falling back to `MASTER_KEY` |
| `DB_PATH` | `./hush.db` | Also the default for `--db` in admin commands |
| `LISTEN_ADDR` | `127.0.0.1:8080` | `host:port` to listen on |
| `PORT` | - | Legacy. Used only when `LISTEN_ADDR` is unset, as `127.0.0.1:$PORT` |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per token |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | `10` | Per client IP, failed-auth requests only |
| `TRUST_PROXY_HEADERS` | `false` | When `true` and the TCP peer is loopback, the rightmost `X-Forwarded-For` entry is the client IP. Set it when Caddy runs on the same host |
| `AUTH_TOKEN` | - | Deprecated. Acts as an admin token named `env:AUTH_TOKEN` and logs a warning |
