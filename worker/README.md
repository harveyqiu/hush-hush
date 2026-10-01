# hush-hush on Cloudflare Workers

The same secret store as the Go version (see [`../docs/functional-spec.md`](../docs/functional-spec.md)), running entirely on Cloudflare: Workers for the API and UI, D1 for storage, a Durable Object for rate limiting. No server to run. How each part maps, and where it deliberately differs from the Go build, is in [`../docs/workers-migration.md`](../docs/workers-migration.md).

Before you deploy, read the trade-off: the ciphertext (D1) and the master key (Worker secret) now live in the same Cloudflare account, so anyone who takes over that account gets both. Protect it with a hardware-key 2FA and a narrowly scoped API token, and consider client-side encryption (`hush init`), which keeps your passphrase off the server entirely.

## Deploy

Needs Node 20+ and a Cloudflare account. Run everything from this directory.

```bash
npm ci

# 1. Database. Paste the printed database_id into wrangler.jsonc.
npx wrangler d1 create hush
npm run db:migrate:remote

# 2. Master key: 32 random bytes, base64. Keep a copy somewhere other than
#    Cloudflare: without it a backup cannot be decrypted.
openssl rand -base64 32 | npx wrangler secret put MASTER_KEY

# 3. Ship it.
npm run deploy

# 4. First admin token (printed once; only its hash goes to D1). Max 90 days.
npm run token:bootstrap -- --name owner --expires 30d --remote
```

Then open `https://<your-worker>.workers.dev/`, sign in with that token, and create agent tokens in the UI. Point the `hush` CLI at the same URL:

```bash
hush login   # URL = your worker, token = the admin token
```

To use your own domain, add a route or custom domain to `wrangler.jsonc` ([docs](https://developers.cloudflare.com/workers/configuration/routing/)).

## Settings

In `wrangler.jsonc` under `vars`; `MASTER_KEY` is a secret.

| Name | Default | Meaning |
|---|---|---|
| `MASTER_KEY` (secret) | required | base64 of 32 bytes; same value as the Go version's `MASTER_KEY` if you migrate |
| `RATE_LIMIT_PER_MINUTE` | 60 | per token |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | 10 | failed authentications, per client IP (IPv6 per /64) |
| `ADMIN_API` | true | `false` removes `/v1/admin/*` and the UI entirely |
| `AUDIT_RETENTION_DAYS` | unset | when set, the daily Cron deletes audit rows older than this |

## Develop

```bash
npm test                     # 107 tests, run inside workerd
npm run typecheck

# Local server with a local D1:
echo "MASTER_KEY=$(openssl rand -base64 32)" > .dev.vars   # throwaway key, git-ignored
npm run db:migrate:local
npm run token:bootstrap -- --name owner --local
npm run dev
```

## Operations

- **Backup**: `npx wrangler d1 export DB --remote --output backup.sql`; D1 Time Travel can also restore any point in the last 30 days. Backups hold ciphertext and token hashes, never the master key.
- **Migrate from the Go version**: see section 6 of the migration doc.
- **Token management**: UI or `/v1/admin/tokens`. There is no CLI; `token:bootstrap` exists only to create the first admin token.
