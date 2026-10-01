# hush-hush on Cloudflare Workers

A personal secret store running entirely on Cloudflare (behavior specified in [`../docs/functional-spec.md`](../docs/functional-spec.md); ported from an earlier Go build, now removed): Workers for the API and UI, D1 for storage, a Durable Object for rate limiting. No server to run. How each part maps, and where it deliberately differs from the Go build, is in [`../docs/workers-migration.md`](../docs/workers-migration.md).

Before you deploy, read the trade-off: the ciphertext (D1) and the master key (Worker secret) live in the same Cloudflare account, so anyone who takes over that account gets both. Protect it with hardware-key 2FA and a narrowly scoped API token. For secrets that must survive that account being compromised, use the client-side encryption in the [`hush` CLI](../cli/README.md); without it, agents and admins read plaintext over HTTPS.

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

Then open `https://<your-worker>.workers.dev/`, sign in with that token, and create agent tokens in the UI. Use the [`hush` CLI](../cli/README.md) from your machine, or give an agent the address `https://<your-worker>.workers.dev/llm.html`: a public page, rendered with your real URL, that tells an LLM how to connect and use the API safely (the same guidance for humans is in [`../docs/agent-guide.md`](../docs/agent-guide.md)). Plain HTTP works too:

```bash
curl -sS "$HUSH_URL/v1/secrets/llm.openai" -H "Authorization: Bearer $HUSH_TOKEN"
```

To use your own domain, add a route or custom domain to `wrangler.jsonc` ([docs](https://developers.cloudflare.com/workers/configuration/routing/)).

## Settings

In `wrangler.jsonc` under `vars`; `MASTER_KEY` is a secret.

| Name | Default | Meaning |
|---|---|---|
| `MASTER_KEY` (secret) | required | base64 of 32 bytes; same value as the Go version's `MASTER_KEY` if you migrate |
| `RATE_LIMIT_PER_MINUTE` | 60 | per token |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | 10 | failed authentications, per client IP (IPv6 per /64) |
| `ADMIN_API` | true | `false` removes `/v1/admin/*` and the UI entirely (`/llm.html` stays) |
| `AUDIT_RETENTION_DAYS` | unset | when set, the daily Cron deletes audit rows older than this |

## Automatic deploy (off by default)

[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml) migrates D1 and deploys on every push to `main` that touches `worker/`. It does nothing until the repository variable `DEPLOY_ENABLED` is set to `true`; the header of that file lists the five steps to switch it on (real `database_id`, a `production` environment with required reviewers, the two Cloudflare secrets, the variable, and the one-time manual `MASTER_KEY` and first admin token). Deleting the variable switches it off again.

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
- **Import a database from the old Go build**: see section 6 of [`../docs/workers-migration.md`](../docs/workers-migration.md).
- **Token management**: UI or `/v1/admin/tokens`. There is no CLI; `token:bootstrap` exists only to create the first admin token.
