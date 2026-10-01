# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use GitHub's private vulnerability reporting: open this repository's **Security** tab, choose **Report a vulnerability**, and describe the issue with reproduction steps if possible. You'll get an acknowledgement within 7 days; we'll discuss the fix and disclosure timeline together.

## Supported versions

This is an active personal project; only the latest commit on `main` is supported. Security fixes land on `main` and are not backported.

| Version | Supported |
| ------- | --------- |
| `main`  | ✅ |
| Tagged releases | Best-effort within the latest minor |

## In scope

- The Worker in `worker/src`: authentication, authorization, crypto, validation, headers, log injection vectors
- The admin UI in `worker/public/ui`
- Dependencies in `worker/package.json` and the GitHub Actions workflows in `.github/workflows`

## Out of scope

This is a deliberately minimal tool for one operator and a handful of agents. The following are documented trade-offs in the [threat model](README.md#threat-model), not vulnerabilities:

- **Server-side encryption**: the master key is a Worker secret. Anyone who can deploy code to the Worker, read its secrets, or administer the Cloudflare account has both the key and the ciphertext. It protects against leaked database exports and backups, not against account compromise.
- **Agents see plaintext values**: an agent token can read the values under its prefixes. Access control limits *which* secrets an agent gets, not what it does with them.
- **Cloudflare-level bypass**: anyone with access to the D1 database plus the Worker secrets can read everything directly, skipping tokens, prefixes and the audit log. Agents must never have Cloudflare account access.
- **Agent-created secrets**: an agent with write prefixes can create new names there (never overwrite or delete). Anything that reads that namespace should treat those values as agent-supplied.
- **Rate limiting fails open**: if the rate-limit Durable Object is unavailable, requests are allowed (and an error is logged). Tokens are 256-bit random values, so the limiter is abuse control, not the authentication boundary.
- **Audit `remote_addr`** comes from `CF-Connecting-IP`, which Cloudflare sets at its edge.
- **Token management over HTTP**: the admin API and web UI let an admin token create tokens. A leaked admin token can therefore mint new tokens and persist; admin tokens are for humans and always expire (at most 90 days, enforced on create and at authentication); set `ADMIN_API=false` to remove the admin API and UI entirely. Every admin call is audited.
- **No master-key rotation** and no key escrow: losing `MASTER_KEY` makes stored values unrecoverable.

If your use case requires any of those properties, please pick a different tool; see the [README's "What this isn't" section](README.md#what-this-isnt).

## Security tooling

| Tool | Purpose |
|---|---|
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Scans git history for committed secrets, on every push, PR and weekly |
| Type check, test suite, `wrangler deploy --dry-run` | Run on every PR ([`worker.yml`](.github/workflows/worker.yml)) |
| Dependabot | Weekly grouped updates for npm and GitHub Actions |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review |

Third-party actions are pinned to a commit SHA to defeat floating-tag supply-chain drift; Dependabot opens PRs to bump them.
