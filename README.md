# hush-hush

[![worker](https://github.com/harveyqiu/hush-hush/actions/workflows/worker.yml/badge.svg)](https://github.com/harveyqiu/hush-hush/actions/workflows/worker.yml)
[![License: MIT](https://img.shields.io/github/license/harveyqiu/hush-hush)](LICENSE)

A minimal secret keeper that runs entirely on Cloudflare: one Worker, one D1 database, one Durable Object. HTTPS API, admin web UI, AES-256-GCM at rest, per-agent tokens with read scopes (plus optional create-only write scopes), and an audit log. No server to run.

Small enough to read in one sitting (about 1.8k lines of TypeScript plus tests), real enough to use.

## What this is

A tiny HTTPS API for storing your own API keys, database URLs and OAuth secrets across personal projects. You `PUT` a value, you `GET` it back.

It is built for one human and a handful of automated agents (LLM tools, CI jobs, scripts). You hold an admin token; each agent gets its own token limited to the name prefixes it needs (read-only by default, optionally allowed to create new secrets in its own namespace), and every access is logged.

## What this isn't

- A team password manager (use [Vaultwarden](https://github.com/dani-garcia/vaultwarden))
- A Vault replacement (no policy language, no dynamic secrets, no PKI)
- Audited or compliant storage for customer data

## Threat model

Values are encrypted server-side with AES-256-GCM. The master key is a Worker secret (`MASTER_KEY`); the ciphertext is in D1. The name and a version byte are bound into the authentication tag, so ciphertext moved to another name, or relabelled with another version, fails to decrypt.

**Protects against:** a leaked D1 export or backup, and read access to the database without access to Worker secrets.

**Does not protect against:** anyone who can deploy code to the Worker, read its secrets, or administer the Cloudflare account. They hold both the key and the ciphertext. Secure that account (hardware-key 2FA, a narrowly scoped API token) as you would the secrets themselves.

**Agents see plaintext.** A token limits *which* secrets an agent can read, not what it does with them.

There is no client-side encryption layer. An earlier Go build had one in its CLI; it was removed together with the rest of the Go code (see [History](#history)).

### Access control

One owner, many agents. Every caller has its own bearer token (`hush_` plus 64 hex characters), stored only as a SHA-256 hash and checked against the database on every request, so revocation is immediate.

| | admin | agent |
|---|---|---|
| read | everything | names under its read prefixes (`*` = everything, must be confirmed) |
| write | everything, can overwrite | create-only under its write prefixes, never overwrite |
| delete, token management, audit | yes | no |
| expiry | required, at most 90 days | optional |

Anything outside an agent's grant is `403`, whether or not the name exists. Every `/v1/secrets` and `/v1/admin` request lands in the audit log (names and outcomes, never values), and a write and its audit row commit together. The full list of guarantees is in [`docs/functional-spec.md`](docs/functional-spec.md#11-安全属性清单重写必须保持).

## Architecture

```
agents / you
     │ HTTPS
     ▼
┌─ Cloudflare ───────────────────────────────────────────┐
│  Worker  (worker/src)                                   │
│    /v1/secrets   /v1/admin   /ui/   /healthz            │
│       │                │                                │
│       ▼                ▼                                │
│  D1  secrets · tokens · audit_log     Durable Object    │
│  (ciphertext, token hashes)           (rate-limit       │
│                                        buckets)         │
│  Secret: MASTER_KEY        Cron: daily housekeeping     │
└─────────────────────────────────────────────────────────┘
```

## Deploy

See [`worker/README.md`](worker/README.md): create the D1 database, set `MASTER_KEY`, deploy, create the first admin token. An automatic deploy workflow exists but is switched off; see the header of [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml).

## Docs

| | |
|---|---|
| [`worker/README.md`](worker/README.md) | Deploy, settings, local development, operations |
| [`docs/agent-guide.md`](docs/agent-guide.md) | For programs and LLM agents that read secrets: endpoints, status codes, examples |
| [`docs/functional-spec.md`](docs/functional-spec.md) | Exact behavior of every endpoint and the security properties to preserve |
| [`docs/workers-migration.md`](docs/workers-migration.md) | Design of the Workers version, how it differs from the old Go build, importing a Go database |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability, scope |

## History

hush-hush started as a single Go binary with SQLite, built to run in Docker. That implementation, including its `hush` command-line client and client-side encryption, was replaced by the Cloudflare version and lives in git history: the last commit that contains it is `e9d00a1`.

## License

[MIT](LICENSE)
