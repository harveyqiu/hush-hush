# hush-hush

[![worker](https://github.com/harveyqiu/hush-hush/actions/workflows/worker.yml/badge.svg)](https://github.com/harveyqiu/hush-hush/actions/workflows/worker.yml)
[![License: MIT](https://img.shields.io/github/license/harveyqiu/hush-hush)](LICENSE)

A minimal secret keeper that runs entirely on Cloudflare: one Worker, one D1 database, one Durable Object. HTTPS API, admin web UI, AES-256-GCM at rest, per-agent tokens with read scopes (plus optional create-only write scopes), and an audit log. No server to run.

Small enough to read in one sitting, real enough to use: the Worker is about 2k lines of TypeScript, the CLI about 1k, plus tests.

## What this is

A tiny HTTPS API for storing your own API keys, database URLs and OAuth secrets across personal projects. You `PUT` a value, you `GET` it back.

It is built for one human and a handful of automated agents (LLM tools, CI jobs, scripts). You hold an admin token; each agent gets its own token limited to the name prefixes it needs (read-only by default, optionally allowed to create new secrets in its own namespace), and every access is logged.

## What this isn't

- A team password manager (use [Vaultwarden](https://github.com/dani-garcia/vaultwarden))
- A Vault replacement (no policy language, no dynamic secrets, no PKI)
- Audited or compliant storage for customer data

## Threat model

Two layers, intentionally stacked. The first is always on; the second is opt-in.

### Layer 1: server-side AES-256-GCM (always on)

Values are encrypted before they reach D1. The master key is a Worker secret (`MASTER_KEY`); the ciphertext is in D1. The name and a version byte are bound into the authentication tag, so ciphertext moved to another name, or relabelled with another version, fails to decrypt.

**Protects against:** a leaked D1 export or backup, and read access to the database without access to Worker secrets.

**Does not protect against:** anyone who can deploy code to the Worker, read its secrets, or administer the Cloudflare account. They hold both the key and the ciphertext. Secure that account (hardware-key 2FA, a narrowly scoped API token) as you would the secrets themselves.

### Layer 2: client-side XChaCha20-Poly1305 (opt-in, `hush init`)

With the [`hush` CLI](cli/README.md), `hush init` creates a vault from a passphrase (Argon2id). From then on `hush put` / `hush get` encrypt and decrypt on your machine, and the server only stores opaque `hh2:` ciphertext on top of layer 1. Your passphrase never reaches Cloudflare.

**Protects against:** the Cloudflare-account and Worker compromise that layer 1 can't.

**Costs:** lose the passphrase and those secrets are gone; the passphrase is typed at a terminal every time, so unattended jobs can't decrypt; anything reading over raw HTTP gets ciphertext it can't use. Details in [`cli/README.md`](cli/README.md#client-side-encryption).

**Agents see plaintext** for anything stored without client-side encryption. A token limits *which* secrets an agent can read, not what it does with them.

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
     │ HTTPS            (the `hush` CLI, cli/, can encrypt
     ▼                   values before they leave your machine)
┌─ Cloudflare ───────────────────────────────────────────┐
│  Worker  (worker/src)                                   │
│    /v1/secrets  /v1/admin  /ui/  /llm.html  /healthz    │
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

## Use

- **You**: the admin UI at `/ui/`, or the [`hush` CLI](cli/README.md).
- **LLM agents**: point them at `https://<your-worker>/llm.html`. It is a public page, rendered with your real URL, that tells an agent how to connect, which calls it can make, what each status code means and how to handle secrets safely. The same server also serves the human guide in [`docs/agent-guide.md`](docs/agent-guide.md).

## Docs

| | |
|---|---|
| [`worker/README.md`](worker/README.md) | Deploy, settings, local development, operations |
| [`cli/README.md`](cli/README.md) | The `hush` command-line client and client-side encryption |
| [`docs/agent-guide.md`](docs/agent-guide.md) | For programs and LLM agents that read secrets: endpoints, status codes, examples |
| [`docs/functional-spec.md`](docs/functional-spec.md) | Exact behavior of every endpoint and the security properties to preserve |
| [`docs/workers-migration.md`](docs/workers-migration.md) | Design of the Workers version, how it differs from the old Go build, importing a Go database |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability, scope |

## History

hush-hush started as a single Go binary with SQLite, built to run in Docker. The Cloudflare version replaced it; the Go source lives in git history (last commit containing it: `e9d00a1`). The `hush` CLI and its client-side encryption were then rewritten in TypeScript, and stay compatible with the Go client's `vault.json` and `hh2:` values.

## License

[MIT](LICENSE)
