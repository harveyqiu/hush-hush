# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to **[Report a vulnerability](https://github.com/cjunks94/hush-hush/security/advisories/new)**
2. Describe the issue with reproduction steps if possible
3. You'll get an acknowledgement within 7 days; we'll discuss the fix and disclosure timeline together

## Supported versions

This is an active personal project; only the latest commit on `main` is supported. Security fixes land on `main` and are not backported.

| Version | Supported |
| ------- | --------- |
| `main`  | ✅ |
| Tagged releases | Best-effort within the latest minor |

## In scope

- The Go HTTP server in `main.go` — auth, crypto, validation, headers, log injection vectors
- Dependencies in `go.mod` — already scanned weekly via `govulncheck`
- The CI workflow in `.github/workflows/security.yml`

## Out of scope

This is a deliberately minimal self-hosted tool for one operator and a handful of agents. The following are documented trade-offs in the [threat model](README.md#threat-model), not vulnerabilities:

- **Server-side encryption**: the master key is loaded into the server process (systemd credential or env var); host compromise exposes both key and ciphertext. Protects against backup / volume-snapshot leaks, not host compromise.
- **Agents see plaintext values**: an agent token can read the values under its prefixes. Access control limits *which* secrets an agent gets, not what it does with them.
- **Same-user bypass**: any process running as the `hush` user (or root) can read the database and master key directly, skipping tokens, prefixes and the audit log. Agents must run as different Linux users; see [`deploy/README.md`](deploy/README.md).
- **Agent-created secrets**: an agent with write prefixes can create new names there (never overwrite or delete). Anything that reads that namespace should treat those values as agent-supplied.
- **In-memory rate limits** reset on restart.
- **Audit `remote_addr` is advisory** for callers on the same host when `TRUST_PROXY_HEADERS=true`, since a local process can talk to the loopback listener and set its own `X-Forwarded-For`.
- **No token management over HTTP**: tokens are created and revoked only through the local `hush-hush token` CLI, by design.

If your use case requires any of those properties, please pick a different tool — see the [README's "What this isn't" section](README.md#what-this-isnt).

## Security tooling

The following run in CI on every push, PR, and weekly Mon 06:00 UTC cron:

| Tool | Purpose |
|---|---|
| [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Stdlib + dependency CVE scan against the live Go vuln DB |
| [`gosec`](https://github.com/securego/gosec) | Static security analysis (medium+ severity) |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Scans git history for committed secrets |
| Dependabot | Weekly grouped dependency updates |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review |

Tool versions are pinned (specific tags / commit SHAs) to defeat `@latest` supply-chain drift; Dependabot opens PRs to bump them as new releases ship.
