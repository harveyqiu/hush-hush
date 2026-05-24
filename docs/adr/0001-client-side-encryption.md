# ADR-0001: Client-side encryption (v2)

## Status

Accepted — shipped via PRs [#13](https://github.com/cjunks94/hush-hush/pull/13), [#14](https://github.com/cjunks94/hush-hush/pull/14), [#15](https://github.com/cjunks94/hush-hush/pull/15) (2026-05-23 / 2026-05-24).

## Context

v1 stores secrets under server-side AES-256-GCM with the master key as a Railway env var. The threat model that buys us: protection against stolen database backups and volume snapshots. The threat model that doesn't: host compromise. If an attacker gets shell on the Railway container, they can read both the key and the ciphertext.

A v2 effort was deferred until "the moment a CLI exists" — that moment arrived with PRs #11/#12. Adding client-side encryption raises the protection ceiling to **Railway host compromise**: the user's passphrase never touches the server, so a fully-compromised host still doesn't yield plaintext.

This ADR captures the design decisions made across the four-PR v2 effort. Implementation lives in `cmd/hush/vault.go` and the get/put/migrate paths in `cmd/hush/main.go`.

## Decisions

### Opt-in via `hush init`, not a flag day

A user who never runs `hush init` sees identical v1 behavior. Activation is local-only state (a `vault.json` file in the OS user config dir). The server is content-agnostic — it stores whatever the client sends, encrypted or not.

**Why:** existing v1 deployments must keep working without intervention. Non-CLI consumers (raw HTTP) can't decrypt v2 ciphertext, so forcing migration would break them. The maintainer's own production deployment is one such case — see the Consequences section.

### Two independent encryption layers (defense in depth)

v2 ciphertext is wrapped by v1's server-side AES-GCM at rest. The server doesn't know or care that the value it's encrypting is itself ciphertext. Two layers, two independent keys, two independent failure modes.

**Why not replace v1?** Removing the server layer would mean a stolen DB backup yields v2 ciphertexts. Without the master key, an attacker would still have to brute-force the passphrase — but defending against weak passphrases is exactly Argon2id's job. Keeping both layers means the attacker has to defeat both. Cost: ~32 bytes of overhead per secret. Worth it.

### KDF: Argon2id

Parameters baked into the binary as OWASP 2025 defaults: `m=64 MiB, t=3, p=4`. Stored per-vault in `vault.json` so future params roll forward cleanly without breaking existing vaults.

**Why Argon2id:** modern OWASP guidance, memory-hard (defeats GPU/ASIC attackers), tunable. Argon2id specifically (vs Argon2i / Argon2d) for resistance to both side-channel and time-memory trade-off attacks.

**Why not scrypt:** older, less well-studied parallelism resistance, no in-tree Go stdlib equivalent so we'd be on `golang.org/x/crypto/scrypt` either way.

**Why not PBKDF2:** not memory-hard. Cheap to parallelize on modern GPUs. OWASP lists it as acceptable but not recommended for new applications.

**Why not bcrypt:** 72-byte input limit, fixed 32-byte salt, not standardized in the way Argon2 is now.

### AEAD: XChaCha20-Poly1305

**Why XChaCha20 specifically:** 192-bit nonces. Random nonces are safe to the birthday bound, which means we can use `crypto/rand` directly without maintaining a per-key counter. A counter would require persistent client-side state per vault — error-prone and fragile.

**Why not AES-GCM:** 96-bit nonce. Random nonces are NOT safe past 2³² messages per key (birthday bound on a 96-bit nonce space). For a personal vault that's well above the practical ceiling, but mixing random nonces with no counter is just a hazard to reason about. XChaCha20-Poly1305 takes the question off the table.

**Why not pull from `crypto/cipher` directly:** `golang.org/x/crypto/chacha20poly1305` is the canonical Go binding, well-maintained, audited.

### Wire format: `hh2:<base64(nonce ‖ ciphertext)>`

Human-recognizable prefix in DB dumps and logs. The `hh2:` literal lets the client distinguish v2 from legacy v1 plaintext without ambiguity, AND lets a user grepping the SQLite file see at a glance which rows are encrypted.

**Why not a single magic byte:** would require base64-decoding every value to inspect, and binary-in-a-JSON-string is unpleasant for debugging.

**Why not embed format version in the verify blob:** the verify blob is encrypted, so the client can't read it before unlock. The prefix needs to be observable pre-unlock.

### AAD bound to the secret name

Every AEAD seal includes the secret's name as Additional Authenticated Data. Server already does this on its layer (same defense, independent key). Without it, an attacker with DB write access could swap ciphertext between rows — moving the value of `prod-db-password` into the `dev-db-password` row, for instance.

### Per-vault salt, not per-secret

One Argon2 derivation per CLI invocation, not N. ~500ms once vs N×500ms per `hush migrate`.

**Why this is safe:** the salt is not the key. It's a value the KDF mixes in to defeat rainbow tables. A single salt per vault, randomly generated, is sufficient — what matters is that the salt is unique across users, not across secrets.

**What we lose:** if the salt leaks (e.g., from a vault.json copy), an attacker who also obtains a passphrase candidate can precompute Argon2 derivations once and use them across all secrets. With per-secret salts, they'd have to redo the work per secret. For a personal vault with a single user, the per-secret salt cost (N×500ms migrations, plus salt storage overhead) isn't worth this marginal gain.

### Reserved `hh2:` prefix on plaintext writes (no-vault collision avoidance)

`cmdPut` refuses to store a plaintext value that starts with `hh2:` when no vault is active. Without this, a future `hush init` would create an ambiguity — was that stored value plaintext or ciphertext?

**Why a write-side check is the right place:** the read path (`maybeDecrypt`) cannot tell legitimate plaintext from ciphertext without the key, and the key is absent in the no-vault state. Refusing on write is the only spot where we have enough context to make a definitive decision.

### Unlock-before-network on every command

`cmdGet`, `cmdPut`, and `cmdMigrate` all derive the key and validate it against the vault's verify blob **before** any HTTP request. Wrong passphrase = no network traffic, no state change, no half-corrupt rows on the server.

**Why a verify blob and not just trust the AEAD tag check on the actual secret:** the verify blob lets us reject wrong-passphrase up front. Without it, `hush put foo bar` with the wrong passphrase would encrypt `bar` under a wrong key, send to the server, and silently corrupt the row — only discoverable later when `hush get foo` fails to decrypt.

### Atomic vault create with `O_EXCL`

`saveNewVault` opens vault.json with `O_WRONLY|O_CREATE|O_EXCL` and a parent-dir `MkdirAll`. Closes a TOCTOU window where two concurrent `hush init` calls could both pass an `os.Stat` check and have the second one overwrite the first.

**Why this matters for a single-user tool:** unlikely in practice but the fix is one syscall and the alternative is a foot-gun documented away as "don't run init twice at the same time."

### No passphrase caching in v2

Each command prompts once. No keychain integration, no session token, no remember-me file.

**Why:** caching the derived key (or the passphrase) means it lives somewhere outside the user's head between commands. Every cache layer is a new threat surface — OS keychain compromise, file permission bug, swap leak. v2 MVP optimizes for the minimum-trust path.

If revisited later, the most likely shape is OS keychain integration (macOS Keychain, Windows DPAPI, Linux libsecret) behind a `--remember` flag — explicit opt-in per the same principle as `hush init`.

### No server-side migration automation

`hush migrate` is a client-side command. There is no Railway deploy hook, no GitHub Actions workflow, no server cron that auto-migrates.

**Why this is non-negotiable:** any "automated on deploy" path requires the passphrase to be reachable from infrastructure the user doesn't fully trust (Railway env vars, GH Actions secrets). That defeats v2's entire reason to exist — the passphrase never touching infrastructure is the whole protection. The acceptable form, if revisited, is a CI workflow that runs migrate with the passphrase in GH secrets AND an explicit threat-model acknowledgment that GH is now the trust anchor.

## Consequences

**Positive:**

- Railway host compromise no longer yields plaintext (the primary v2 goal).
- Two independent encryption layers — even a master-key leak doesn't expose v2-encrypted values without the passphrase.
- Opt-in design means existing v1 deployments are unaffected.
- Migration tooling (`hush migrate`) is idempotent and safe to re-run: already-v2 secrets are skipped.

**Negative:**

- **Lose the passphrase = lose every v2-encrypted secret.** Catastrophic, irrecoverable. `hush init` prints a loud warning at vault creation.
- Wrong passphrase typed at `hush init` (somehow surviving the confirm-prompt check) bakes the wrong key into the vault permanently. Not really fixable.
- Non-CLI consumers of the HTTP API can't decrypt v2. Raw `curl /v1/secrets/foo` against a v2-encrypted secret returns the `hh2:base64...` blob. Any external consumer must either use the CLI, vendor the vault code, or stay on v1.
- The maintainer's own production deployment is opt-out because of the consumer-compatibility issue: `agentic-portfolio` fetches the deepseek key via raw HTTP. v2 ships as portfolio-visible code but is not activated on `hush-hush-production.up.railway.app`. If/when consumers move to the CLI or a vault-aware client library, activation becomes possible.
- Every command pays ~500ms for the Argon2 derivation. Acceptable for personal-scale interactive use; would be too slow for a hot path.

**Neutral / future work:**

- OS keychain integration deferred (see "No passphrase caching" above).
- `--unencrypted` flag on `hush put` for per-secret opt-out under an active vault — deferred. Would unblock partial-v2 deployments where some secrets need raw HTTP consumers and some don't.
- Key rotation tooling (re-key the vault, re-encrypt all secrets under the new key) deferred. Currently the only path is `hush init` to a fresh vault dir plus manual re-puts.
