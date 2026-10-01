# hush: command-line client

A command-line client for hush-hush, with optional client-side encryption. One file, no install step beyond Node 20+.

```bash
hush put llm.openai          # prompts for the value, hidden
hush get llm.openai          # prints it, no trailing newline
hush list
```

## Build and install

```bash
cd cli
npm ci
npm run build                # -> dist/hush.mjs, a single self-contained file (about 75 KiB)
install -m 755 dist/hush.mjs ~/.local/bin/hush
```

The bundle needs only Node 20 or newer; `node_modules` is not needed to run it.

## Connect

```bash
hush login --url https://<your-worker>.workers.dev --token hush_...   # saved to config.json, mode 0600
hush health                                                           # reachable? token accepted?
```

or use the environment (`HUSH_URL`, `HUSH_TOKEN`) or the flags `--url` / `--token` on any command. Precedence: flag, then environment, then the config file.

The token is only ever sent over `https`. Plain `http` is accepted for `localhost` / `127.0.0.1` (for `wrangler dev`) and nothing else, and redirects are never followed with the token attached.

## Commands

| | |
|---|---|
| `login --url U --token T` | Save the connection to the config file |
| `health` | Check the server is reachable and the token works |
| `get NAME` | Print a secret's value |
| `put NAME [VALUE]` | Create or update a secret. The value comes from the argument, `--from-file PATH`, `--from-stdin`, or a hidden prompt |
| `delete NAME` | Remove a secret (idempotent; admin tokens only) |
| `list [--json]` | List the names you can see |
| `init` | Create a client-side encryption vault |
| `migrate [--dry-run]` | Encrypt the existing plaintext secrets under the vault |

Exit codes: `0` success, `1` an error (including a server error status), `2` a usage mistake.

For real secrets prefer the prompt, `--from-stdin` or `--from-file` over a `VALUE` argument: arguments show up in the process list and in shell history. A single trailing newline is stripped from stdin and file input, so an editor's final newline doesn't become part of the secret.

Where the config lives: `$HUSH_CONFIG_DIR`, else `~/.config/hush` (Linux), `~/Library/Application Support/hush` (macOS) or `%AppData%\hush` (Windows). It holds `config.json` and, after `hush init`, `vault.json`.

## Client-side encryption

Without a vault, the server stores your value as sent (encrypted at rest with its own key). With a vault, `hush put` encrypts the value on your machine first and `hush get` decrypts it after receiving it, so the server only ever holds ciphertext it cannot read, even if the Cloudflare account is compromised.

```bash
hush init            # choose a passphrase (asked twice); creates vault.json
hush migrate         # optional: encrypt secrets that were stored before the vault existed
```

How it works: your passphrase goes through Argon2id (64 MiB, 3 passes, 4 lanes) to make a 32-byte key. Each value is sealed with XChaCha20-Poly1305 using a fresh random 24-byte nonce, with the secret's name bound in as authenticated data (so a ciphertext moved to another name fails to decrypt), and stored as `hh2:` + base64(nonce ‖ ciphertext). `vault.json` holds only the Argon2 parameters, the salt and a check value that lets a wrong passphrase be rejected before any request is made. The reasoning is in [`../docs/adr/0001-client-side-encryption.md`](../docs/adr/0001-client-side-encryption.md).

This is byte-compatible with the earlier Go client: a `vault.json` and `hh2:` values written by either work with the other (the tests include vectors produced by the Go code).

What to know before you rely on it:

- **If you lose the passphrase, every encrypted secret is gone.** There is no recovery. Back it up.
- **The passphrase is read from the terminal, every time.** It is not cached, kept in the environment or stored in a file, so an unattended job (CI, a cron task, an agent) cannot decrypt. Secrets that automation must read over plain HTTP should stay plaintext (see below).
- **Anything that reads over raw HTTP gets `hh2:` ciphertext** for an encrypted secret, which it cannot use. Don't migrate those.
- With a vault active, `put` always encrypts and `get` refuses a plaintext value (run `hush migrate`). To manage plaintext secrets for HTTP consumers alongside an encrypted vault, use a second config directory without a vault (it needs its own `hush login`, or `HUSH_URL` and `HUSH_TOKEN`): `HUSH_CONFIG_DIR=~/.config/hush-plain hush put ...`.
- A wrong passphrase is detected before any network request, so it can't write a value sealed under the wrong key.
- `vault.json` is not secret in the way the passphrase is, but it lets someone who also has your ciphertext try passphrases offline (slowed by Argon2id). Choose a long passphrase and keep the file private (it is created `0600`).
- `get` reports "the stored value was modified or belongs to another name" when a ciphertext fails to decrypt after the passphrase was accepted.
- An existing vault is never overwritten by `hush init`; a `vault.json` that asks for more than 1 GiB of memory, more than 64 passes or more than 64 lanes is refused.

## Develop

```bash
npm ci
npm run typecheck
npm test                     # unit + command tests, against an in-memory mock server
bash scripts/e2e.sh          # builds the CLI, starts a real Worker (wrangler dev), runs the CLI against it
```

`scripts/e2e.sh` needs `npm ci` in `../worker` as well. Source is in `src/`: `vault.ts` (the cryptography), `client.ts` (HTTP), `commands.ts` (the commands), `config.ts`, `value.ts` (value sources and the hidden prompt), `main.ts` (dispatch).
