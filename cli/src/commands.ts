// The hush commands. Each takes its arguments and a Deps bag (I/O, environment,
// prompts, fetch) so tests can drive them without a terminal or a real server.

import { parseArgs } from "node:util";
import { stat } from "node:fs/promises";
import { ApiError, Client, normalizeBaseUrl, type FetchFn, type Secret } from "./client";
import { resolveConfig, saveConfigFile, type Env } from "./config";
import { resolveValue, readAll } from "./value";
import {
  VAULT_PREFIX,
  VaultError,
  decryptWire,
  defaultKdfParams,
  encryptWire,
  initVault,
  newSalt,
  unlockIfPresent,
  vaultPath,
  type KdfParams,
} from "./vault";

export interface Out {
  write(s: string): unknown;
}

export interface Deps {
  stdout: Out;
  stderr: Out;
  stdin: NodeJS.ReadableStream & { isTTY?: boolean };
  env: Env;
  configDir: string;
  /** Reads a hidden line from the terminal (passphrases, interactive values). */
  prompt: (label: string) => Promise<string>;
  fetch?: FetchFn;
  /** Tests substitute cheap Argon2id parameters; production uses the defaults. */
  kdfParams?: () => KdfParams;
}

/** A mistake in how the command was invoked: exits 2 and prints the usage text. */
export class UsageError extends Error {}

export const USAGE = `hush: command-line client for the hush-hush secret store.

Usage:
  hush <command> [flags]

Commands:
  login            Save URL + token to the local config (0600)
  health           Verify the server is reachable and the token works
  get NAME         Print the value of a secret to stdout
  put NAME [VALUE] Create/update a secret. Sources: arg | --from-file | --from-stdin | hidden prompt
  delete NAME      Remove a secret (idempotent)
  list             List the secrets you can see (table; --json for JSON)
  init             Create a client-side encryption vault (opt-in)
  migrate          Re-encrypt plaintext secrets under the active vault
  help             Show this message

Global flags (network commands):
  --url    Server base URL  (overrides config / HUSH_URL)
  --token  Bearer token     (overrides config / HUSH_TOKEN)

For real secrets prefer --from-stdin, --from-file or the prompt over a VALUE
argument: arguments end up in the process list and your shell history.

Config resolution: flag > env (HUSH_URL / HUSH_TOKEN) > config file.
Config dir: $HUSH_CONFIG_DIR, else the OS user config dir under hush/
(~/.config/hush on Linux). It holds config.json and, after \`hush init\`, vault.json.

With a vault, put encrypts on this machine before sending and get decrypts after
receiving; the passphrase never leaves it. Without one, values are sent as-is
(the server still encrypts them at rest).
`;

const CONN_OPTIONS = {
  url: { type: "string", default: "" },
  token: { type: "string", default: "" },
} as const;

type Parsed<O extends Record<string, { type: "string" | "boolean"; default?: string | boolean }>> = {
  values: { [K in keyof O]: O[K]["type"] extends "boolean" ? boolean : string };
  positionals: string[];
};

function parse<O extends Record<string, { type: "string" | "boolean"; default?: string | boolean }>>(
  cmd: string,
  args: string[],
  options: O,
): Parsed<O> {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true }) as unknown as Parsed<O>;
  } catch (e) {
    throw new Error(`${cmd}: ${(e as Error).message}`);
  }
}

function expectArgs(cmd: string, positionals: string[], max: number): void {
  if (positionals.length > max) throw new Error(`${cmd}: unexpected arguments: ${positionals.slice(max).join(" ")}`);
}

/** Prefixes failures with the command, and keeps server errors readable. */
function wrap(tag: string, e: unknown): Error {
  if (e instanceof ApiError) {
    const hint = e.status === 429 && e.retryAfter ? ` (retry after ${e.retryAfter}s)` : "";
    return new Error(`${tag}: ${e.message}${hint}`);
  }
  if (e instanceof Error && e.name === "TimeoutError") return new Error(`${tag}: request timed out`);
  if (e instanceof TypeError && e.message === "fetch failed") {
    const cause = (e as { cause?: { code?: string; message?: string } }).cause;
    return new Error(`${tag}: cannot reach the server${cause?.code ? ` (${cause.code})` : ""}`);
  }
  return new Error(`${tag}: ${(e as Error).message}`);
}

async function resolveClient(d: Deps, flagUrl: string, flagToken: string): Promise<Client> {
  const cfg = await resolveConfig(d.configDir, flagUrl, flagToken, d.env);
  if (!cfg.url) throw new Error("no URL configured (set via --url, HUSH_URL, or 'hush login')");
  if (!cfg.token) throw new Error("no token configured (set via --token, HUSH_TOKEN, or 'hush login')");
  return new Client(cfg.url, cfg.token, d.fetch);
}

/**
 * Bridge between the wire format and the value the user sees:
 *  - no vault: pass through (there is no key; an `hh2:` value can only be a
 *    plaintext that happens to start with it)
 *  - vault + `hh2:` value: decrypt, with the name bound as AAD
 *  - vault + plaintext value: refuse and point at `hush migrate`
 */
function maybeDecrypt(key: Uint8Array | null, name: string, wire: string): string {
  if (key === null) return wire;
  if (!wire.startsWith(VAULT_PREFIX)) {
    throw new Error(`${JSON.stringify(name)} is a plaintext secret; run \`hush migrate\` to convert it`);
  }
  try {
    return decryptWire(key, wire, name);
  } catch (e) {
    // The passphrase was already verified at unlock, so a tag failure here
    // means the stored value was modified or belongs to a different name.
    if (e instanceof VaultError && e.code === "bad_passphrase") {
      throw new Error(`cannot decrypt ${JSON.stringify(name)}: the stored value was modified or belongs to another name`);
    }
    throw e;
  }
}

export async function cmdLogin(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("login", args, CONN_OPTIONS);
  expectArgs("login", positionals, 0);
  if (!values.url || !values.token) throw new Error("login: --url and --token are required");
  normalizeBaseUrl(values.url); // fail now, not on the first command
  const p = await saveConfigFile(d.configDir, { url: values.url, token: values.token });
  d.stdout.write(`config saved to ${p} (mode 0600)\n`);
}

export async function cmdHealth(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("health", args, CONN_OPTIONS);
  expectArgs("health", positionals, 0);
  const cfg = await resolveConfig(d.configDir, values.url, values.token, d.env);
  if (!cfg.url) throw new Error("no URL configured (set via --url, HUSH_URL, or 'hush login')");
  const c = new Client(cfg.url, cfg.token, d.fetch);
  try {
    await c.health();
  } catch (e) {
    throw wrap("reachability check failed", e);
  }
  d.stdout.write(`${cfg.url}: reachable\n`);
  if (!cfg.token) {
    d.stdout.write("auth: skipped (no token configured)\n");
    return;
  }
  try {
    await c.authCheck();
  } catch (e) {
    throw wrap("auth check failed", e);
  }
  d.stdout.write("auth: ok\n");
}

export async function cmdGet(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("get", args, CONN_OPTIONS);
  expectArgs("get", positionals, 1);
  const name = positionals[0];
  if (!name) throw new Error("get: NAME is required");
  // Unlock BEFORE the network round trip, so a wrong passphrase fails fast
  // instead of surfacing as "decrypt failed" after the value came back.
  let key: Uint8Array | null;
  try {
    key = await unlockIfPresent(d.configDir, d.prompt);
  } catch (e) {
    throw wrap("get", e);
  }
  const c = await resolveClient(d, values.url, values.token);
  let s: Secret;
  try {
    s = await c.get(name);
  } catch (e) {
    throw wrap("get", e);
  }
  let value: string;
  try {
    value = maybeDecrypt(key, name, s.value ?? "");
  } catch (e) {
    throw wrap("get", e);
  }
  // No trailing newline, so `hush get FOO | clip` round-trips the exact value.
  d.stdout.write(value);
}

export async function cmdPut(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("put", args, {
    ...CONN_OPTIONS,
    "from-file": { type: "string", default: "" },
    "from-stdin": { type: "boolean", default: false },
  });
  expectArgs("put", positionals, 2);
  const name = positionals[0];
  if (!name) throw new Error("put: NAME is required");

  let value: string;
  try {
    value = await resolveValue({
      arg: positionals[1] ?? "",
      fromFile: values["from-file"],
      fromStdin: values["from-stdin"],
      readStdin: () => readAll(d.stdin),
      prompt: d.prompt,
      isTty: d.stdin.isTTY === true,
    });
  } catch (e) {
    throw wrap("put", e);
  }
  if (value === "") throw new Error("put: value is empty");

  // Unlock BEFORE encrypting so a wrong passphrase can't push a value sealed
  // under the wrong key, which would corrupt the row until someone noticed.
  let key: Uint8Array | null;
  try {
    key = await unlockIfPresent(d.configDir, d.prompt);
  } catch (e) {
    throw wrap("put", e);
  }
  let wire = value;
  if (key !== null) {
    wire = encryptWire(key, value, name);
  } else if (value.startsWith(VAULT_PREFIX)) {
    // Reserve the prefix on the plaintext path: otherwise a value that merely
    // looks like ciphertext becomes ambiguous the day a vault is created.
    throw new Error(
      `put: values starting with ${JSON.stringify(VAULT_PREFIX)} are reserved for client-encrypted secrets; run \`hush init\` to encrypt or choose a different value`,
    );
  }

  const c = await resolveClient(d, values.url, values.token);
  try {
    await c.put(name, wire);
  } catch (e) {
    throw wrap("put", e);
  }
  // "saved", not "created"/"updated": timestamps have one-second resolution, so
  // a put-then-put in the same second is indistinguishable from a create.
  d.stdout.write(`${name}: saved\n`);
}

export async function cmdDelete(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("delete", args, CONN_OPTIONS);
  expectArgs("delete", positionals, 1);
  const name = positionals[0];
  if (!name) throw new Error("delete: NAME is required");
  const c = await resolveClient(d, values.url, values.token);
  try {
    await c.delete(name);
  } catch (e) {
    throw wrap("delete", e);
  }
  d.stdout.write(`${name}: deleted\n`);
}

const fmtTime = (unix: number) =>
  unix ? new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z") : "-";

/** Left-aligned columns separated by two spaces. */
export function renderTable(rows: string[][]): string {
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? "").length)));
  return rows.map((r) => r.map((cell, i) => (i === r.length - 1 ? cell : cell.padEnd(widths[i]! + 2))).join("")).join("\n") + "\n";
}

export async function cmdList(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("list", args, { ...CONN_OPTIONS, json: { type: "boolean", default: false } });
  expectArgs("list", positionals, 0);
  const c = await resolveClient(d, values.url, values.token);
  let secrets: Secret[];
  try {
    secrets = await c.list();
  } catch (e) {
    throw wrap("list", e);
  }
  if (values.json) {
    d.stdout.write(JSON.stringify(secrets, null, 2) + "\n");
    return;
  }
  if (secrets.length === 0) {
    d.stdout.write("(no secrets)\n");
    return;
  }
  d.stdout.write(
    renderTable([["NAME", "CREATED", "UPDATED"], ...secrets.map((s) => [s.name, fmtTime(s.created_at), fmtTime(s.updated_at)])]),
  );
}

export async function cmdInit(args: string[], d: Deps): Promise<void> {
  const { positionals } = parse("init", args, {});
  expectArgs("init", positionals, 0);
  // Check first so we don't ask for a passphrase that can't be used;
  // initVault's exclusive create is what actually guarantees it.
  const vp = vaultPath(d.configDir);
  if (await stat(vp).then(() => true, () => false)) throw new Error(`init: ${new VaultError("exists").message}`);

  const p1 = await d.prompt("vault passphrase: ").catch((e: unknown) => {
    throw wrap("init", e);
  });
  if (p1 === "") throw new Error("init: passphrase cannot be empty");
  const p2 = await d.prompt("confirm passphrase: ").catch((e: unknown) => {
    throw wrap("init", e);
  });
  if (p1 !== p2) throw new Error("init: passphrases do not match");

  try {
    await initVault(d.configDir, p1, (d.kdfParams ?? (() => defaultKdfParams(newSalt())))());
  } catch (e) {
    throw wrap("init", e);
  }
  d.stdout.write(`vault initialized at ${vp} (mode 0600)\n\n`);
  // Loud, once: the passphrase is irrecoverable.
  d.stdout.write("IMPORTANT: back up this passphrase somewhere safe.\n");
  d.stdout.write("If you lose it, every client-encrypted secret in your vault is unrecoverable.\n");
}

/**
 * Re-puts every plaintext secret as ciphertext under the active vault; values
 * already encrypted are skipped, so it is safe to re-run. Sequential, and it
 * carries on past a failing secret, then exits non-zero if any failed.
 */
export async function cmdMigrate(args: string[], d: Deps): Promise<void> {
  const { values, positionals } = parse("migrate", args, { ...CONN_OPTIONS, "dry-run": { type: "boolean", default: false } });
  expectArgs("migrate", positionals, 0);
  let key: Uint8Array | null;
  try {
    key = await unlockIfPresent(d.configDir, d.prompt);
  } catch (e) {
    throw wrap("migrate", e);
  }
  if (key === null) throw new Error("migrate: no vault configured (run `hush init` first)");

  const c = await resolveClient(d, values.url, values.token);
  let secrets: Secret[];
  try {
    secrets = await c.list();
  } catch (e) {
    throw wrap("migrate: list", e);
  }
  const dry = values["dry-run"];
  let migrated = 0;
  let skipped = 0;
  let failed = 0;
  for (const s of secrets) {
    let full: Secret;
    try {
      full = await c.get(s.name);
    } catch (e) {
      d.stdout.write(`error: ${s.name}: get: ${(e as Error).message}\n`);
      failed++;
      continue;
    }
    const current = full.value ?? "";
    if (current.startsWith(VAULT_PREFIX)) {
      skipped++;
      continue;
    }
    if (dry) {
      d.stdout.write(`would migrate: ${s.name}\n`);
      migrated++;
      continue;
    }
    try {
      await c.put(s.name, encryptWire(key, current, s.name));
    } catch (e) {
      d.stdout.write(`error: ${s.name}: put: ${(e as Error).message}\n`);
      failed++;
      continue;
    }
    d.stdout.write(`migrated: ${s.name}\n`);
    migrated++;
  }
  d.stdout.write(`done: ${migrated} ${dry ? "would migrate" : "migrated"}, ${skipped} skipped (already encrypted), ${failed} errors\n`);
  if (failed > 0) throw new Error(`migrate: ${failed} secret(s) failed`);
}

