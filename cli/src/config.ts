// Connection settings: URL + token, from flag > environment > config file.

import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export interface Config {
  url: string;
  token: string;
}

export interface Env {
  [key: string]: string | undefined;
}

/**
 * Where config.json and vault.json live. HUSH_CONFIG_DIR overrides; otherwise
 * the OS user config dir: $XDG_CONFIG_HOME or ~/.config on Linux,
 * ~/Library/Application Support on macOS, %AppData% on Windows.
 */
export function configDir(env: Env = process.env, platform: string = process.platform, home: string = homedir()): string {
  if (env["HUSH_CONFIG_DIR"]) return env["HUSH_CONFIG_DIR"];
  let base: string;
  if (platform === "win32") base = env["APPDATA"] || join(home, "AppData", "Roaming");
  else if (platform === "darwin") base = join(home, "Library", "Application Support");
  else base = env["XDG_CONFIG_HOME"] || join(home, ".config");
  return join(base, "hush");
}

export const configPath = (dir: string) => join(dir, "config.json");

/** A missing file is fine (flags/env may supply everything); a corrupt one is an error so it isn't silently ignored. */
export async function loadConfigFile(dir: string): Promise<Config> {
  const p = configPath(dir);
  let raw: string;
  try {
    raw = await readFile(p, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { url: "", token: "" };
    throw new Error(`read config: ${(e as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`parse config ${p}: ${(e as Error).message}`);
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error(`parse config ${p}: not an object`);
  const o = parsed as Record<string, unknown>;
  return { url: typeof o["url"] === "string" ? o["url"] : "", token: typeof o["token"] === "string" ? o["token"] : "" };
}

/** Writes config.json (dir 0700, file 0600) and returns its path. */
export async function saveConfigFile(dir: string, cfg: Config): Promise<string> {
  const p = configPath(dir);
  await mkdir(dirname(p), { recursive: true, mode: 0o700 });
  await writeFile(p, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  // writeFile's mode only applies on creation; tighten an existing file too.
  await chmod(p, 0o600).catch(() => {});
  return p;
}

/** flag > env (HUSH_URL / HUSH_TOKEN) > file. An empty value counts as "not set". */
export async function resolveConfig(dir: string, flagUrl: string, flagToken: string, env: Env): Promise<Config> {
  const cfg = await loadConfigFile(dir);
  if (env["HUSH_URL"]) cfg.url = env["HUSH_URL"];
  if (env["HUSH_TOKEN"]) cfg.token = env["HUSH_TOKEN"];
  if (flagUrl) cfg.url = flagUrl;
  if (flagToken) cfg.token = flagToken;
  return cfg;
}
