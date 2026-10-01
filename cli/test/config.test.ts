import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { configDir, configPath, loadConfigFile, resolveConfig, saveConfigFile } from "../src/config";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hush-cfg-"));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

describe("configDir", () => {
  it("HUSH_CONFIG_DIR wins; otherwise the OS user config dir", () => {
    expect(configDir({ HUSH_CONFIG_DIR: "/x" }, "linux", "/home/u")).toBe("/x");
    expect(configDir({}, "linux", "/home/u")).toBe(join("/home/u", ".config", "hush"));
    expect(configDir({ XDG_CONFIG_HOME: "/xdg" }, "linux", "/home/u")).toBe(join("/xdg", "hush"));
    expect(configDir({}, "darwin", "/Users/u")).toBe(join("/Users/u", "Library", "Application Support", "hush"));
    expect(configDir({ APPDATA: "C:\\Roaming" }, "win32", "C:\\Users\\u")).toBe(join("C:\\Roaming", "hush"));
  });
});

describe("config file", () => {
  it("a missing file is empty config; a corrupt one is an error", async () => {
    expect(await loadConfigFile(dir)).toEqual({ url: "", token: "" });
    await writeFile(configPath(dir), "{nope");
    await expect(loadConfigFile(dir)).rejects.toThrow(/parse config/);
    await writeFile(configPath(dir), "[]");
    expect(await loadConfigFile(dir)).toEqual({ url: "", token: "" });
    await writeFile(configPath(dir), "null");
    await expect(loadConfigFile(dir)).rejects.toThrow(/not an object/);
  });

  it.skipIf(process.platform === "win32")("is saved 0600, tightening an existing wider file", async () => {
    await writeFile(configPath(dir), "{}", { mode: 0o644 });
    await chmod(configPath(dir), 0o644);
    await saveConfigFile(dir, { url: "https://x", token: "t" });
    expect((await stat(configPath(dir))).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(configPath(dir), "utf8"))).toEqual({ url: "https://x", token: "t" });
  });

  it("creates the config directory when needed", async () => {
    const nested = join(dir, "a", "b");
    await saveConfigFile(nested, { url: "https://x", token: "t" });
    expect((await loadConfigFile(nested)).url).toBe("https://x");
  });
});

describe("resolveConfig precedence: flag > env > file", () => {
  it("applies them in order, treating empty values as unset", async () => {
    await saveConfigFile(dir, { url: "https://file", token: "file-t" });
    expect(await resolveConfig(dir, "", "", {})).toEqual({ url: "https://file", token: "file-t" });
    expect(await resolveConfig(dir, "", "", { HUSH_URL: "https://env", HUSH_TOKEN: "env-t" })).toEqual({ url: "https://env", token: "env-t" });
    expect(await resolveConfig(dir, "https://flag", "flag-t", { HUSH_URL: "https://env", HUSH_TOKEN: "env-t" })).toEqual({ url: "https://flag", token: "flag-t" });
    expect(await resolveConfig(dir, "", "", { HUSH_URL: "", HUSH_TOKEN: "" })).toEqual({ url: "https://file", token: "file-t" });
  });
});
