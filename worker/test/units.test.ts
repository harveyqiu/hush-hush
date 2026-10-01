import { describe, expect, it } from "vitest";
import { ALL_SECRETS, validateGrants, canCreate, canRead, type Principal } from "../src/auth";
import { CRYPTO_VERSION, aad, decodeMasterKey, importMasterKey, open, seal, sha256, bytesToHex } from "../src/crypto";
import { parseAuditTime, parseDurationMs, parseQueryTime } from "../src/duration";
import { decodeFields, ipBucketKey, clientIp } from "../src/http";
import { NAME_RE } from "../src/http";
import { positiveInt, parseBool, ConfigError } from "../src/config";

const hex = (s: string) => Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));

describe("crypto: compatibility with the Go implementation", () => {
  // Produced by Go's crypto/cipher (key 0x00..0x1f, nonce 0xa0..0xab, name
  // "llm.openai"): ciphertext column = 0x01 || Seal(plaintext), AAD = 0x01 || name.
  const KEY_B64 = btoa(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i)));
  const NONCE = hex("a0a1a2a3a4a5a6a7a8a9aaab");
  const GO_CT = hex("019573515920b8769287e53bfee5e65310bcdb632b9e9bb35eabafecbebf2131");
  const VALUE = "sk-test-值-✓";

  it("opens a ciphertext sealed by Go", async () => {
    const key = await importMasterKey(decodeMasterKey(KEY_B64));
    expect(await open(key, "llm.openai", GO_CT, NONCE)).toBe(VALUE);
  });

  it("seals to the exact bytes Go produced", async () => {
    const key = await importMasterKey(decodeMasterKey(KEY_B64));
    const { ciphertext } = await seal(key, "llm.openai", VALUE, NONCE);
    expect(bytesToHex(ciphertext)).toBe(bytesToHex(GO_CT));
  });

  it("binds the secret name: a ciphertext moved to another name does not open", async () => {
    const key = await importMasterKey(decodeMasterKey(KEY_B64));
    await expect(open(key, "llm.other", GO_CT, NONCE)).rejects.toThrow("decrypt");
  });

  it("rejects an unknown version byte and empty ciphertext", async () => {
    const key = await importMasterKey(decodeMasterKey(KEY_B64));
    const bad = GO_CT.slice();
    bad[0] = 0x02;
    await expect(open(key, "llm.openai", bad, NONCE)).rejects.toThrow("version");
    await expect(open(key, "llm.openai", new Uint8Array(0), NONCE)).rejects.toThrow("empty");
  });

  it("detects tampering", async () => {
    const key = await importMasterKey(decodeMasterKey(KEY_B64));
    const bad = GO_CT.slice();
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    await expect(open(key, "llm.openai", bad, NONCE)).rejects.toThrow("decrypt");
  });

  it("hashes tokens like Go's sha256.Sum256", async () => {
    expect(bytesToHex(await sha256("hush_abc"))).toBe(
      "fb2f01fcbfccd92e1f3de069e4bc72457652756b5506b0c31a884c7d3d995c20",
    );
  });

  it("aad is version byte + name", () => {
    expect(Array.from(aad("ab"))).toEqual([CRYPTO_VERSION, 0x61, 0x62]);
  });

  it("master key must be padded base64 of exactly 32 bytes", () => {
    expect(decodeMasterKey(KEY_B64)).toHaveLength(32);
    expect(() => decodeMasterKey("short")).toThrow();
    expect(() => decodeMasterKey(KEY_B64.slice(0, -1))).toThrow(); // unpadded
    expect(() => decodeMasterKey(btoa("x".repeat(31)))).toThrow();
    expect(() => decodeMasterKey(btoa("x".repeat(33)))).toThrow();
  });
});

describe("duration parsing", () => {
  it("accepts Go durations and an integer day suffix", () => {
    expect(parseDurationMs("90d")).toBe(90 * 86_400_000);
    expect(parseDurationMs("12h")).toBe(12 * 3_600_000);
    expect(parseDurationMs("90m")).toBe(90 * 60_000);
    expect(parseDurationMs("1h30m")).toBe(90 * 60_000);
    expect(parseDurationMs("1.5h")).toBe(90 * 60_000);
    expect(parseDurationMs("300ms")).toBe(300);
  });
  it("rejects non-positive and malformed input", () => {
    for (const s of ["", "0", "0d", "-5h", "-5d", "1.5d", "d", "h", "12", "abc", "12x", "1h junk"]) {
      expect(parseDurationMs(s), s).toBeNull();
    }
  });
  it("parseAuditTime takes RFC3339 or an age", () => {
    const now = Date.UTC(2026, 8, 1, 12, 0, 0);
    expect(parseAuditTime("2026-09-01T00:00:00Z", now)).toBe(Date.UTC(2026, 8, 1) / 1000);
    expect(parseAuditTime("24h", now)).toBe((now - 86_400_000) / 1000);
    expect(parseAuditTime("2026-09-01", now)).toBeNull(); // not RFC3339
    expect(parseAuditTime("nope", now)).toBeNull();
  });
  it("parseQueryTime tries integer Unix seconds first", () => {
    expect(parseQueryTime("1700000000", 0)).toBe(1700000000);
    expect(parseQueryTime("7d", 8 * 86_400_000)).toBe(86_400);
  });
});

describe("client IP", () => {
  const req = (h: Record<string, string>) => new Request("https://x/", { headers: h });
  it("uses CF-Connecting-IP and ignores X-Forwarded-For", () => {
    expect(clientIp(req({ "CF-Connecting-IP": "203.0.113.7", "X-Forwarded-For": "6.6.6.6" }))).toBe("203.0.113.7");
    expect(clientIp(req({ "X-Forwarded-For": "6.6.6.6" }))).toBe("unknown");
  });
  it("rejects values that are not IP-shaped", () => {
    expect(clientIp(req({ "CF-Connecting-IP": "1.2.3.4, evil\" injection" }))).toBe("unknown");
  });
  it("groups IPv6 by /64 and leaves IPv4 alone", () => {
    expect(ipBucketKey("203.0.113.7")).toBe("203.0.113.7");
    expect(ipBucketKey("unknown")).toBe("unknown");
    const a = ipBucketKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd");
    expect(a).toBe(ipBucketKey("2001:db8:1:2::1"));
    expect(a).not.toBe(ipBucketKey("2001:db8:1:3::1"));
    expect(ipBucketKey("2001:db8::1")).toBe(ipBucketKey("2001:0db8:0:0:5:6:7:8"));
    expect(ipBucketKey("::1")).toBe("0:0:0:0::/64");
  });
});

describe("strict JSON decoding", () => {
  const spec = { value: "string" } as const;
  it("accepts the known field, case-insensitively like encoding/json", () => {
    expect(decodeFields('{"value":"x"}', spec)).toEqual({ value: "x" });
    expect(decodeFields('{"Value":"x"}', spec)).toEqual({ value: "x" });
  });
  it("rejects unknown fields, wrong types, non-objects and garbage", () => {
    expect(decodeFields('{"value":"x","extra":1}', spec)).toBeNull();
    expect(decodeFields('{"value":1}', spec)).toBeNull();
    expect(decodeFields('["x"]', spec)).toBeNull();
    expect(decodeFields('"x"', spec)).toBeNull();
    expect(decodeFields('{"value":"x"} trailing', spec)).toBeNull();
    expect(decodeFields("", spec)).toBeNull();
  });
  it("treats null as absent and checks array element types", () => {
    expect(decodeFields('{"value":null}', spec)).toEqual({});
    const arr = { prefixes: "strings" } as const;
    expect(decodeFields('{"prefixes":["a.","b."]}', arr)).toEqual({ prefixes: ["a.", "b."] });
    expect(decodeFields('{"prefixes":[1]}', arr)).toBeNull();
    expect(decodeFields('{"prefixes":"a."}', arr)).toBeNull();
  });
});

describe("grants", () => {
  it("validates like the Go version", () => {
    expect(validateGrants("admin", [], [])).toBeNull();
    expect(validateGrants("admin", ["a."], [])).toMatch(/admin tokens do not take/);
    expect(validateGrants("agent", [], [])).toMatch(/at least one/);
    expect(validateGrants("root", [], [])).toMatch(/role must be/);
    expect(validateGrants("agent", ["llm."], [])).toBeNull();
    expect(validateGrants("agent", [ALL_SECRETS], [])).toBeNull();
    expect(validateGrants("agent", [ALL_SECRETS, "a."], [])).toMatch(/must be the only prefix/);
    expect(validateGrants("agent", [], [ALL_SECRETS])).toMatch(/not allowed as a write prefix/);
    expect(validateGrants("agent", ["llm"], [])).toMatch(/invalid prefix/); // no trailing separator
    expect(validateGrants("agent", ["."], [])).toMatch(/invalid prefix/); // nothing before the separator
    expect(validateGrants("agent", ["a.", "a."], [])).toMatch(/duplicate prefix/);
    expect(validateGrants("agent", [], ["w.", "w."])).toMatch(/duplicate write prefix/);
    expect(validateGrants("agent", Array.from({ length: 65 }, (_, i) => `p${i}.`), [])).toMatch(/at most 64/);
  });

  const agent = (over: Partial<Principal>): Principal => ({
    name: "a", role: "agent", prefixes: [], writePrefixes: [], expiresAt: null, ...over,
  });
  it("the trailing separator keeps 'llm.' from matching 'llmx.key'", () => {
    const p = agent({ prefixes: ["llm."] });
    expect(canRead(p, "llm.key")).toBe(true);
    expect(canRead(p, "llmx.key")).toBe(false);
  });
  it("re-validates stored prefixes: a hand-edited empty prefix grants nothing", () => {
    expect(canRead(agent({ prefixes: [""] }), "anything")).toBe(false);
    expect(canCreate(agent({ writePrefixes: [""] }), "anything", NAME_RE)).toBe(false);
    expect(canCreate(agent({ writePrefixes: ["*"] }), "anything", NAME_RE)).toBe(false);
  });
  it("create needs a write prefix and a valid name", () => {
    const p = agent({ writePrefixes: ["crawler."] });
    expect(canCreate(p, "crawler.token", NAME_RE)).toBe(true);
    expect(canCreate(p, "other.token", NAME_RE)).toBe(false);
    expect(canCreate(p, "crawler.bad name", NAME_RE)).toBe(false);
  });
});

describe("config parsing", () => {
  it("positiveInt", () => {
    expect(positiveInt(undefined, "X", 5)).toBe(5);
    expect(positiveInt("", "X", 5)).toBe(5);
    expect(positiveInt("12", "X", 5)).toBe(12);
    for (const v of ["0", "-1", "abc", "1.5"]) expect(() => positiveInt(v, "X", 5), v).toThrow(ConfigError);
  });
  it("parseBool uses Go's literals", () => {
    expect(parseBool(undefined, "X", true)).toBe(true);
    for (const v of ["1", "t", "T", "TRUE", "true", "True"]) expect(parseBool(v, "X", false)).toBe(true);
    for (const v of ["0", "f", "F", "FALSE", "false", "False"]) expect(parseBool(v, "X", true)).toBe(false);
    expect(() => parseBool("yes", "X", true)).toThrow(ConfigError);
  });
});
