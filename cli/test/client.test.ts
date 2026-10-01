import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import { ApiError, Client, normalizeBaseUrl } from "../src/client";
import { startMock, type MockServer } from "./mock-server";

let mock: MockServer;
beforeEach(async () => {
  mock = await startMock();
});
afterEach(() => mock.close());

const client = () => new Client(mock.url, mock.token);

describe("Client", () => {
  it("health works without a token and authCheck needs a valid one", async () => {
    await new Client(mock.url, "").health();
    await client().authCheck();
    await expect(new Client(mock.url, "hush_bad").authCheck()).rejects.toMatchObject({ status: 401 });
  });

  it("put / get / list / delete round-trip, with names URL-encoded and the bearer token sent", async () => {
    const c = client();
    const put = await c.put("llm.openai", "sk-值");
    expect(put.name).toBe("llm.openai");
    expect((await c.get("llm.openai")).value).toBe("sk-值");
    expect((await c.list()).map((s) => s.name)).toEqual(["llm.openai"]);
    await c.delete("llm.openai");
    await c.delete("llm.openai"); // idempotent
    expect(await c.list()).toEqual([]);
  });

  it("maps JSON errors to ApiError with status and message", async () => {
    const e = await client().get("missing").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({ status: 404, message: "server returned 404: not found" });
  });

  it("falls back to the status text for non-JSON error bodies (CDN pages)", async () => {
    mock.override.set("GET /v1/secrets", { status: 502, body: "<html>Bad gateway</html>" });
    await expect(client().list()).rejects.toMatchObject({ status: 502 });
  });

  it("surfaces Retry-After on 429", async () => {
    mock.override.set("GET /v1/secrets", { status: 429, body: '{"error":"rate_limited"}', headers: { "Retry-After": "7" } });
    await expect(client().list()).rejects.toMatchObject({ status: 429, retryAfter: 7 });
  });

  it("rejects invalid names locally, before any request", async () => {
    const c = client();
    for (const bad of ["", "has space", "a/b", "x".repeat(129), "ü"]) {
      await expect(c.get(bad)).rejects.toThrow(/invalid name/);
      await expect(c.put(bad, "v")).rejects.toThrow(/invalid name/);
      await expect(c.delete(bad)).rejects.toThrow(/invalid name/);
    }
    expect(mock.requests).toEqual([]);
  });

  it("never follows a redirect (the token must not leave for another host)", async () => {
    const seen: string[] = [];
    const other = createServer((req, res) => {
      seen.push(String(req.headers.authorization));
      res.end("{}");
    });
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
    const port = (other.address() as import("node:net").AddressInfo).port;
    mock.override.set("GET /v1/secrets", { status: 302, headers: { Location: `http://127.0.0.1:${port}/steal` } });
    await expect(client().list()).rejects.toMatchObject({ status: 302 });
    expect(seen).toEqual([]);
    await new Promise((r) => other.close(r));
  });

  it("times out instead of hanging", async () => {
    mock.override.set("GET /v1/secrets", { status: 200, hang: true });
    const slow = new Client(mock.url, mock.token, fetch, 150);
    await expect(slow.list()).rejects.toMatchObject({ name: "TimeoutError" });
  });
});

describe("normalizeBaseUrl", () => {
  it("accepts https anywhere and http only for loopback, trimming trailing slashes", () => {
    expect(normalizeBaseUrl("https://secrets.example.com/")).toBe("https://secrets.example.com");
    expect(normalizeBaseUrl("https://x.workers.dev///")).toBe("https://x.workers.dev");
    for (const ok of ["http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"]) {
      expect(() => normalizeBaseUrl(ok), ok).not.toThrow();
    }
  });

  it("refuses to send a token over http to a remote host, and rejects garbage", () => {
    expect(() => normalizeBaseUrl("http://secrets.example.com")).toThrow(/only sent over https/);
    expect(() => normalizeBaseUrl("http://127.0.0.1.evil.example")).toThrow(/only sent over https/);
    expect(() => normalizeBaseUrl("ftp://x")).toThrow(/only sent over https/);
    expect(() => normalizeBaseUrl("not a url")).toThrow(/invalid URL/);
    expect(() => normalizeBaseUrl("")).toThrow(/invalid URL/);
  });
});
