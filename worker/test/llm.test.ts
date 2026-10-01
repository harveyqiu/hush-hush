import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/config";
import { DEFAULT_RATE_LIMIT_PER_MINUTE, DEFAULT_UNAUTH_RATE_LIMIT_PER_MINUTE } from "../src/config";
import { MAX_VALUE_BYTES, NAME_RE } from "../src/http";
import { AGENT_ENDPOINTS, LLM_CSS, LLM_CSS_SHA256, STATUS_GUIDE, escapeText, renderLlmPage } from "../src/llm";
import { LIST_LIMIT } from "../src/secrets";
import { auditRows, call, env, makeToken, resetAll } from "./helpers";

beforeEach(resetAll);

const page = async (init?: Parameters<typeof call>[1]) => (await call("/llm.html", init)).text();

describe("GET /llm.html", () => {
  it("is public HTML: no token, not audited, not rate limited", async () => {
    const res = await call("/llm.html");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("X-Request-ID")).toBeTruthy();
    expect(await auditRows()).toHaveLength(0);
    // hammering it spends nobody's budget
    for (let i = 0; i < 15; i++) expect((await call("/llm.html", { env: { UNAUTH_RATE_LIMIT_PER_MINUTE: "1" } })).status).toBe(200);
  });

  it("works when the rest of the server is misconfigured or the admin API is off", async () => {
    expect((await call("/llm.html", { env: { MASTER_KEY: "" } })).status).toBe(200);
    expect((await call("/llm.html", { env: { ADMIN_API: "false" } })).status).toBe(200);
  });

  it("puts the real base URL in the HTML itself, for agents that don't run JavaScript", async () => {
    const html = await (async () => {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request("https://secrets.example.org/llm.html"), env as Env, ctx);
      await waitOnExecutionContext(ctx);
      return res.text();
    })();
    expect(html).toContain("https://secrets.example.org/v1/secrets/llm.openai");
    expect(html).toContain('BASE = "https://secrets.example.org"');
    expect(html).not.toMatch(/<your-|example\.com|\{origin\}|undefined/);
    expect(html).not.toContain("https://hush.test");
    expect(html).not.toContain("<script");
  });

  it("answers HEAD without a body and refuses other methods", async () => {
    const head = await call("/llm.html", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    const post = await call("/llm.html", { method: "POST" });
    expect(post.status).toBe(405);
    expect(post.headers.get("Allow")).toBe("GET, HEAD");
  });

  it("has a strict CSP that allows only its own stylesheet, and the hash is the stylesheet's", async () => {
    const res = await call("/llm.html");
    const csp = res.headers.get("Content-Security-Policy")!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|script-src/);
    expect(csp).toContain(`style-src 'sha256-${LLM_CSS_SHA256}'`);
    expect(csp).toContain("frame-ancestors 'none'");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(LLM_CSS)));
    expect(btoa(String.fromCharCode(...digest))).toBe(LLM_CSS_SHA256);
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
  });

  it("the inline <style> in the page is exactly the hashed stylesheet", async () => {
    const m = /<style>([\s\S]*?)<\/style>/.exec(await page());
    expect(m?.[1]).toBe(LLM_CSS);
  });
});

describe("what the page says matches what the API does", () => {
  it("states the real limits and patterns, not copies that could drift", async () => {
    const html = await page();
    expect(html).toContain(NAME_RE.source);
    expect(html).toContain(String(MAX_VALUE_BYTES));
    expect(html).toContain(`at most ${LIST_LIMIT}`);
    expect(html).toContain(`${DEFAULT_RATE_LIMIT_PER_MINUTE} requests per minute per token`);
    expect(html).toContain(`${DEFAULT_UNAUTH_RATE_LIMIT_PER_MINUTE} failed authentications per minute`);
  });

  it("documents every endpoint an agent can use, and only those", async () => {
    const html = await page();
    for (const e of AGENT_ENDPOINTS) expect(html).toContain(e.path);
    expect(html).not.toMatch(/<code>DELETE<\/code><\/td>/); // not offered to agents
    expect(html).toContain("DELETE</code> and everything under <code>/v1/admin/");
  });

  it("the documented status behavior is what the server really does", async () => {
    const ro = await makeToken({ name: "reader", prefixes: ["llm."] });
    const rw = await makeToken({ name: "writer", writePrefixes: ["crawler."] });
    const admin = await makeToken({ name: "root", role: "admin" });
    await call("/v1/secrets/llm.openai", { method: "PUT", token: admin, body: { value: "v" } });
    const status = async (path: string, init: Parameters<typeof call>[1] = {}) => (await call(path, init)).status;

    const observed: Record<string, number> = {
      "200": await status("/v1/secrets/llm.openai", { token: ro }),
      "400": await status("/v1/secrets/bad%20name", { token: ro }),
      "401": await status("/v1/secrets", { token: "hush_wrong", env: { UNAUTH_RATE_LIMIT_PER_MINUTE: "1000" } }),
      "403": await status("/v1/secrets/other.name", { token: ro }),
      "404": await status("/v1/secrets/llm.missing", { token: ro }),
      "405": await status("/v1/secrets", { method: "POST", token: ro }),
      "413": await status("/v1/secrets/crawler.big", { method: "PUT", token: rw, body: { value: "x".repeat(MAX_VALUE_BYTES + 1) } }),
      "415": await status("/v1/secrets/crawler.t", { method: "PUT", token: rw, body: "x", headers: { "Content-Type": "text/plain" } }),
    };
    await call("/v1/secrets/crawler.once", { method: "PUT", token: rw, body: { value: "1" } });
    observed["409"] = await status("/v1/secrets/crawler.once", { method: "PUT", token: rw, body: { value: "2" } });
    // its own token: a drained bucket would otherwise leak into the checks below
    const limited = await makeToken({ name: "limited", prefixes: ["llm."] });
    await call("/v1/secrets", { token: limited, env: { RATE_LIMIT_PER_MINUTE: "1" } });
    observed["429"] = await status("/v1/secrets", { token: limited, env: { RATE_LIMIT_PER_MINUTE: "1" } });
    observed["500"] = await status("/v1/secrets", { token: ro, env: { MASTER_KEY: "bad" } });

    for (const g of STATUS_GUIDE) expect(observed[g.status], `status ${g.status}`).toBe(Number(g.status));
    expect(Object.keys(observed).sort()).toEqual(STATUS_GUIDE.map((g) => g.status).sort());

    // agents really can't delete or use admin routes, as the page says
    expect(await status("/v1/secrets/llm.openai", { method: "DELETE", token: ro })).toBe(403);
    expect(await status("/v1/admin/tokens", { token: ro })).toBe(403);
    // the prefix example: llm. covers llm.openai but not llmx.key or llm
    await call("/v1/secrets/llmx.key", { method: "PUT", token: admin, body: { value: "v" } });
    expect(await status("/v1/secrets/llmx.key", { token: ro })).toBe(403);
    expect(await status("/v1/secrets/llm", { token: ro })).toBe(403);
  });

  it("the machine-readable manifest parses and agrees with the page", async () => {
    const html = await page();
    const m = /<pre id="manifest-json"><code>([\s\S]*?)<\/code><\/pre>/.exec(html);
    const manifest = JSON.parse(m![1]!.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
    expect(manifest.base_url).toBe("https://hush.test");
    expect(manifest.auth).toMatchObject({ type: "bearer", header: "Authorization", token_env: "HUSH_TOKEN" });
    expect(manifest.max_value_bytes).toBe(MAX_VALUE_BYTES);
    expect(manifest.name_pattern).toBe(NAME_RE.source);
    expect(manifest.endpoints.map((e: { method: string; path: string }) => `${e.method} ${e.path}`)).toEqual(
      AGENT_ENDPOINTS.map((e) => `${e.method} ${e.path}`),
    );
    for (const e of manifest.endpoints) expect(e.url).toBe("https://hush.test" + e.path);
  });

  it("the example in the page works against the API: the documented curl round trip", async () => {
    const admin = await makeToken({ name: "root", role: "admin" });
    await call("/v1/secrets/llm.openai", { method: "PUT", token: admin, body: { value: "sk-from-the-page-test" } });
    const tok = await makeToken({ name: "agent", prefixes: ["llm."] });
    const shapes = await (await call("/v1/secrets/llm.openai", { token: tok })).json();
    expect(Object.keys(shapes as object).sort()).toEqual(["created_at", "name", "updated_at", "value"]);
    const list = (await (await call("/v1/secrets", { token: tok })).json()) as { secrets: Record<string, unknown>[] };
    expect(Object.keys(list.secrets[0]!).sort()).toEqual(["created_at", "name", "updated_at"]);
  });
});

describe("safety of the rendering", () => {
  it("escapes text so a hostile origin can't inject markup", () => {
    const html = renderLlmPage('https://x"><script>alert(1)</script>');
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(escapeText(`<a href="x">&</a>`)).toBe(`&lt;a href="x"&gt;&amp;&lt;/a&gt;`);
  });

  it("keeps quotes readable in the raw source (that is what a fetching agent sees)", async () => {
    const html = await page();
    expect(html).toContain('-H "Authorization: Bearer $HUSH_TOKEN"');
    expect(html).not.toContain("&quot;");
  });

  it("tells agents the safe-handling rules", async () => {
    const html = await page();
    for (const rule of ["Never print, log or repeat a value", "Never put a secret in a URL", "Stay inside your grant", "only over https", "hh2:"]) {
      expect(html, rule).toContain(rule);
    }
  });
});
