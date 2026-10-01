// A minimal in-memory hush-hush server that follows the real API contract
// (docs/functional-spec.md section 9): bearer auth, name rules, strict PUT
// body, 404/204 semantics. Counts requests so tests can assert "no network".

import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface MockServer {
  url: string;
  token: string;
  store: Map<string, { value: string; created: number; updated: number }>;
  /** Every request received, "METHOD /path". */
  requests: string[];
  /** Force a response for requests matching "METHOD /path". */
  override: Map<string, { status: number; body?: string; headers?: Record<string, string>; hang?: boolean }>;
  close(): Promise<void>;
}

const NAME_RE = /^[a-zA-Z0-9_.-]{1,128}$/;

async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export async function startMock(token = "hush_" + "0".repeat(64)): Promise<MockServer> {
  const m: Omit<MockServer, "url" | "close"> = { token, store: new Map(), requests: [], override: new Map() };
  const send = (res: import("node:http").ServerResponse, status: number, json?: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "Content-Type": "application/json", ...headers });
    res.end(json === undefined ? undefined : JSON.stringify(json) + "\n");
  };

  const server: Server = createServer(async (req, res) => {
    const key = `${req.method} ${req.url}`;
    m.requests.push(key);
    const forced = m.override.get(key);
    if (forced) {
      if (forced.hang) return; // never answer
      res.writeHead(forced.status, { "Content-Type": "application/json", ...forced.headers });
      res.end(forced.body);
      return;
    }
    if (req.url === "/healthz") return send(res, 200, { status: "ok" });
    if (req.headers.authorization !== `Bearer ${m.token}`) return send(res, 401, { error: "unauthorized" });

    if (req.url === "/v1/secrets" && req.method === "GET") {
      const secrets = [...m.store].sort(([a], [b]) => (a < b ? -1 : 1)).map(([name, v]) => ({ name, created_at: v.created, updated_at: v.updated }));
      return send(res, 200, { secrets });
    }
    const match = /^\/v1\/secrets\/([^/]+)$/.exec(req.url ?? "");
    if (!match) return send(res, 404, { error: "not found" });
    const name = decodeURIComponent(match[1]!);
    if (!NAME_RE.test(name)) return send(res, 400, { error: "invalid name" });

    if (req.method === "GET") {
      const v = m.store.get(name);
      if (!v) return send(res, 404, { error: "not found" });
      return send(res, 200, { name, value: v.value, created_at: v.created, updated_at: v.updated });
    }
    if (req.method === "PUT") {
      if (!String(req.headers["content-type"]).startsWith("application/json")) return send(res, 415, { error: "content-type must be application/json" });
      let parsed: unknown;
      try {
        parsed = JSON.parse(await body(req));
      } catch {
        return send(res, 400, { error: "invalid json" });
      }
      const value = (parsed as { value?: unknown }).value;
      if (typeof value !== "string" || Object.keys(parsed as object).length !== 1) return send(res, 400, { error: "invalid json" });
      if (value === "") return send(res, 400, { error: "value required" });
      const now = Math.floor(Date.now() / 1000);
      const prev = m.store.get(name);
      m.store.set(name, { value, created: prev?.created ?? now, updated: now });
      return send(res, 200, { name, created_at: prev?.created ?? now, updated_at: now });
    }
    if (req.method === "DELETE") {
      m.store.delete(name);
      res.writeHead(204);
      return res.end();
    }
    return send(res, 405, { error: "method not allowed" });
  });

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return {
    ...m,
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}
