// Thin client for the hush-hush HTTP API.

/** Mirrors the server's name rule; checking here fails fast with a clear error. */
export const NAME_RE = /^[a-zA-Z0-9_.-]{1,128}$/;
const DEFAULT_TIMEOUT_MS = 30_000;

export interface Secret {
  name: string;
  value?: string;
  created_at: number;
  updated_at: number;
}

/** The server's JSON error, keeping the HTTP status so callers can switch on it. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(`server returned ${status}: ${message}`);
  }
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * Normalizes the base URL and refuses to send a bearer token over plain http
 * to anything but the local machine.
 */
export function normalizeBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`invalid URL ${JSON.stringify(raw)}`);
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && LOOPBACK.has(u.hostname))) {
    throw new Error(`refusing to use ${u.protocol}//${u.host}: tokens are only sent over https (http is allowed for localhost)`);
  }
  return raw.replace(/\/+$/, "");
}

export type FetchFn = typeof fetch;

export class Client {
  readonly baseUrl: string;

  constructor(
    baseUrl: string,
    private readonly token: string,
    private readonly fetchFn: FetchFn = fetch,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
  }

  private async request(method: string, path: string, auth: boolean, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth) headers["Authorization"] = `Bearer ${this.token}`;
    return this.fetchFn(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // Never follow a redirect with the token attached.
      redirect: "manual",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  /** Turns a non-2xx response into an ApiError, falling back to the status text for non-JSON bodies (CDN error pages). */
  private async fail(res: Response): Promise<never> {
    let message = "";
    try {
      const text = (await res.text()).slice(0, 4096);
      const parsed = JSON.parse(text) as { error?: unknown };
      if (typeof parsed.error === "string") message = parsed.error;
    } catch {
      // not JSON
    }
    if (message === "") message = res.statusText || `HTTP ${res.status}`;
    const ra = Number(res.headers.get("Retry-After"));
    throw new ApiError(res.status, message, Number.isFinite(ra) && ra > 0 ? ra : undefined);
  }

  private async json<T>(res: Response, ok: number): Promise<T> {
    if (res.status !== ok) return this.fail(res);
    return (await res.json()) as T;
  }

  /** Probes the unauthenticated /healthz. */
  async health(): Promise<void> {
    const res = await this.request("GET", "/healthz", false);
    if (res.status !== 200) await this.fail(res);
    await res.arrayBuffer();
  }

  /** Verifies the token is accepted by hitting an authenticated endpoint. */
  async authCheck(): Promise<void> {
    await this.list();
  }

  async list(): Promise<Secret[]> {
    const res = await this.request("GET", "/v1/secrets", true);
    const body = await this.json<{ secrets?: Secret[] }>(res, 200);
    return body.secrets ?? [];
  }

  private checkName(name: string): void {
    if (!NAME_RE.test(name)) throw new Error(`invalid name ${JSON.stringify(name)}: use letters, digits, '.', '_' and '-' (1-128 characters)`);
  }

  async get(name: string): Promise<Secret> {
    this.checkName(name);
    const res = await this.request("GET", `/v1/secrets/${encodeURIComponent(name)}`, true);
    return this.json<Secret>(res, 200);
  }

  async put(name: string, value: string): Promise<{ name: string; created_at: number; updated_at: number }> {
    this.checkName(name);
    const res = await this.request("PUT", `/v1/secrets/${encodeURIComponent(name)}`, true, { value });
    return this.json(res, 200);
  }

  async delete(name: string): Promise<void> {
    this.checkName(name);
    const res = await this.request("DELETE", `/v1/secrets/${encodeURIComponent(name)}`, true);
    if (res.status !== 204) await this.fail(res);
  }
}
