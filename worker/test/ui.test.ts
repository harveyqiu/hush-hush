import { beforeEach, describe, expect, it } from "vitest";
import { call, resetAll } from "./helpers";

beforeEach(resetAll);

describe("web UI", () => {
  it("redirects / to /ui/", async () => {
    const res = await call("/");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/ui/");
    expect((await call("/ui")).headers.get("Location")).toBe("/ui/");
  });

  it("serves the static files with the strict security headers", async () => {
    for (const [path, type] of [["/ui/", "text/html"], ["/ui/app.js", "javascript"], ["/ui/style.css", "text/css"]] as const) {
      const res = await call(path);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("Content-Type"), path).toContain(type);
      expect(res.headers.get("Content-Security-Policy"), path).toBe(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      );
      expect(res.headers.get("X-Frame-Options")).toBe("DENY");
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(res.headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("X-Request-ID")).toBeTruthy();
    }
  });

  it("the page is the admin UI", async () => {
    expect(await (await call("/ui/")).text()).toContain("hush-hush");
  });

  it("does not serve anything else and only answers GET", async () => {
    expect((await call("/ui/missing.txt")).status).toBe(404);
    expect((await call("/ui/", { method: "POST" })).status).toBe(405);
  });
});
