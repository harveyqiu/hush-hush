// Parsing of "expires" and "since / until" values. Accepts Go durations
// (12h, 90m, 1h30m) plus an integer day suffix (90d), which Go lacks.

const UNIT_MS: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  "µs": 1e-3,
  "μs": 1e-3,
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
};
const GO_DURATION_RE = /^\+?(?:(?:\d+\.?\d*|\.\d+)(?:ns|us|µs|μs|ms|s|m|h))+$/;
const DAY_MS = 86_400_000;

/** Milliseconds, or null when the text is not a positive duration. */
export function parseDurationMs(s: string): number | null {
  let ms: number;
  if (s.endsWith("d")) {
    const n = s.slice(0, -1);
    if (!/^\+?\d+$/.test(n)) return null;
    ms = Number(n) * DAY_MS;
  } else {
    if (!GO_DURATION_RE.test(s)) return null;
    ms = 0;
    for (const m of s.matchAll(/(\d+\.?\d*|\.\d+)(ns|us|µs|μs|ms|s|m|h)/g)) {
      ms += Number(m[1]) * UNIT_MS[m[2]!]!;
    }
  }
  return Number.isFinite(ms) && ms > 0 ? ms : null;
}

const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/** Unix seconds for an RFC3339 timestamp or a "that long ago" duration. */
export function parseAuditTime(s: string, nowMs: number): number | null {
  if (RFC3339_RE.test(s)) {
    const t = Date.parse(s);
    if (!Number.isNaN(t)) return Math.floor(t / 1000);
  }
  const d = parseDurationMs(s);
  return d === null ? null : Math.floor((nowMs - d) / 1000);
}

/** since/until query value: integer Unix seconds first, then the above. */
export function parseQueryTime(v: string, nowMs: number): number | null {
  if (/^[+-]?\d+$/.test(v)) return Number(v);
  return parseAuditTime(v, nowMs);
}
