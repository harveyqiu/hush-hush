-- Token buckets for rate limiting (src/ratelimit.ts). Replaces the Durable
-- Object the first Workers build used. Times are Unix milliseconds. Rows are
-- disposable: a bucket idle for a minute is full again, and the daily Cron
-- deletes those.

CREATE TABLE rate_limits (
  key     TEXT PRIMARY KEY,
  tokens  REAL    NOT NULL,
  last_ms INTEGER NOT NULL,
  -- 1 if the latest call consumed a token; read back through RETURNING so
  -- the whole decision is one atomic statement.
  allowed INTEGER NOT NULL
);
CREATE INDEX rate_limits_last ON rate_limits (last_ms);
