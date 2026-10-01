-- Final schema of the Go version (its migrations 1-5 folded together), so a
-- database dumped from the Go build can be imported as-is. Times are Unix
-- seconds. See docs/functional-spec.md section 2.

CREATE TABLE secrets (
  name       TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  nonce      BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Only the SHA-256 of a token is stored. prefixes / write_prefixes are JSON
-- arrays of strings (agent tokens only).
CREATE TABLE tokens (
  id             INTEGER PRIMARY KEY,
  name           TEXT    NOT NULL UNIQUE,
  token_hash     BLOB    NOT NULL UNIQUE,
  role           TEXT    NOT NULL CHECK (role IN ('admin', 'agent')),
  prefixes       TEXT    NOT NULL DEFAULT '[]',
  revoked_at     INTEGER,
  expires_at     INTEGER,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER,
  write_prefixes TEXT    NOT NULL DEFAULT '[]'
);

-- One row per /v1/secrets or /v1/admin request. Never holds values or tokens.
CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  token_name  TEXT    NOT NULL DEFAULT '',
  action      TEXT    NOT NULL,
  secret_name TEXT    NOT NULL DEFAULT '',
  result      TEXT    NOT NULL,
  request_id  TEXT    NOT NULL DEFAULT '',
  remote_addr TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts     ON audit_log (ts);
CREATE INDEX audit_log_token  ON audit_log (token_name, ts);
CREATE INDEX audit_log_secret ON audit_log (secret_name, ts);
