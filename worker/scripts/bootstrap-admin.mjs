#!/usr/bin/env node
// Creates the first admin token (the Go version used `token create` against
// the database file; a Worker has no such file). The token is generated
// here, only its SHA-256 goes to D1, and the plaintext is printed once.
//
//   node scripts/bootstrap-admin.mjs --name owner --expires 30d --remote
//   node scripts/bootstrap-admin.mjs --name owner --local        # wrangler dev
//
// After that, manage tokens in the web UI / admin API.

import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";

const MAX_DAYS = 90;
const { values } = parseArgs({
  options: {
    name: { type: "string" },
    expires: { type: "string", default: "30d" },
    local: { type: "boolean", default: false },
    remote: { type: "boolean", default: false },
    binding: { type: "string", default: "DB" },
  },
});

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(2);
}

if (!values.name || !/^[a-zA-Z0-9_.-]{1,64}$/.test(values.name)) fail("--name is required and must match ^[a-zA-Z0-9_.-]{1,64}$");
if (values.local === values.remote) fail("pass exactly one of --local or --remote");
const m = /^(\d+)([dh])$/.exec(values.expires);
if (!m) fail('--expires must look like "30d" or "12h"');
const seconds = Number(m[1]) * (m[2] === "d" ? 86400 : 3600);
if (seconds <= 0) fail("--expires must be positive");
if (seconds > MAX_DAYS * 86400) fail(`admin tokens may live at most ${MAX_DAYS}d`);

const token = "hush_" + randomBytes(32).toString("hex");
const hash = createHash("sha256").update(token).digest("hex");
const now = Math.floor(Date.now() / 1000);
// name and hash are restricted to [A-Za-z0-9_.-] / hex above, so inlining is safe.
const sql =
  `INSERT INTO tokens (name, token_hash, role, prefixes, write_prefixes, expires_at, created_at) ` +
  `VALUES ('${values.name}', X'${hash}', 'admin', '[]', '[]', ${now + seconds}, ${now})`;

try {
  // wrangler's own output goes to stderr so stdout carries only the token.
  execFileSync("npx", ["wrangler", "d1", "execute", values.binding, values.local ? "--local" : "--remote", "--command", sql], {
    stdio: ["ignore", 2, 2],
  });
} catch {
  fail("wrangler could not insert the token (does the name already exist? were migrations applied?)");
}

console.error(`created admin token "${values.name}", expires in ${values.expires}. Store it now; it cannot be shown again:`);
console.log(token);
