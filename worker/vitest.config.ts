import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Throwaway test key: the 32 bytes 0x00..0x1f, built at runtime rather than
// written down as a literal (secret scanners flag high-entropy strings). The
// same key produced the Go ciphertext vector in test/units.test.ts.
const TEST_MASTER_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("base64");

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: { MASTER_KEY: TEST_MASTER_KEY, TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: { include: ["test/**/*.test.ts"], silent: "passed-only" as const },
  };
});
