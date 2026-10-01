import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The production-parameter Argon2id check allocates 64 MiB and takes a few seconds.
    testTimeout: 30_000,
  },
});
