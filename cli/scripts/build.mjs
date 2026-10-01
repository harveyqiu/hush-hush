// Bundles the CLI into one self-contained file: dist/hush.mjs. No node_modules
// needed to run it, only Node 20+.

import { build } from "esbuild";
import { chmod, readFile } from "node:fs/promises";

const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/hush.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  minify: false,
  banner: { js: "#!/usr/bin/env node" },
  define: { __HUSH_VERSION__: JSON.stringify(pkg.version) },
  legalComments: "none",
});
await chmod("dist/hush.mjs", 0o755);
console.log("built dist/hush.mjs");
