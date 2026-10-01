// Entry point of the `hush` binary.

import { configDir } from "./config";
import { run } from "./main";
import { promptNoEcho } from "./value";

process.exitCode = await run(process.argv.slice(2), {
  stdout: process.stdout,
  stderr: process.stderr,
  stdin: process.stdin,
  env: process.env,
  configDir: configDir(),
  prompt: (label) => promptNoEcho(label),
});
