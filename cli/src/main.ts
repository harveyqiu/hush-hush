import {
  USAGE,
  UsageError,
  cmdDelete,
  cmdGet,
  cmdHealth,
  cmdInit,
  cmdList,
  cmdLogin,
  cmdMigrate,
  cmdPut,
  type Deps,
} from "./commands";

declare const __HUSH_VERSION__: string | undefined;
export const VERSION = typeof __HUSH_VERSION__ === "string" ? __HUSH_VERSION__ : "dev";

/** Runs one invocation and returns the process exit code: 0 ok, 1 error, 2 usage. */
export async function run(argv: string[], d: Deps): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === undefined) {
    d.stderr.write(USAGE);
    return 2;
  }
  try {
    switch (cmd) {
      case "login":
        await cmdLogin(rest, d);
        break;
      case "health":
        await cmdHealth(rest, d);
        break;
      case "get":
        await cmdGet(rest, d);
        break;
      case "put":
        await cmdPut(rest, d);
        break;
      case "delete":
        await cmdDelete(rest, d);
        break;
      case "list":
        await cmdList(rest, d);
        break;
      case "init":
        await cmdInit(rest, d);
        break;
      case "migrate":
        await cmdMigrate(rest, d);
        break;
      case "help":
      case "-h":
      case "--help":
        d.stdout.write(USAGE);
        break;
      case "version":
      case "--version":
        d.stdout.write(`hush ${VERSION}\n`);
        break;
      default:
        throw new UsageError(`unknown command: ${cmd}`);
    }
    return 0;
  } catch (e) {
    if (e instanceof UsageError) {
      d.stderr.write(`${e.message}\n\n${USAGE}`);
      return 2;
    }
    d.stderr.write(`error: ${(e as Error).message}\n`);
    return 1;
  }
}
