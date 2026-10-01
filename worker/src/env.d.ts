import type { Env as HushEnv } from "./config";

declare global {
  namespace Cloudflare {
    interface Env extends HushEnv {}
  }
}
export {};
