// Where a secret value comes from: an argument, a file, stdin, or a hidden prompt.

import { readFile } from "node:fs/promises";

export const NO_VALUE_SOURCE =
  "no value source: pass a positional arg, --from-file PATH, --from-stdin, or run from a terminal";
export const MULTIPLE_VALUE_SOURCES = "at most one of value-arg / --from-file / --from-stdin may be specified";

/**
 * Strips ONE trailing newline (CRLF, LF or CR) and nothing more, so an editor's
 * automatic final newline doesn't become part of the secret, while newlines
 * that are part of the value are kept.
 */
export function trimOneTrailingNewline(s: string): string {
  if (s.endsWith("\r\n")) return s.slice(0, -2);
  if (s.endsWith("\n") || s.endsWith("\r")) return s.slice(0, -1);
  return s;
}

export interface ValueSource {
  arg: string;
  fromFile: string;
  fromStdin: boolean;
  readStdin: () => Promise<string>;
  prompt: (label: string) => Promise<string>;
  isTty: boolean;
}

export async function resolveValue(src: ValueSource): Promise<string> {
  const count = Number(src.arg !== "") + Number(src.fromFile !== "") + Number(src.fromStdin);
  if (count > 1) throw new Error(MULTIPLE_VALUE_SOURCES);
  if (src.arg !== "") return src.arg;
  if (src.fromFile !== "") {
    try {
      return trimOneTrailingNewline(await readFile(src.fromFile, "utf8"));
    } catch (e) {
      throw new Error(`read ${src.fromFile}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
    }
  }
  if (src.fromStdin) return trimOneTrailingNewline(await src.readStdin());
  if (src.isTty) return src.prompt("value: ");
  throw new Error(NO_VALUE_SOURCE);
}

export async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(typeof c === "string" ? Buffer.from(c) : (c as Buffer));
  return Buffer.concat(chunks).toString("utf8");
}

interface TtyInput extends NodeJS.ReadableStream {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  setEncoding(encoding: BufferEncoding): this;
}

/**
 * Reads a line from the terminal without echoing it. Handles paste (many
 * characters per chunk), Backspace, Enter, Ctrl-C (rejects "interrupted") and
 * Ctrl-D, and ignores arrow-key escape sequences. Rejects when there is no
 * terminal rather than hanging.
 */
export function promptNoEcho(
  label: string,
  input: TtyInput = process.stdin as unknown as TtyInput,
  output: { write: (s: string) => unknown } = process.stderr,
): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!input.isTTY || typeof input.setRawMode !== "function") {
      reject(new Error("no terminal available to read a hidden value"));
      return;
    }
    output.write(label);
    const chars: string[] = [];
    let escape = 0; // characters still to skip from an escape sequence
    input.setEncoding("utf8");
    input.setRawMode(true);
    input.resume();

    const finish = (err: Error | null) => {
      input.removeListener("data", onData);
      input.setRawMode?.(false);
      input.pause();
      output.write("\n");
      if (err) reject(err);
      else resolve(chars.join(""));
    };
    const onData = (chunk: string | Buffer) => {
      for (const ch of String(chunk)) {
        if (escape > 0) {
          escape--;
          continue;
        }
        if (ch === "\u001b") {
          escape = 2; // ESC [ X: drop the rest of a typical arrow-key sequence
          continue;
        }
        if (ch === "\r" || ch === "\n") return finish(null);
        if (ch === "\u0003") return finish(new Error("interrupted"));
        if (ch === "\u0004") return finish(chars.length === 0 ? new Error("unexpected end of input") : null);
        if (ch === "\u007f" || ch === "\b") {
          chars.pop();
          continue;
        }
        if (ch >= " ") chars.push(ch);
      }
    };
    input.on("data", onData);
  });
}
