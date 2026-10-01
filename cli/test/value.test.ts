import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { MULTIPLE_VALUE_SOURCES, NO_VALUE_SOURCE, promptNoEcho, resolveValue, trimOneTrailingNewline, type ValueSource } from "../src/value";

describe("trimOneTrailingNewline", () => {
  it("strips exactly one trailing newline", () => {
    expect(trimOneTrailingNewline("v\n")).toBe("v");
    expect(trimOneTrailingNewline("v\r\n")).toBe("v");
    expect(trimOneTrailingNewline("v\r")).toBe("v");
    expect(trimOneTrailingNewline("v\n\n")).toBe("v\n"); // the intentional one stays
    expect(trimOneTrailingNewline("a\nb")).toBe("a\nb");
    expect(trimOneTrailingNewline("  v  ")).toBe("  v  ");
    expect(trimOneTrailingNewline("")).toBe("");
  });
});

describe("resolveValue", () => {
  const base: ValueSource = {
    arg: "",
    fromFile: "",
    fromStdin: false,
    readStdin: async () => "from-stdin\n",
    prompt: async () => "typed",
    isTty: false,
  };

  it("takes the argument, stdin, a file, or the prompt", async () => {
    expect(await resolveValue({ ...base, arg: "a" })).toBe("a");
    expect(await resolveValue({ ...base, fromStdin: true })).toBe("from-stdin");
    expect(await resolveValue({ ...base, isTty: true })).toBe("typed");
    const dir = await mkdtemp(join(tmpdir(), "hush-val-"));
    try {
      const f = join(dir, "v.txt");
      await writeFile(f, "from-file\n\n");
      expect(await resolveValue({ ...base, fromFile: f })).toBe("from-file\n");
    } finally {
      await rm(dir, { recursive: true });
    }
  });

  it("refuses more than one source instead of picking silently", async () => {
    await expect(resolveValue({ ...base, arg: "a", fromStdin: true })).rejects.toThrow(MULTIPLE_VALUE_SOURCES);
    await expect(resolveValue({ ...base, arg: "a", fromFile: "/x" })).rejects.toThrow(MULTIPLE_VALUE_SOURCES);
  });

  it("without a source and without a terminal it errors instead of hanging", async () => {
    await expect(resolveValue(base)).rejects.toThrow(NO_VALUE_SOURCE);
  });

  it("reports a missing file by name", async () => {
    await expect(resolveValue({ ...base, fromFile: "/nonexistent/hush-file" })).rejects.toThrow(/read \/nonexistent\/hush-file: ENOENT/);
  });
});

describe("promptNoEcho", () => {
  function fakeTty() {
    const input = Object.assign(new PassThrough(), { isTTY: true, raw: [] as boolean[], setRawMode(m: boolean) { this.raw.push(m); return this; } });
    const written: string[] = [];
    return { input, output: { write: (s: string) => written.push(s) }, written };
  }
  const type = (t: ReturnType<typeof fakeTty>, ...chunks: string[]) => chunks.forEach((c) => t.input.write(c));

  it("returns what was typed, never echoes it, and restores the terminal", async () => {
    const t = fakeTty();
    const p = promptNoEcho("pw: ", t.input, t.output);
    type(t, "hunter2\r");
    expect(await p).toBe("hunter2");
    expect(t.written.join("")).toBe("pw: \n"); // only the label and the final newline
    expect(t.input.raw).toEqual([true, false]);
  });

  it("handles paste, Backspace, multibyte characters and Enter as LF", async () => {
    const t = fakeTty();
    const p = promptNoEcho("", t.input, t.output);
    type(t, "pässw", "\u007f", "ö✓", "\u007f\u007f", "rd\n");
    expect(await p).toBe("pässrd");
  });

  it("ignores arrow-key escape sequences", async () => {
    const t = fakeTty();
    const p = promptNoEcho("", t.input, t.output);
    type(t, "ab", "\u001b[A", "\u001b[D", "c\r");
    expect(await p).toBe("abc");
  });

  it("Ctrl-C rejects with 'interrupted' and still restores the terminal", async () => {
    const t = fakeTty();
    const p = promptNoEcho("", t.input, t.output);
    type(t, "abc", "\u0003");
    await expect(p).rejects.toThrow("interrupted");
    expect(t.input.raw).toEqual([true, false]);
  });

  it("Ctrl-D on an empty line is end of input; after typing it submits", async () => {
    const a = fakeTty();
    const pa = promptNoEcho("", a.input, a.output);
    type(a, "\u0004");
    await expect(pa).rejects.toThrow(/end of input/);
    const b = fakeTty();
    const pb = promptNoEcho("", b.input, b.output);
    type(b, "xy\u0004");
    expect(await pb).toBe("xy");
  });

  it("rejects when there is no terminal", async () => {
    const input = Object.assign(new PassThrough(), { isTTY: false });
    await expect(promptNoEcho("", input as never, { write: () => {} })).rejects.toThrow(/no terminal/);
  });
});
