// AES-256-GCM at rest, SHA-256 token hashing, constant-time compare.
// The byte layout is identical to the Go version so databases are
// interchangeable: ciphertext column = 0x01 || Seal(plaintext), nonce column
// = 12 random bytes, AAD = 0x01 || name.

export const CRYPTO_VERSION = 0x01;
const NONCE_BYTES = 12;
const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Binds the secret name AND the ciphertext version into the AEAD tag. Name
 * binding prevents moving ciphertext between names; version binding prevents
 * algorithm downgrade if a future version is introduced.
 */
export function aad(name: string): Uint8Array {
  const n = enc.encode(name);
  const out = new Uint8Array(1 + n.length);
  out[0] = CRYPTO_VERSION;
  out.set(n, 1);
  return out;
}

/** Standard padded base64 that decodes to exactly 32 bytes. */
export function decodeMasterKey(s: string): Uint8Array {
  const t = s.trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(t)) throw new Error("MASTER_KEY must be standard base64 that decodes to 32 bytes");
  const bin = atob(t);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export interface Sealed {
  /** version byte || sealed payload (ciphertext || 16-byte tag) */
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export async function seal(key: CryptoKey, name: string, plaintext: string, nonce?: Uint8Array): Promise<Sealed> {
  const iv = nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(name) }, key, enc.encode(plaintext)),
  );
  const ciphertext = new Uint8Array(1 + sealed.length);
  ciphertext[0] = CRYPTO_VERSION;
  ciphertext.set(sealed, 1);
  return { ciphertext, nonce: iv };
}

export type OpenError = "empty" | "version" | "decrypt";

/** Throws an Error whose message is one of OpenError. */
export async function open(key: CryptoKey, name: string, ciphertext: Uint8Array, nonce: Uint8Array): Promise<string> {
  if (ciphertext.length < 1) throw new Error("empty" satisfies OpenError);
  if (ciphertext[0] !== CRYPTO_VERSION) throw new Error("version" satisfies OpenError);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad(name) },
      key,
      ciphertext.subarray(1),
    );
    return dec.decode(pt);
  } catch {
    throw new Error("decrypt" satisfies OpenError);
  }
}

export async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: (a: BufferSource, b: BufferSource) => boolean };
  if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(a, b);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
