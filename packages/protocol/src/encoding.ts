import { createHash, randomBytes } from "node:crypto";

export const utf8 = {
  encode: (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "utf8")),
  decode: (b: Uint8Array): string => Buffer.from(b).toString("utf8"),
};

export const base64url = {
  encode: (b: Uint8Array): string => Buffer.from(b).toString("base64url"),
  decode: (s: string): Uint8Array => {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
    return new Uint8Array(Buffer.from(s, "base64url"));
  },
};

export const hex = {
  encode: (b: Uint8Array): string => Buffer.from(b).toString("hex"),
  decode: (s: string): Uint8Array => {
    if (!/^[0-9a-f]*$/.test(s) || s.length % 2) throw new Error("not lowercase hex");
    return new Uint8Array(Buffer.from(s, "hex"));
  },
};

/** SHA-256 of a string (UTF-8) or bytes. */
export function sha256(input: string | Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input));
  return new Uint8Array(h.digest());
}

/** Lowercase hex SHA-256. */
export function sha256hex(input: string | Uint8Array): string {
  return hex.encode(sha256(input));
}

export function randomBytesU8(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= (ab[i] as number) ^ (bb[i] as number);
  return diff === 0;
}
