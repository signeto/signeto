// DER builders for the test-support modules (`appattest/testing`, `androidkey/testing`): just enough to
// make X.509 certificates and Android KeyDescription extensions under throwaway test roots.
import { sign, type KeyObject } from "node:crypto";

const len = (n: number): number[] => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
export const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = Buffer.concat(parts);
  return new Uint8Array([tag, ...len(body.length), ...body]);
};
export const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
export const set = (...p: Uint8Array[]) => tlv(0x31, ...p);
function intBytes(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("der-build: non-negative safe integers only");
  const out: number[] = [];
  let x = n;
  do {
    out.unshift(x % 256);
    x = Math.floor(x / 256);
  } while (x > 0);
  if ((out[0] as number) & 0x80) out.unshift(0);
  return new Uint8Array(out);
}
export const int = (n: number) => tlv(0x02, intBytes(n));
export const enumerated = (n: number) => tlv(0x0a, intBytes(n));
export const octet = (b: Uint8Array) => tlv(0x04, b);
export const bitString = (b: Uint8Array) => tlv(0x03, new Uint8Array([0]), b);
export const bool = (v: boolean) => tlv(0x01, new Uint8Array([v ? 0xff : 0]));
export const nul = () => new Uint8Array([0x05, 0x00]);
export const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
export const explicit = (n: number, p: Uint8Array) => tlv(0xa0 | n, p);
/** `[n] EXPLICIT` in context-specific constructed form, high tag-number form when n >= 31. */
export function ctx(n: number, p: Uint8Array): Uint8Array {
  if (n < 31) return explicit(n, p);
  const groups: number[] = [];
  let x = n;
  do {
    groups.unshift(x & 0x7f);
    x = Math.floor(x / 128);
  } while (x > 0);
  const id = [0xbf, ...groups.map((g, i) => (i < groups.length - 1 ? g | 0x80 : g))];
  return new Uint8Array([...id, ...len(p.length), ...p]);
}
export function oid(s: string): Uint8Array {
  const [a, b, ...rest] = s.split(".").map(Number) as [number, number, ...number[]];
  const out = [a * 40 + b];
  for (const v of rest) {
    const groups: number[] = [];
    let x = v;
    do {
      groups.unshift(x & 0x7f);
      x = Math.floor(x / 128);
    } while (x > 0);
    out.push(...groups.map((g, i) => (i < groups.length - 1 ? g | 0x80 : g)));
  }
  return tlv(0x06, new Uint8Array(out));
}
function utcTime(d: Date): Uint8Array {
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));

export interface CertSpec {
  subject: string;
  issuer: string;
  publicKey: KeyObject;
  signer: KeyObject;
  ca?: boolean;
  extensions?: Uint8Array[];
  notBefore?: Date;
  notAfter?: Date;
  serial?: number;
}

export function makeCert(c: CertSpec): Uint8Array {
  const p384 = c.signer.asymmetricKeyDetails?.namedCurve === "secp384r1";
  const sigAlg = seq(oid(p384 ? "1.2.840.10045.4.3.3" : "1.2.840.10045.4.3.2"));
  const exts = [...(c.ca ? [seq(oid("2.5.29.19"), bool(true), octet(seq(bool(true))))] : []), ...(c.extensions ?? [])];
  const tbs = seq(
    explicit(0, int(2)),
    int(c.serial ?? 1),
    sigAlg,
    name(c.issuer),
    seq(utcTime(c.notBefore ?? new Date("2025-01-01T00:00:00Z")), utcTime(c.notAfter ?? new Date("2040-01-01T00:00:00Z"))),
    name(c.subject),
    new Uint8Array(c.publicKey.export({ type: "spki", format: "der" })),
    ...(exts.length ? [explicit(3, seq(...exts))] : []),
  );
  const sig = sign(p384 ? "sha384" : "sha256", tbs, c.signer);
  return seq(tbs, sigAlg, bitString(new Uint8Array(sig)));
}

export const derToPem = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;
