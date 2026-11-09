// Minimal DER reader shared by the attestation verifiers (node only; not exported from the package root).
// Enough of X.690 to walk a certificate to one extension and to read Android's KeyDescription: definite
// lengths only, tags in low or high tag-number form, INTEGER/ENUMERATED as safe JS numbers.

export class DerError extends Error {}
const fail = (m: string): never => {
  throw new DerError(m);
};

export interface Der {
  /** First identifier octet (class, constructed bit, and the low tag number or 0x1f). */
  tag: number;
  /** 0 universal, 1 application, 2 context-specific, 3 private. */
  cls: number;
  constructed: boolean;
  /** Tag number, also in high tag-number form (e.g. 702 for Android's `[702] origin`). */
  num: number;
  value: Uint8Array;
  end: number;
}

export function derRead(buf: Uint8Array, pos: number): Der {
  if (pos + 2 > buf.length) fail("DER truncated");
  const tag = buf[pos] as number;
  let off = pos + 1;
  let num = tag & 0x1f;
  if (num === 0x1f) {
    num = 0;
    for (let i = 0; ; i++) {
      if (off >= buf.length || i >= 4) fail("DER tag invalid");
      const b = buf[off++] as number;
      num = num * 128 + (b & 0x7f);
      if (!(b & 0x80)) break;
    }
    if (num < 0x1f) fail("DER tag invalid");
  }
  if (off >= buf.length) fail("DER truncated");
  let len = buf[off++] as number;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + n > buf.length) fail("DER length invalid");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (buf[off + i] as number);
    off += n;
  }
  if (off + len > buf.length) fail("DER value truncated");
  return { tag, cls: tag >> 6, constructed: (tag & 0x20) !== 0, num, value: buf.subarray(off, off + len), end: off + len };
}

/** The items laid end to end in `buf` (the contents of a SEQUENCE or SET, or a concatenation). */
export function derChildren(buf: Uint8Array): Der[] {
  const out: Der[] = [];
  for (let p = 0; p < buf.length; ) {
    const d = derRead(buf, p);
    out.push(d);
    p = d.end;
  }
  return out;
}

/** Read exactly one item that fills `buf`. */
export function derOne(buf: Uint8Array): Der {
  const d = derRead(buf, 0);
  if (d.end !== buf.length) fail("trailing bytes after DER item");
  return d;
}

function signedInt(d: Der, what: string): number {
  const v = d.value;
  if (v.length === 0 || v.length > 7) fail(`${what} out of range`);
  let n = (v[0] as number) & 0x80 ? -1 : 0;
  for (const b of v) n = n * 256 + b;
  if (!Number.isSafeInteger(n)) fail(`${what} out of range`);
  return n;
}

export function derInt(d: Der): number {
  if (d.tag !== 0x02) fail("expected INTEGER");
  return signedInt(d, "INTEGER");
}

export function derEnum(d: Der): number {
  if (d.tag !== 0x0a) fail("expected ENUMERATED");
  return signedInt(d, "ENUMERATED");
}

export function derBool(d: Der): boolean {
  if (d.tag !== 0x01 || d.value.length !== 1) fail("expected BOOLEAN");
  return d.value[0] !== 0;
}

export function derOctets(d: Der): Uint8Array {
  if (d.tag !== 0x04) fail("expected OCTET STRING");
  return d.value;
}

export function derSequence(d: Der): Der[] {
  if (d.tag !== 0x30) fail("expected SEQUENCE");
  return derChildren(d.value);
}

export function derSet(d: Der): Der[] {
  if (d.tag !== 0x31) fail("expected SET");
  return derChildren(d.value);
}

export function oidString(b: Uint8Array): string {
  const first = b[0] as number;
  const parts = [Math.floor(first / 40), first % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    const c = b[i] as number;
    v = v * 128 + (c & 0x7f);
    if (!(c & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

/** extnValue (the OCTET STRING contents) of extension `oid` in a DER certificate, or undefined. */
export function certExtension(certDer: Uint8Array, oid: string): Uint8Array | undefined {
  const cert = derRead(certDer, 0);
  const tbs = derChildren(cert.value)[0];
  if (!tbs || tbs.tag !== 0x30) fail("certificate has no TBSCertificate");
  const extsWrapper = derChildren((tbs as Der).value).find((d) => d.tag === 0xa3);
  if (!extsWrapper) return undefined;
  const exts = derRead(extsWrapper.value, 0);
  for (const ext of derChildren(exts.value)) {
    const f = derChildren(ext.value);
    if (f[0]?.tag === 0x06 && oidString(f[0].value) === oid) {
      const octet = f[f.length - 1];
      if (octet?.tag !== 0x04) fail("extension value is not an OCTET STRING");
      return (octet as Der).value;
    }
  }
  return undefined;
}
