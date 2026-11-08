// Test support, exported as `@signeto/protocol/appattest/testing`: builds App Attest statements shaped
// like Apple's (root → intermediate → credential certificate with the nonce extension, CBOR attestation
// object) under a throwaway test root. Pass TEST_ROOT_PEM as `roots` to accept them. Never trusted by
// default: the verifier pins Apple's root unless told otherwise.
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { base64url } from "./encoding.js";
import { jwkThumbprint, type PublicJwk } from "./ids.js";

// ---- DER ---------------------------------------------------------------------------------------------
const len = (n: number): number[] => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = Buffer.concat(parts);
  return new Uint8Array([tag, ...len(body.length), ...body]);
};
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const set = (...p: Uint8Array[]) => tlv(0x31, ...p);
const int = (n: number) => tlv(0x02, new Uint8Array([n]));
const octet = (b: Uint8Array) => tlv(0x04, b);
const bitString = (b: Uint8Array) => tlv(0x03, new Uint8Array([0]), b);
const bool = (v: boolean) => tlv(0x01, new Uint8Array([v ? 0xff : 0]));
const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
const explicit = (n: number, p: Uint8Array) => tlv(0xa0 | n, p);
function oid(s: string): Uint8Array {
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

interface CertSpec {
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

// ---- CBOR --------------------------------------------------------------------------------------------
function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 0xff];
  return [(major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}
export function cbor(v: unknown): Uint8Array {
  if (typeof v === "number") return new Uint8Array(head(0, v));
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    return new Uint8Array([...head(3, b.length), ...b]);
  }
  if (v instanceof Uint8Array) return new Uint8Array([...head(2, v.length), ...v]);
  if (Array.isArray(v)) return new Uint8Array([...head(4, v.length), ...v.flatMap((x) => [...cbor(x)])]);
  if (v instanceof Map) return new Uint8Array([...head(5, v.size), ...[...v].flatMap(([k, x]) => [...cbor(k), ...cbor(x)])]);
  throw new Error("cbor: unsupported");
}

// ---- the statement -----------------------------------------------------------------------------------
const sha256 = (...parts: Uint8Array[]) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

export interface Fixture {
  rootPem: string;
  devicePublicKey: PublicJwk;
  attestation: { format: string; data: string };
  object: Uint8Array;
  clientDataHash: Uint8Array;
}

export interface FixtureOptions {
  appId?: string;
  aaguid?: "production" | "development" | Uint8Array;
  signCount?: number;
  /** Replace the credential id in authData (default: keyId). */
  credentialId?: Uint8Array;
  /** Bind the nonce to this clientDataHash instead of the device key's thumbprint. */
  nonceFor?: Uint8Array;
  credNotAfter?: Date;
  /** Sign the intermediate with a key other than the root's. */
  rogueIntermediate?: boolean;
  fmt?: string;
}

const ec = (curve: string) => generateKeyPairSync("ec", { namedCurve: curve });
const rootKeys = ec("secp384r1");
const rootDer = makeCert({ subject: "Test App Attestation Root CA", issuer: "Test App Attestation Root CA", publicKey: rootKeys.publicKey, signer: rootKeys.privateKey, ca: true });
export const TEST_ROOT_PEM = derToPem(rootDer);

export function makeAttestation(o: FixtureOptions = {}): Fixture {
  const appId = o.appId ?? "3PL7Z4G933.dev.signeto.approver";
  const device = ec("prime256v1");
  const devicePublicKey = device.publicKey.export({ format: "jwk" }) as PublicJwk;
  const clientDataHash = jwkThumbprint(devicePublicKey);

  const interKeys = ec("secp384r1");
  const interSigner = o.rogueIntermediate ? ec("secp384r1").privateKey : rootKeys.privateKey;
  const interDer = makeCert({ subject: "Test App Attestation CA 1", issuer: "Test App Attestation Root CA", publicKey: interKeys.publicKey, signer: interSigner, ca: true, serial: 2 });

  const cred = ec("prime256v1");
  const cj = cred.publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const keyId = sha256(new Uint8Array([4, ...base64url.decode(cj.x), ...base64url.decode(cj.y)]));
  const aaguid =
    o.aaguid instanceof Uint8Array ? o.aaguid : o.aaguid === "development" ? new TextEncoder().encode("appattestdevelop") : new Uint8Array([...new TextEncoder().encode("appattest"), 0, 0, 0, 0, 0, 0, 0]);
  const credId = o.credentialId ?? keyId;
  const count = o.signCount ?? 0;
  const authData = new Uint8Array([
    ...sha256(new TextEncoder().encode(appId)),
    0x40,
    (count >>> 24) & 0xff, (count >>> 16) & 0xff, (count >>> 8) & 0xff, count & 0xff,
    ...aaguid,
    credId.length >> 8, credId.length & 0xff,
    ...credId,
    ...cbor(new Map<unknown, unknown>([[1, 2], [3, 0]])), // stand-in COSE key; never parsed
  ]);
  const nonce = sha256(authData, o.nonceFor ?? clientDataHash);
  const nonceExt = seq(oid("1.2.840.113635.100.8.2"), octet(seq(tlv(0xa1, octet(nonce)))));
  const credDer = makeCert({ subject: "credential", issuer: "Test App Attestation CA 1", publicKey: cred.publicKey, signer: interKeys.privateKey, extensions: [nonceExt], serial: 3, ...(o.credNotAfter ? { notAfter: o.credNotAfter } : {}) });

  const object = cbor(
    new Map<unknown, unknown>([
      ["fmt", o.fmt ?? "apple-appattest"],
      ["attStmt", new Map<unknown, unknown>([["x5c", [credDer, interDer]], ["receipt", new Uint8Array([1, 2, 3])]])],
      ["authData", authData],
    ]),
  );
  return { rootPem: TEST_ROOT_PEM, devicePublicKey, attestation: { format: "apple-appattest", data: base64url.encode(object) }, object, clientDataHash };
}
