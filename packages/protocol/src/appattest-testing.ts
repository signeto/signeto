// Test support, exported as `@signeto/protocol/appattest/testing`: builds App Attest statements shaped
// like Apple's (root → intermediate → credential certificate with the nonce extension, CBOR attestation
// object) under a throwaway test root. Pass TEST_ROOT_PEM as `roots` to accept them. Never trusted by
// default: the verifier pins Apple's root unless told otherwise.
import { createHash, generateKeyPairSync } from "node:crypto";
import { derToPem, makeCert, octet, oid, seq, tlv } from "./der-build.js";

export { derToPem, makeCert } from "./der-build.js";
import { base64url } from "./encoding.js";
import { jwkThumbprint, type PublicJwk } from "./ids.js";

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
