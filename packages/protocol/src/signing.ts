// Raw signature primitives for the two algorithms from ADR-0002.
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";
import type { PrivateJwk, PublicJwk, SignatureAlg } from "./ids.js";
import { algForJwk } from "./ids.js";
import { isWeakPublicJwk } from "./weakkeys.js";

export function publicKeyFromJwk(jwk: PublicJwk | PrivateJwk): KeyObject {
  const { d: _d, ...pub } = jwk as PrivateJwk;
  return createPublicKey({ key: pub as unknown as Record<string, string>, format: "jwk" });
}
export function privateKeyFromJwk(jwk: PrivateJwk): KeyObject {
  return createPrivateKey({ key: jwk as unknown as Record<string, string>, format: "jwk" });
}

/** ES256: ECDSA P-256 over SHA-256(data), raw r||s (64 bytes). Ed25519: PureEdDSA over data. */
export function signRaw(alg: SignatureAlg, data: Uint8Array, priv: KeyObject): Uint8Array {
  if (alg === "ES256") return new Uint8Array(nodeSign("sha256", Buffer.from(data), { key: priv, dsaEncoding: "ieee-p1363" }));
  return new Uint8Array(nodeSign(null, Buffer.from(data), priv));
}

export function verifyRaw(alg: SignatureAlg, data: Uint8Array, sig: Uint8Array, pub: KeyObject): boolean {
  if (sig.length !== 64) return false;
  try {
    // §5.1: a small-order Ed25519 key verifies forged signatures; nothing verifies under one.
    if (alg === "Ed25519" && isWeakPublicJwk(pub.export({ format: "jwk" }) as { kty?: unknown; crv?: unknown; x?: unknown })) return false;
    if (alg === "ES256") return nodeVerify("sha256", Buffer.from(data), { key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(sig));
    return nodeVerify(null, Buffer.from(data), pub, Buffer.from(sig));
  } catch {
    return false;
  }
}

/** Sign with a private JWK in that key's own algorithm. */
export function signWithJwk(data: Uint8Array, jwk: PrivateJwk): { alg: SignatureAlg; signature: Uint8Array } {
  const alg = algForJwk(jwk);
  return { alg, signature: signRaw(alg, data, privateKeyFromJwk(jwk)) };
}

export function verifyWithJwk(data: Uint8Array, sig: Uint8Array, jwk: PublicJwk | PrivateJwk): boolean {
  if (isWeakPublicJwk(jwk)) return false;
  return verifyRaw(algForJwk(jwk), data, sig, publicKeyFromJwk(jwk));
}
