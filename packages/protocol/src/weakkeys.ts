// docs/protocol.md §5.1: Ed25519 public keys that are refused everywhere. A point of small order (1, 2, 4 or 8) as a
// public key makes the all-zero-S signature with R = identity valid for every message under cofactorless
// verification, so a device that pinned one would "sign" anything. The list is libsodium's
// (crypto_sign_ed25519 / ge25519_has_small_order): the 8-torsion points by their y coordinate, including the
// non-canonical encodings y = p, p + 1, compared with the sign bit (bit 255) ignored.
import { base64url } from "./encoding.js";

const SMALL_ORDER_Y: readonly string[] = [
  // 0 (order 4)
  "0000000000000000000000000000000000000000000000000000000000000000",
  // 1 (order 1: the identity)
  "0100000000000000000000000000000000000000000000000000000000000000",
  // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  // p - 1 (order 2)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // p (non-canonical 0, order 4)
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // p + 1 (non-canonical 1, order 1)
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];
const BLOCKED = SMALL_ORDER_Y.map((h) => Uint8Array.from(h.match(/../g) as string[], (b) => parseInt(b, 16)));

/** True when the 32-byte Ed25519 public key encoding is a point of small order (§5.1). Not 32 bytes: true. */
export function isSmallOrderEd25519(raw: Uint8Array): boolean {
  if (raw.length !== 32) return true;
  for (const b of BLOCKED) {
    let diff = 0;
    for (let i = 0; i < 31; i++) diff |= raw[i]! ^ b[i]!;
    diff |= (raw[31]! & 0x7f) ^ b[31]!;
    if (diff === 0) return true;
  }
  return false;
}

/**
 * §5.1: true for a JWK that must not be pinned, enrolled or trusted: an Ed25519 key whose `x` is not 32 bytes of
 * base64url or is a small-order point. EC keys are not affected (P-256 has cofactor 1; invalid points fail import).
 */
export function isWeakPublicJwk(jwk: { kty?: unknown; crv?: unknown; x?: unknown }): boolean {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") return false;
  if (typeof jwk.x !== "string") return true;
  let raw: Uint8Array;
  try {
    raw = base64url.decode(jwk.x);
  } catch {
    return true;
  }
  return isSmallOrderEd25519(raw);
}
