// Regression for SIG-92 N1 / SIG-108: a small-order Ed25519 public key. With A = the identity point, R = identity and
// S = 0, [S]B = R + [k]A holds for every message, so OpenSSL's (cofactorless) Ed25519 verification accepts that
// signature for anything. Such a key is refused by verifyWithJwk and verifyRaw, and at pairing, enrollment and
// QR parse (gateway, relay, web approver, SignetoSign).
import { describe, expect, it } from "vitest";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { base64url, isWeakPublicJwk, receiptSigningInput, utf8, verifyRaw, verifyWithJwk, type PublicJwk } from "../src/index.js";

const H = "0".repeat(64);
const TS = "2026-11-07T12:00:00.000Z";

describe("SEC: small-order Ed25519 public keys (N1)", () => {
  const x = new Uint8Array(32);
  x[0] = 1; // y = 1: the identity
  const identity = { kty: "OKP", crv: "Ed25519", x: base64url.encode(x) } as PublicJwk;
  const sig = new Uint8Array(64);
  sig[0] = 1; // R = encoding of the identity, S = 0
  const messages = ["approve anything", receiptSigningInput({ canonical_bytes_sha256: H, decision: "approve", signed_at: TS })];

  it("refused: the all-message signature no longer verifies, through verifyWithJwk or verifyRaw", () => {
    for (const m of messages) {
      expect(verifyWithJwk(utf8.encode(m), sig, identity)).toBe(false);
      const ko = createPublicKey({ key: identity as unknown as Record<string, string>, format: "jwk" });
      expect(verifyRaw("Ed25519", utf8.encode(m), sig, ko)).toBe(false);
    }
    expect(isWeakPublicJwk(identity)).toBe(true);
  });

  it("an ordinary Ed25519 key is unaffected, and so is ES256", () => {
    const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }) as PublicJwk;
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }) as PublicJwk;
    expect(isWeakPublicJwk(ed)).toBe(false);
    expect(isWeakPublicJwk(ec)).toBe(false);
    expect(isWeakPublicJwk({ kty: "OKP", crv: "Ed25519", x: "short" })).toBe(true);
  });
});
