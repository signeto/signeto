// verifyWebAuthnAssertion (protocol.md §4.4): the check verifyReceipt runs, exported for verifiers that
// re-check stored assertions (the gateway's ledger verifier), with or without the allow-list.
import { describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { base64url, receiptSigningInput, utf8, verifyWebAuthnAssertion, type PublicJwk } from "../src/index.js";

const sha = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());
const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pub = kp.publicKey.export({ format: "jwk" }) as unknown as PublicJwk;
const SI = receiptSigningInput({ canonical_bytes_sha256: "a".repeat(64), decision: "approve", signed_at: "2026-11-05T18:05:00.000Z" });

function assertion(o: { rpId: string; origin: string; flags?: number; si?: string }) {
  const authData = new Uint8Array(37);
  authData.set(sha(o.rpId), 0);
  authData[32] = o.flags ?? 0x05;
  const cdj = utf8.encode(JSON.stringify({ type: "webauthn.get", challenge: base64url.encode(sha(o.si ?? SI)), origin: o.origin }));
  const sig = sign("sha256", new Uint8Array([...authData, ...sha(cdj)]), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return { webauthn: { authenticator_data: base64url.encode(authData), client_data_json: base64url.encode(cdj) }, signature: new Uint8Array(sig) };
}

const check = (a: ReturnType<typeof assertion>, extra: { allowed_origins?: string[]; rp_id?: string; require_user_verified?: boolean } = {}) =>
  verifyWebAuthnAssertion({ ...a, signing_input: SI, public_key: pub, require_user_verified: extra.require_user_verified ?? true, allowed_origins: extra.allowed_origins, rp_id: extra.rp_id });

describe("verifyWebAuthnAssertion", () => {
  it("with the policy: origin in the allow-list and the configured RP ID", () => {
    const a = assertion({ rpId: "signeto.dev", origin: "https://api.signeto.dev" });
    expect(check(a, { allowed_origins: ["https://api.signeto.dev"], rp_id: "signeto.dev" })).toEqual({ ok: true, origin: "https://api.signeto.dev", rp_id: "signeto.dev", user_verified: true });
    expect(check(a, { allowed_origins: [], rp_id: "signeto.dev" })).toMatchObject({ ok: false, code: "webauthn_origin" });
    expect(check(a, { allowed_origins: ["https://api.signeto.dev"], rp_id: "api.signeto.dev" })).toMatchObject({ ok: false, code: "webauthn_rp_id" });
  });

  it("without the policy: the RP ID must be the origin's host or a parent domain, never a bare TLD", () => {
    expect(check(assertion({ rpId: "signeto.dev", origin: "https://api.signeto.dev" }))).toMatchObject({ ok: true, rp_id: "signeto.dev" });
    expect(check(assertion({ rpId: "api.signeto.dev", origin: "https://api.signeto.dev" }))).toMatchObject({ ok: true });
    expect(check(assertion({ rpId: "localhost", origin: "http://localhost:8080" }))).toMatchObject({ ok: true });
    expect(check(assertion({ rpId: "dev", origin: "https://api.signeto.dev" }))).toMatchObject({ ok: false, code: "webauthn_rp_id" });
    expect(check(assertion({ rpId: "evil.example", origin: "https://api.signeto.dev" }))).toMatchObject({ ok: false, code: "webauthn_rp_id" });
    expect(check(assertion({ rpId: "0.1", origin: "http://127.0.0.1:8080" }))).toMatchObject({ ok: false, code: "webauthn_rp_id" });
  });

  it("challenge, flags and signature", () => {
    expect(check(assertion({ rpId: "signeto.dev", origin: "https://signeto.dev", si: SI + " " }))).toMatchObject({ ok: false, code: "webauthn_challenge" });
    expect(check(assertion({ rpId: "signeto.dev", origin: "https://signeto.dev", flags: 0x01 }))).toMatchObject({ ok: false, code: "webauthn_user_flags" });
    expect(check(assertion({ rpId: "signeto.dev", origin: "https://signeto.dev", flags: 0x01 }), { require_user_verified: false })).toMatchObject({ ok: true, user_verified: false });
    const a = assertion({ rpId: "signeto.dev", origin: "https://signeto.dev" });
    a.signature[5] ^= 1;
    expect(check(a)).toMatchObject({ ok: false, code: "invalid_signature" });
  });
});
