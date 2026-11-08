import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { APPLE_APP_ATTEST_ROOT_CA, SIGNETO_APP_ID, verifyAppAttest, verifyDeviceAttestation } from "../src/appattest.js";
import { base64url } from "../src/encoding.js";
import type { PublicJwk } from "../src/ids.js";
import { cbor, makeAttestation, TEST_ROOT_PEM } from "../src/appattest-testing.js";

const roots = [TEST_ROOT_PEM];
const NOW = Date.parse("2026-11-08T00:00:00Z");
const opts = { roots, now: NOW };

describe("App Attest verification", () => {
  it("accepts a production statement bound to the device key", () => {
    const f = makeAttestation();
    const r = verifyDeviceAttestation(f.attestation, f.devicePublicKey, opts);
    expect(r).toMatchObject({ ok: true, environment: "production", app_id: SIGNETO_APP_ID });
    if (r.ok) {
      expect(r.key_id).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect([...(r.receipt ?? [])]).toEqual([1, 2, 3]);
    }
  });

  it("accepts development builds unless they are switched off", () => {
    const f = makeAttestation({ aaguid: "development" });
    expect(verifyDeviceAttestation(f.attestation, f.devicePublicKey, opts)).toMatchObject({ ok: true, environment: "development" });
    expect(verifyDeviceAttestation(f.attestation, f.devicePublicKey, { ...opts, allowDevelopment: false })).toEqual({ ok: false, reason: "development-build attestations are not accepted" });
  });

  it("rejects a statement for another device key (the nonce binds the thumbprint)", () => {
    const f = makeAttestation();
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" }) as PublicJwk;
    expect(verifyDeviceAttestation(f.attestation, other, opts)).toEqual({ ok: false, reason: "nonce does not match authData and the device key" });
    const g = makeAttestation({ nonceFor: new Uint8Array(32) });
    expect(verifyDeviceAttestation(g.attestation, g.devicePublicKey, opts)).toMatchObject({ ok: false, reason: "nonce does not match authData and the device key" });
  });

  it("pins the root: a chain to any other root fails, including Apple's for a test chain", () => {
    const f = makeAttestation();
    expect(verifyAppAttest(f.object, f.clientDataHash, { now: NOW })).toEqual({ ok: false, reason: "certificate chain does not lead to the Apple App Attestation Root CA" });
    const rogue = makeAttestation({ rogueIntermediate: true });
    expect(verifyAppAttest(rogue.object, rogue.clientDataHash, opts)).toMatchObject({ ok: false, reason: "certificate chain does not lead to the Apple App Attestation Root CA" });
  });

  it("checks the app id, sign count, aaguid and credential id", () => {
    const wrongApp = makeAttestation({ appId: "ABCDE12345.com.example.other" });
    expect(verifyAppAttest(wrongApp.object, wrongApp.clientDataHash, opts)).toEqual({ ok: false, reason: "attestation is for a different app" });
    expect(verifyAppAttest(wrongApp.object, wrongApp.clientDataHash, { ...opts, appIds: ["ABCDE12345.com.example.other"] })).toMatchObject({ ok: true });
    const used = makeAttestation({ signCount: 1 });
    expect(verifyAppAttest(used.object, used.clientDataHash, opts)).toEqual({ ok: false, reason: "sign count is not zero" });
    const guid = makeAttestation({ aaguid: new Uint8Array(16) });
    expect(verifyAppAttest(guid.object, guid.clientDataHash, opts)).toEqual({ ok: false, reason: "aaguid is not an App Attest environment" });
    const cred = makeAttestation({ credentialId: new Uint8Array(32).fill(7) });
    expect(verifyAppAttest(cred.object, cred.clientDataHash, opts)).toEqual({ ok: false, reason: "credential id does not match the credential certificate key" });
  });

  it("checks certificate validity at the given time", () => {
    const f = makeAttestation({ credNotAfter: new Date("2026-01-01T00:00:00Z") });
    expect(verifyAppAttest(f.object, f.clientDataHash, opts)).toEqual({ ok: false, reason: "credential certificate is not valid now" });
    const g = makeAttestation();
    expect(verifyAppAttest(g.object, g.clientDataHash, { roots, now: Date.parse("2041-01-01T00:00:00Z") })).toMatchObject({ ok: false });
    // Pairing later: an expired credential certificate still verifies when checked as of issuance.
    expect(verifyAppAttest(f.object, f.clientDataHash, { ...opts, validity: "issuance" })).toMatchObject({ ok: true });
    expect(verifyAppAttest(g.object, g.clientDataHash, { roots, now: Date.parse("2024-06-01T00:00:00Z"), validity: "issuance" })).toEqual({ ok: false, reason: "credential certificate is issued in the future" });
  });

  it("rejects malformed input without throwing", () => {
    const f = makeAttestation();
    const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }) as PublicJwk;
    expect(verifyDeviceAttestation(f.attestation, ed, opts)).toMatchObject({ ok: false, reason: "App Attest binds ES256 (P-256) device keys only" });
    expect(verifyDeviceAttestation({ format: "android-key", data: f.attestation.data }, f.devicePublicKey, opts)).toMatchObject({ ok: false });
    expect(verifyDeviceAttestation({ format: "apple-appattest", data: "!!" }, f.devicePublicKey, opts)).toMatchObject({ ok: false });
    expect(verifyAppAttest(f.object.subarray(0, 40), f.clientDataHash, opts)).toMatchObject({ ok: false });
    expect(verifyAppAttest(new Uint8Array([...f.object, 0]), f.clientDataHash, opts)).toEqual({ ok: false, reason: "trailing bytes after CBOR item" });
    expect(verifyAppAttest(f.object, new Uint8Array(31), opts)).toEqual({ ok: false, reason: "clientDataHash must be 32 bytes" });
    const wrongFmt = makeAttestation({ fmt: "packed" });
    expect(verifyAppAttest(wrongFmt.object, wrongFmt.clientDataHash, opts)).toEqual({ ok: false, reason: "fmt is not apple-appattest" });
    const noCerts = cbor(new Map<unknown, unknown>([["fmt", "apple-appattest"], ["attStmt", new Map([["x5c", []]])], ["authData", new Uint8Array(60)]]));
    expect(verifyAppAttest(noCerts, f.clientDataHash, opts)).toEqual({ ok: false, reason: "x5c must hold the credential and intermediate certificates" });
    expect(base64url.encode(new Uint8Array([1]))).toBe("AQ");
  });

  it("ships Apple's root CA", () => {
    expect(APPLE_APP_ATTEST_ROOT_CA).toContain("MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw");
  });
});
