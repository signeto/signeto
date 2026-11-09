import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ANDROID_KEY_FORMAT,
  GOOGLE_HARDWARE_ATTESTATION_ROOTS,
  normalizeSerial,
  parseAttestationStatusList,
  SIGNETO_ANDROID_PACKAGE,
  verifyAndroidDeviceAttestation,
  verifyAndroidKeyAttestation,
  type AndroidKeyOptions,
} from "../src/androidkey.js";
import { makeAndroidAttestation, TEST_ANDROID_OTHER_SIGNER, TEST_ANDROID_ROOT_PEM, TEST_ANDROID_SIGNER, type AndroidFixtureOptions } from "../src/androidkey-testing.js";
import { base64url } from "../src/encoding.js";
import type { PublicJwk } from "../src/ids.js";
import { X509Certificate } from "node:crypto";

const NOW = Date.parse("2026-11-09T00:00:00Z");
const opts: AndroidKeyOptions = { roots: [TEST_ANDROID_ROOT_PEM], signers: [TEST_ANDROID_SIGNER], now: NOW };
const check = (f: AndroidFixtureOptions = {}, o: AndroidKeyOptions = {}) => {
  const fx = makeAndroidAttestation(f);
  return verifyAndroidDeviceAttestation(fx.attestation, fx.devicePublicKey, { ...opts, ...o });
};
const refused = (reason: string) => ({ ok: false, reason });

describe("Android Key Attestation: genuine statements", () => {
  it("accepts a TEE key under the production signer on a verified, locked phone", () => {
    expect(check()).toEqual({
      ok: true,
      vouches: true,
      environment: "production",
      package_name: SIGNETO_ANDROID_PACKAGE,
      signer_sha256: TEST_ANDROID_SIGNER,
      security_level: "tee",
      verified_boot: "verified",
      device_locked: true,
      attestation_version: 300,
      os_patch_level: 202610,
    });
  });

  it("reports StrongBox", () => {
    expect(check({ attestationSecurityLevel: 2 })).toMatchObject({ ok: true, vouches: true, security_level: "strongbox" });
  });

  it("accepts chains of three and four certificates, with or without the root, and older attestation versions", () => {
    expect(check({ chainLength: 3 })).toMatchObject({ ok: true, vouches: true });
    expect(check({ omitRoot: true })).toMatchObject({ ok: true, vouches: true });
    expect(check({ attestationVersion: 3 })).toMatchObject({ ok: true, vouches: true, attestation_version: 3 });
    expect(check({ attestationVersion: 400 })).toMatchObject({ ok: true, vouches: true });
  });

  it("pins the root by key: an expired certificate for the same root key is fine", () => {
    expect(check({ expiredRootCopy: true })).toMatchObject({ ok: true, vouches: true });
  });

  it("accepts SIGN with VERIFY, and a missing ecCurve tag", () => {
    expect(check({ purposes: [2, 3] })).toMatchObject({ ok: true, vouches: true });
    expect(check({ ecCurve: null })).toMatchObject({ ok: true, vouches: true });
  });

  it("ignores the challenge and tags it does not know", () => {
    // Every fixture has a random challenge and a softwareEnforced creationDateTime [701].
    const a = makeAndroidAttestation();
    const b = makeAndroidAttestation();
    expect(verifyAndroidDeviceAttestation(a.attestation, a.devicePublicKey, opts)).toMatchObject({ ok: true });
    expect(verifyAndroidDeviceAttestation(b.attestation, b.devicePublicKey, opts)).toMatchObject({ ok: true });
  });
});

describe("Android Key Attestation: genuine but not vouching (records software: true)", () => {
  it("a listed development signer is development, an unknown signer does not vouch", () => {
    expect(check({ signers: [TEST_ANDROID_OTHER_SIGNER] }, { developmentSigners: [TEST_ANDROID_OTHER_SIGNER] })).toMatchObject({ ok: true, vouches: true, environment: "development" });
    expect(check({ signers: [TEST_ANDROID_OTHER_SIGNER] })).toMatchObject({ ok: true, vouches: false, reason: "signed by a signer that is not a production or listed development signer", signer_sha256: TEST_ANDROID_OTHER_SIGNER });
  });

  it("an unlocked bootloader or unverified boot does not vouch, whatever the signer", () => {
    expect(check({ deviceLocked: false })).toMatchObject({ ok: true, vouches: false, reason: "boot is not verified and locked", device_locked: false });
    expect(check({ verifiedBootState: 2 })).toMatchObject({ ok: true, vouches: false, verified_boot: "unverified" });
    expect(check({ verifiedBootState: 1 })).toMatchObject({ ok: true, vouches: false, verified_boot: "self_signed" });
    expect(check({ deviceLocked: false, signers: [TEST_ANDROID_OTHER_SIGNER] }, { developmentSigners: [TEST_ANDROID_OTHER_SIGNER] })).toMatchObject({ ok: true, vouches: false });
  });

  it("with no production signers configured (the default today) nothing is production", () => {
    const fx = makeAndroidAttestation();
    expect(verifyAndroidDeviceAttestation(fx.attestation, fx.devicePublicKey, { roots: [TEST_ANDROID_ROOT_PEM], now: NOW })).toMatchObject({ ok: true, vouches: false });
  });
});

describe("Android Key Attestation: refused", () => {
  it("(a) a chain to another root, a rogue intermediate, a non-CA intermediate", () => {
    const fx = makeAndroidAttestation();
    expect(verifyAndroidDeviceAttestation(fx.attestation, fx.devicePublicKey, { signers: [TEST_ANDROID_SIGNER], now: NOW })).toEqual(refused("certificate chain does not lead to a Google Hardware Attestation root"));
    expect(check({ rogueIntermediate: true })).toEqual(refused("certificate 2 is not signed by the next one in the chain"));
    expect(check({ rogueIntermediate: true, omitRoot: true })).toEqual(refused("certificate chain does not lead to a Google Hardware Attestation root"));
    expect(check({ intermediateNotCa: true })).toEqual(refused("certificate 2 in the chain is not a CA"));
  });

  it("(b) a statement for another key", () => {
    expect(check({ leafKeyMismatch: true })).toEqual(refused("attested key is not the device key"));
    const fx = makeAndroidAttestation();
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" }) as PublicJwk;
    expect(verifyAndroidDeviceAttestation(fx.attestation, other, opts)).toEqual(refused("attested key is not the device key"));
    const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }) as PublicJwk;
    expect(verifyAndroidDeviceAttestation(fx.attestation, ed, opts)).toEqual(refused("Android Key Attestation binds ES256 (P-256) device keys only"));
  });

  it("(c) a KeyDescription anywhere but the leaf", () => {
    expect(check({ keyDescriptionOnIntermediate: true })).toEqual(refused("certificate 2 in the chain also carries a KeyDescription"));
  });

  it("(d) a software key, or a TEE statement about a software key", () => {
    expect(check({ attestationSecurityLevel: 0 })).toEqual(refused("key is not in a TEE or StrongBox"));
    expect(check({ attestationSecurityLevel: 1, keyMintSecurityLevel: 0 })).toEqual(refused("key is not in a TEE or StrongBox"));
  });

  it("(e) a key policy other than a generated EC signing key with a biometric for every operation", () => {
    expect(check({ origin: 2 })).toEqual(refused("key was not generated in the hardware"));
    expect(check({ purposes: [2, 1] })).toEqual(refused("key purpose is not signing only"));
    expect(check({ purposes: [3] })).toEqual(refused("key purpose is not signing only"));
    expect(check({ algorithm: 1 })).toEqual(refused("key algorithm is not EC"));
    expect(check({ ecCurve: 2 })).toEqual(refused("key curve is not P-256"));
    expect(check({ noAuthRequired: true })).toEqual(refused("key does not require user authentication"));
    expect(check({ userAuthType: 1 })).toEqual(refused("key does not require a biometric (and only a biometric)"));
    expect(check({ userAuthType: 3 })).toEqual(refused("key does not require a biometric (and only a biometric)"));
    expect(check({ authTimeout: 0 })).toEqual(refused("key authorizes a time window, not each operation"));
    expect(check({ authTimeout: 30 })).toEqual(refused("key authorizes a time window, not each operation"));
    expect(check({ allowWhileOnBody: true })).toEqual(refused("key stays usable while on body"));
  });

  it("(e) boot state counts only from hardwareEnforced", () => {
    expect(check({ rootOfTrustIn: "software" })).toEqual(refused("attestation has no hardware root of trust"));
  });

  it("(f) another package, two packages, two signers, an application id outside softwareEnforced", () => {
    expect(check({ packages: ["com.example.other"] })).toEqual(refused("attestation is for a different app"));
    expect(check({ packages: [SIGNETO_ANDROID_PACKAGE, "com.example.shared"] })).toEqual(refused("application id must name exactly one package"));
    expect(check({ signers: [TEST_ANDROID_SIGNER, TEST_ANDROID_OTHER_SIGNER] })).toEqual(refused("application id must carry exactly one SHA-256 signer digest"));
    expect(check({ appIdIn: "hardware" })).toEqual(refused("attestation has no application id"));
    expect(check({ packages: ["com.example.other"] }, { packages: ["com.example.other"] })).toMatchObject({ ok: true, vouches: true });
  });

  it("an attestation version before 3", () => {
    expect(check({ attestationVersion: 2 })).toEqual(refused("attestation version 2 is too old"));
  });
});

describe("Android Key Attestation: validity and revocation", () => {
  it("relay (now): every certificate but the root valid now, with 60 s of skew", () => {
    expect(check({ intermediateNotAfter: new Date("2026-11-01T00:00:00Z") })).toEqual(refused("certificate 2 in the chain is not valid now"));
    expect(check({ intermediateNotBefore: new Date(NOW + 30_000) })).toMatchObject({ ok: true });
    expect(check({ intermediateNotBefore: new Date(NOW + 120_000) })).toEqual(refused("certificate 2 in the chain is not valid now"));
  });

  it("gateway (issuance): notAfter is not enforced, notBefore at most a day ahead", () => {
    expect(check({ intermediateNotAfter: new Date("2026-11-01T00:00:00Z") }, { validity: "issuance" })).toMatchObject({ ok: true, vouches: true });
    expect(check({ intermediateNotBefore: new Date(NOW + 3_600_000) }, { validity: "issuance" })).toMatchObject({ ok: true });
    expect(check({ intermediateNotBefore: new Date(NOW + 2 * 86_400_000) }, { validity: "issuance" })).toEqual(refused("certificate 2 in the chain is issued in the future"));
  });

  it("refuses a chain with a revoked or suspended certificate (serials as Google writes them)", () => {
    const list = parseAttestationStatusList({ entries: { a1b2c: { status: "REVOKED", reason: "KEY_COMPROMISE" }, "3d4e5f": { status: "SUSPENDED" }, ff: { status: "SOMETHING_ELSE" } } });
    expect([...list].sort()).toEqual(["3d4e5f", "a1b2c"]);
    expect(check({}, { revokedSerials: new Set(["a1b2c"]) })).toEqual(refused("certificate 1 in the chain is revoked"));
    expect(check({}, { revokedSerials: list })).toMatchObject({ ok: false });
    expect(check({}, { revokedSerials: new Set(["123456"]) })).toMatchObject({ ok: true });
    expect(normalizeSerial("000A1B2C")).toBe("a1b2c");
    expect(normalizeSerial("00")).toBe("0");
    expect(() => parseAttestationStatusList({ nope: 1 })).toThrow();
  });
});

describe("Android Key Attestation: input handling", () => {
  it("refuses malformed data without throwing", () => {
    const fx = makeAndroidAttestation();
    const v = (data: string) => verifyAndroidKeyAttestation(data, fx.devicePublicKey, opts);
    expect(v("")).toEqual(refused("attestation data is empty or too large"));
    expect(v("!!")).toEqual(refused("attestation data is not base64url UTF-8"));
    expect(check({ rawData: "not json" })).toEqual(refused("attestation data is not JSON"));
    expect(check({ rawData: '{"x5c":[],"challenge":"x"}' })).toEqual(refused('attestation data must have exactly the member "x5c"'));
    expect(check({ rawData: '{ "x5c": ["AA", "AA"] }' })).toEqual(refused("attestation data is not canonical JSON (RFC 8785)"));
    expect(check({ rawData: '{"x5c":["AA"]}' })).toEqual(refused("x5c must hold 2 to 10 certificates"));
    expect(check({ rawData: '{"x5c":["AA","!"]}' })).toEqual(refused("x5c entry is not base64url"));
    expect(check({ rawData: '{"x5c":["AAAA","AAAA"]}' })).toEqual(refused("x5c entry is not an X.509 certificate"));
    expect(verifyAndroidDeviceAttestation({ format: "apple-appattest", data: fx.attestation.data }, fx.devicePublicKey, opts)).toEqual(refused('unsupported attestation format "apple-appattest"'));
    expect(ANDROID_KEY_FORMAT).toBe("android-key");
    // Truncated certificate bytes.
    const cut = base64url.encode(new TextEncoder().encode(JSON.stringify({ x5c: fx.chain.map((c, i) => base64url.encode(i === 0 ? c.subarray(0, 100) : c)) })));
    expect(v(cut)).toMatchObject({ ok: false });
  });
});

describe("Google roots", () => {
  it("ships the RSA-4096 root and the ECDSA P-384 Key Attestation CA1, and they refuse the test chain", () => {
    const keys = GOOGLE_HARDWARE_ATTESTATION_ROOTS.map((p) => new X509Certificate(p).publicKey.asymmetricKeyDetails);
    expect(keys).toEqual([expect.objectContaining({ modulusLength: 4096 }), expect.objectContaining({ namedCurve: "secp384r1" })]);
    const fx = makeAndroidAttestation();
    expect(verifyAndroidDeviceAttestation(fx.attestation, fx.devicePublicKey, { signers: [TEST_ANDROID_SIGNER], now: NOW })).toMatchObject({ ok: false });
  });
});
