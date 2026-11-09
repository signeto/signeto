// Android Key Attestation verification (node only; exported as `@signeto/protocol/androidkey`, not from the
// root, so browser bundles never pull in X.509). Implements protocol.md §5.3 point 3, "Android Key
// Attestation".
//
// The Android app generates its device key in the Keystore (StrongBox or TEE) and sends the attestation
// chain Keystore returns for it: `data` = base64url(JCS {"x5c": [leaf, …, root]}), each certificate base64url
// DER. The leaf certificate's public key IS the device key, so the statement binds the key without a nonce;
// the attestation challenge is device-chosen and ignored here.
//
// Outcomes:
//   ok: false                  refuse (attestation_invalid): forged or broken chain, another key, software
//                              security level, a key policy other than "biometric for every operation", another
//                              package, a revoked certificate, malformed input.
//   ok: true, vouches: true    hardware key under the released app (production) or a listed development signer,
//                              on a phone whose boot is verified and locked.
//   ok: true, vouches: false   genuine hardware statement that does not vouch for the app (another signer, an
//                              unlocked bootloader, an unverified boot): record the device `software: true`.
import { X509Certificate, type KeyObject } from "node:crypto";
import { base64url, hex } from "./encoding.js";
import type { PublicJwk } from "./ids.js";
import { isCanonical } from "./jcs.js";
import { certExtension, derBool, derChildren, derEnum, DerError, derInt, derOctets, derOne, derSequence, derSet, type Der } from "./der.js";

export const ANDROID_KEY_FORMAT = "android-key";

/** The Signeto approver app's package name. */
export const SIGNETO_ANDROID_PACKAGE = "dev.signeto.approver";

/**
 * Production signers of the Signeto app: lowercase hex SHA-256 of the Play App Signing certificate.
 * Empty until the app exists in Play Console (SIG-124): until then no statement is `production`, so every
 * Android device records `software: true`, which is the safe default.
 */
export const SIGNETO_ANDROID_SIGNERS: readonly string[] = [];

/** KeyDescription extension (Android Keystore attestation). */
export const KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

/** Google's published roots (JSON array of PEMs) and revocation list. */
export const GOOGLE_ATTESTATION_ROOTS_URL = "https://android.googleapis.com/attestation/root";
export const GOOGLE_ATTESTATION_STATUS_URL = "https://android.googleapis.com/attestation/status";

/**
 * Google Hardware Attestation roots, from GOOGLE_ATTESTATION_ROOTS_URL (fetched 2026-11-09). Matched by public
 * key (SubjectPublicKeyInfo), not by certificate: Google reissued the RSA root under the same key, and older
 * phones still return expired copies of it.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOTS: readonly string[] = [
  // serialNumber=f92009e853b6b045 | Mar 20 18:07:48 2022 GMT to Mar 15 18:07:48 2042 GMT
  // cert SHA-256 CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC
  // SPKI SHA-256 feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae
  `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----
`,
  // CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US | Jul 17 22:32:18 2025 GMT to Jul 15 22:32:18 2035 GMT
  // cert SHA-256 6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0
  // SPKI SHA-256 3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec
  `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----
`,
];

export type AndroidSecurityLevel = "tee" | "strongbox";
export type VerifiedBoot = "verified" | "self_signed" | "unverified" | "failed";
export type AndroidKeyEnvironment = "production" | "development";

export interface AndroidKeyOptions {
  /** Accepted package names. Default: [SIGNETO_ANDROID_PACKAGE]. */
  packages?: readonly string[];
  /** Production signers (lowercase hex SHA-256 of the signing certificate). Default: SIGNETO_ANDROID_SIGNERS. */
  signers?: readonly string[];
  /** Development signers (local builds). Default: none. */
  developmentSigners?: readonly string[];
  /** Reference time, ms. Default Date.now(). */
  now?: number;
  /**
   * "now" (default, relay enrollment): every certificate but the root valid at `now`, ±60 s.
   * "issuance" (gateway pairing, the statement may be months old): no certificate's notBefore more than a day
   * after `now`; notAfter is not enforced.
   */
  validity?: "now" | "issuance";
  /** Trusted roots (PEM), matched by public key. Default: GOOGLE_HARDWARE_ATTESTATION_ROOTS. Tests pass their own. */
  roots?: readonly string[];
  /** Revoked or suspended serial numbers (lowercase hex, no leading zeros), e.g. from parseAttestationStatusList. */
  revokedSerials?: ReadonlySet<string>;
}

export interface AndroidKeyFacts {
  package_name: string;
  signer_sha256: string;
  security_level: AndroidSecurityLevel;
  verified_boot: VerifiedBoot;
  device_locked: boolean;
  attestation_version: number;
  os_patch_level: number | null;
}

export type AndroidKeyResult =
  | ({ ok: true; vouches: true; environment: AndroidKeyEnvironment } & AndroidKeyFacts)
  | ({ ok: true; vouches: false; reason: string } & AndroidKeyFacts)
  | { ok: false; reason: string };

/** Verify `data` (base64url JCS {"x5c": [...]}) for `devicePublicKey`. Never throws. */
export function verifyAndroidKeyAttestation(data: string, devicePublicKey: PublicJwk, opts: AndroidKeyOptions = {}): AndroidKeyResult {
  try {
    return verifyInner(data, devicePublicKey, opts);
  } catch (e) {
    return { ok: false, reason: e instanceof KeyAttestError || e instanceof DerError ? e.message : `malformed attestation: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/** The check the relay and the gateway run on a device's `{format, data}` attestation. */
export function verifyAndroidDeviceAttestation(attestation: { format: string; data: string }, devicePublicKey: PublicJwk, opts: AndroidKeyOptions = {}): AndroidKeyResult {
  if (attestation.format !== ANDROID_KEY_FORMAT) return { ok: false, reason: `unsupported attestation format ${JSON.stringify(attestation.format).slice(0, 80)}` };
  return verifyAndroidKeyAttestation(attestation.data, devicePublicKey, opts);
}

/**
 * Serial numbers Google lists as REVOKED or SUSPENDED in its status list (GOOGLE_ATTESTATION_STATUS_URL,
 * `{"entries": {"<lowercase hex serial>": {"status": ..., "reason": ...}}}`). Throws on a malformed list.
 */
export function parseAttestationStatusList(json: unknown): Set<string> {
  const entries = (json as { entries?: unknown } | null)?.entries;
  if (typeof entries !== "object" || entries === null || Array.isArray(entries)) throw new Error("attestation status list has no entries object");
  const out = new Set<string>();
  for (const [serial, entry] of Object.entries(entries as Record<string, unknown>)) {
    const status = (entry as { status?: unknown } | null)?.status;
    if (status === "REVOKED" || status === "SUSPENDED") out.add(normalizeSerial(serial));
  }
  return out;
}

/** Serial number as the status list writes it: lowercase hex without leading zeros. */
export function normalizeSerial(serial: string): string {
  return serial.toLowerCase().replace(/^0+(?=.)/, "");
}

// ---- internals -----------------------------------------------------------------------------------------

class KeyAttestError extends Error {}
const fail = (m: string): never => {
  throw new KeyAttestError(m);
};

const MAX_CERTS = 10;
const MAX_DATA = 65_536;
const SKEW_MS = 60_000;
const DAY_MS = 86_400_000;

// AuthorizationList tags (Android KeyMint / Keymaster attestation schema).
const TAG = { purpose: 1, algorithm: 2, ecCurve: 10, noAuthRequired: 503, userAuthType: 504, authTimeout: 505, allowWhileOnBody: 506, origin: 702, rootOfTrust: 704, osPatchLevel: 706, attestationApplicationId: 709 } as const;
const PURPOSE_SIGN = 2;
const PURPOSE_VERIFY = 3;
const ALGORITHM_EC = 3;
const EC_CURVE_P256 = 1;
const ORIGIN_GENERATED = 0;
const AUTH_BIOMETRIC = 2;
const BOOT: Record<number, VerifiedBoot> = { 0: "verified", 1: "self_signed", 2: "unverified", 3: "failed" };

const spkiOf = (k: KeyObject) => new Uint8Array(k.export({ type: "spki", format: "der" }));

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] as number) ^ (b[i] as number);
  return d === 0;
}

function decodeChain(data: string): Uint8Array[] {
  if (typeof data !== "string" || data.length === 0 || data.length > MAX_DATA) fail("attestation data is empty or too large");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(base64url.decode(data));
  } catch {
    return fail("attestation data is not base64url UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail("attestation data is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) fail('attestation data is not {"x5c": [...]}');
  const keys = Object.keys(parsed as object);
  if (keys.length !== 1 || keys[0] !== "x5c") fail('attestation data must have exactly the member "x5c"');
  if (!isCanonical(text)) fail("attestation data is not canonical JSON (RFC 8785)");
  const x5c = (parsed as { x5c: unknown }).x5c;
  if (!Array.isArray(x5c) || x5c.length < 2 || x5c.length > MAX_CERTS || !x5c.every((c) => typeof c === "string" && c.length > 0)) fail(`x5c must hold 2 to ${MAX_CERTS} certificates`);
  return (x5c as string[]).map((c) => {
    try {
      return base64url.decode(c);
    } catch {
      return fail("x5c entry is not base64url");
    }
  });
}

/** AuthorizationList → tag number → the item inside `[n] EXPLICIT`. Duplicate tags are malformed. */
function authList(d: Der, which: string): Map<number, Der> {
  const out = new Map<number, Der>();
  for (const item of derSequence(d)) {
    if (item.cls !== 2 || !item.constructed) fail(`${which} has a non-context-specific item`);
    if (out.has(item.num)) fail(`${which} repeats tag ${item.num}`);
    out.set(item.num, derOne(item.value));
  }
  return out;
}

function verifyInner(data: string, devicePublicKey: PublicJwk, opts: AndroidKeyOptions): AndroidKeyResult {
  const now = opts.now ?? Date.now();
  const packages = opts.packages ?? [SIGNETO_ANDROID_PACKAGE];
  const signers = opts.signers ?? SIGNETO_ANDROID_SIGNERS;
  const devSigners = opts.developmentSigners ?? [];
  if (devicePublicKey.kty !== "EC" || devicePublicKey.crv !== "P-256") fail("Android Key Attestation binds ES256 (P-256) device keys only");

  const ders = decodeChain(data);
  const certs = ders.map((d) => {
    try {
      return new X509Certificate(d);
    } catch {
      return fail("x5c entry is not an X.509 certificate");
    }
  });
  const leaf = certs[0] as X509Certificate;

  // (a) chain: each signed by the next, non-leaf certificates are CAs, ends at a pinned root key.
  const rootKeys = (opts.roots ?? GOOGLE_HARDWARE_ATTESTATION_ROOTS).map((p) => new X509Certificate(p).publicKey);
  const rootSpkis = rootKeys.map(spkiOf);
  const last = certs[certs.length - 1] as X509Certificate;
  const lastIsRoot = rootSpkis.some((s) => eq(s, spkiOf(last.publicKey)));
  for (let i = 0; i < certs.length - 1; i++) {
    const c = certs[i] as X509Certificate;
    const issuer = certs[i + 1] as X509Certificate;
    if (!issuer.ca) fail(`certificate ${i + 1} in the chain is not a CA`);
    if (!c.checkIssued(issuer) || !c.verify(issuer.publicKey)) fail(`certificate ${i} is not signed by the next one in the chain`);
  }
  if (!lastIsRoot) {
    if (!last.ca) fail(`certificate ${certs.length - 1} in the chain is not a CA`);
    if (!rootKeys.some((k) => last.verify(k))) fail("certificate chain does not lead to a Google Hardware Attestation root");
  }

  // Validity (the pinned root itself excluded).
  const checked = lastIsRoot ? certs.slice(0, -1) : certs;
  for (const [i, c] of checked.entries()) {
    const from = Date.parse(c.validFrom);
    const to = Date.parse(c.validTo);
    if (opts.validity === "issuance") {
      if (from > now + DAY_MS) fail(`certificate ${i} in the chain is issued in the future`);
    } else if (from > now + SKEW_MS || to < now - SKEW_MS) {
      fail(`certificate ${i} in the chain is not valid now`);
    }
  }

  // Revocation.
  if (opts.revokedSerials) {
    for (const [i, c] of certs.entries()) if (opts.revokedSerials.has(normalizeSerial(c.serialNumber))) fail(`certificate ${i} in the chain is revoked`);
  }

  // (b) the leaf key is the device key.
  const lj = leaf.publicKey.export({ format: "jwk" }) as { kty?: string; crv?: string; x?: string; y?: string };
  if (lj.kty !== "EC" || lj.crv !== "P-256") fail("attested key is not P-256");
  const dk = devicePublicKey as { x: string; y: string };
  if (lj.x !== dk.x || lj.y !== dk.y) fail("attested key is not the device key");

  // (c) KeyDescription in the leaf and nowhere else.
  const ext = certExtension(ders[0] as Uint8Array, KEY_DESCRIPTION_OID);
  if (!ext) fail("leaf certificate has no KeyDescription extension");
  for (let i = 1; i < ders.length; i++) if (certExtension(ders[i] as Uint8Array, KEY_DESCRIPTION_OID)) fail(`certificate ${i} in the chain also carries a KeyDescription`);

  const kd = derSequence(derOne(ext as Uint8Array));
  if (kd.length < 8) fail("KeyDescription is too short");
  const attestationVersion = derInt(kd[0] as Der);
  if (attestationVersion < 3) fail(`attestation version ${attestationVersion} is too old`);
  const attestationLevel = derEnum(kd[1] as Der);
  const keyMintLevel = derEnum(kd[3] as Der);
  derOctets(kd[4] as Der); // attestationChallenge: device-chosen, carries no meaning
  derOctets(kd[5] as Der); // uniqueId
  const sw = authList(kd[6] as Der, "softwareEnforced");
  const hw = authList(kd[7] as Der, "hardwareEnforced");

  // (d) security levels.
  const hwLevel = (n: number) => n === 1 || n === 2;
  if (!hwLevel(attestationLevel) || !hwLevel(keyMintLevel)) fail("key is not in a TEE or StrongBox");

  // (e) hardware-enforced key policy: a generated EC P-256 signing key, biometric for every operation.
  const hwInt = (tag: number) => {
    const d = hw.get(tag);
    return d === undefined ? undefined : derInt(d);
  };
  if (hwInt(TAG.origin) !== ORIGIN_GENERATED) fail("key was not generated in the hardware");
  const purposeItem = hw.get(TAG.purpose);
  const purposes = purposeItem ? derSet(purposeItem).map(derInt) : [];
  if (!purposes.includes(PURPOSE_SIGN) || purposes.some((p) => p !== PURPOSE_SIGN && p !== PURPOSE_VERIFY)) fail("key purpose is not signing only");
  if (hwInt(TAG.algorithm) !== ALGORITHM_EC) fail("key algorithm is not EC");
  const curve = hwInt(TAG.ecCurve);
  if (curve !== undefined && curve !== EC_CURVE_P256) fail("key curve is not P-256");
  if (hw.has(TAG.noAuthRequired)) fail("key does not require user authentication");
  if (hwInt(TAG.userAuthType) !== AUTH_BIOMETRIC) fail("key does not require a biometric (and only a biometric)");
  if (hw.has(TAG.authTimeout)) fail("key authorizes a time window, not each operation");
  if (hw.has(TAG.allowWhileOnBody)) fail("key stays usable while on body");

  // (f) attestationApplicationId: exactly one package, accepted, and exactly one signer digest.
  const appIdItem = sw.get(TAG.attestationApplicationId);
  if (!appIdItem) fail("attestation has no application id");
  const appId = derSequence(derOne(derOctets(appIdItem as Der)));
  if (appId.length < 2) fail("application id is malformed");
  const pkgs = derSet(appId[0] as Der).map((p) => derSequence(p));
  const digests = derSet(appId[1] as Der).map(derOctets);
  if (pkgs.length !== 1) fail("application id must name exactly one package");
  const pkgName = new TextDecoder("utf-8", { fatal: true }).decode(derOctets((pkgs[0] as Der[])[0] as Der));
  if (!packages.includes(pkgName)) fail("attestation is for a different app");
  if (digests.length !== 1 || (digests[0] as Uint8Array).length !== 32) fail("application id must carry exactly one SHA-256 signer digest");
  const signer = hex.encode(digests[0] as Uint8Array);

  // Root of trust (hardware-enforced only).
  const rotItem = hw.get(TAG.rootOfTrust);
  if (!rotItem) fail("attestation has no hardware root of trust");
  const rot = derSequence(rotItem as Der);
  if (rot.length < 3) fail("root of trust is malformed");
  const deviceLocked = derBool(rot[1] as Der);
  const verifiedBoot = BOOT[derEnum(rot[2] as Der)];
  if (!verifiedBoot) fail("root of trust has an unknown verified boot state");
  const patch = hwInt(TAG.osPatchLevel) ?? null;

  const facts: AndroidKeyFacts = {
    package_name: pkgName,
    signer_sha256: signer,
    security_level: keyMintLevel === 2 ? "strongbox" : "tee",
    verified_boot: verifiedBoot as VerifiedBoot,
    device_locked: deviceLocked,
    attestation_version: attestationVersion,
    os_patch_level: patch,
  };
  if (verifiedBoot !== "verified" || !deviceLocked) return { ok: true, vouches: false, reason: "boot is not verified and locked", ...facts };
  if (signers.includes(signer)) return { ok: true, vouches: true, environment: "production", ...facts };
  if (devSigners.includes(signer)) return { ok: true, vouches: true, environment: "development", ...facts };
  return { ok: true, vouches: false, reason: "signed by a signer that is not a production or listed development signer", ...facts };
}
