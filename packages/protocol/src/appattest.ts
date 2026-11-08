// Apple App Attest verification (node only; exported as `@signeto/protocol/appattest`, not from the root,
// so the browser bundles never pull in X.509).
//
// The iOS app attests a fresh App Attest key with clientDataHash = the RFC 7638 thumbprint of the device's
// signing key (Secure Enclave, ES256). A statement that verifies here therefore says: a genuine Apple
// device running a genuine build of the app named by `appId` asked for this exact device key to be
// vouched for. That is what the relay (enrollment, §7.4) and the gateway (pairing, §5.3 point 3) need.
//
// Steps follow Apple's "Validating apps that connect to your server", attestation part:
//   1. x5c = [credCert, intermediate] chains to the pinned Apple App Attestation Root CA, all valid now
//   2. nonce = SHA-256(authData || clientDataHash)
//   3. credCert extension 1.2.840.113635.100.8.2 holds exactly that nonce
//   4. keyId = SHA-256(credCert public key, uncompressed point)
//   5. authData rpIdHash = SHA-256(appId)          (appId = "<TEAM ID>.<bundle id>")
//   6. authData sign count = 0
//   7. aaguid = "appattestdevelop" (development) or "appattest" + 7 zero bytes (production)
//   8. authData credentialId = keyId
// Apple's receipt (attStmt.receipt) is returned for callers that want fraud metrics later; it is not
// needed for any of the checks above.
import { X509Certificate, createHash } from "node:crypto";
import { base64url } from "./encoding.js";
import { jwkThumbprint, type PublicJwk } from "./ids.js";

export const APP_ATTEST_FORMAT = "apple-appattest";

/** The Signeto approver app: team 3PL7Z4G933, bundle id dev.signeto.approver. */
export const SIGNETO_APP_ID = "3PL7Z4G933.dev.signeto.approver";

/**
 * Apple App Attestation Root CA, from https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
 * SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32,
 * valid 2020-03-18 to 2045-03-15. P-384.
 */
export const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`;

const NONCE_OID = "1.2.840.113635.100.8.2";
const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");
const AAGUID_PRODUCTION = new Uint8Array([...new TextEncoder().encode("appattest"), 0, 0, 0, 0, 0, 0, 0]);

export type AppAttestEnvironment = "production" | "development";

export interface AppAttestOptions {
  /** Accepted "<TEAM ID>.<bundle id>" values. Default: [SIGNETO_APP_ID]. */
  appIds?: readonly string[];
  /** Accept attestations from development builds (aaguid "appattestdevelop"). Default true. */
  allowDevelopment?: boolean;
  /** Validity reference time, ms. Default Date.now(). */
  now?: number;
  /**
   * "now" (default): every certificate must be valid at `now`, for a statement made moments ago (relay
   * enrollment). "issuance": the chain must have been valid when Apple issued the credential certificate
   * and that issuance must not be in the future. The gateway uses this at pairing, because the app sends
   * the statement it made at enrollment, possibly long ago, and an attestation does not stop being true
   * when its certificate expires: its nonce still binds that device key.
   */
  validity?: "now" | "issuance";
  /** Trusted roots (PEM). Default: the Apple App Attestation Root CA only. Tests pass their own. */
  roots?: readonly string[];
}

export type AppAttestResult =
  | { ok: true; environment: AppAttestEnvironment; app_id: string; key_id: string; receipt: Uint8Array | null }
  | { ok: false; reason: string };

/** Verify an App Attest attestation object against `clientDataHash` (the bytes passed to attestKey). */
export function verifyAppAttest(attestationObject: Uint8Array, clientDataHash: Uint8Array, opts: AppAttestOptions = {}): AppAttestResult {
  try {
    return verifyInner(attestationObject, clientDataHash, opts);
  } catch (e) {
    return { ok: false, reason: e instanceof AttestError ? e.message : `malformed attestation: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/**
 * The check the relay and the gateway run on a device's `{format, data}` attestation: App Attest over the
 * device key's RFC 7638 thumbprint. Only ES256 (P-256) device keys can be attested.
 */
export function verifyDeviceAttestation(attestation: { format: string; data: string }, devicePublicKey: PublicJwk, opts: AppAttestOptions = {}): AppAttestResult {
  if (attestation.format !== APP_ATTEST_FORMAT) return { ok: false, reason: `unsupported attestation format ${JSON.stringify(attestation.format).slice(0, 80)}` };
  if (devicePublicKey.kty !== "EC" || devicePublicKey.crv !== "P-256") return { ok: false, reason: "App Attest binds ES256 (P-256) device keys only" };
  let obj: Uint8Array;
  try {
    obj = base64url.decode(attestation.data);
  } catch {
    return { ok: false, reason: "attestation data is not base64url" };
  }
  return verifyAppAttest(obj, jwkThumbprint(devicePublicKey), opts);
}

// ---- internals -----------------------------------------------------------------------------------------

class AttestError extends Error {}
const fail = (m: string): never => {
  throw new AttestError(m);
};

const sha256 = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] as number) ^ (b[i] as number);
  return d === 0;
}

function verifyInner(attestationObject: Uint8Array, clientDataHash: Uint8Array, opts: AppAttestOptions): AppAttestResult {
  const appIds = opts.appIds ?? [SIGNETO_APP_ID];
  const allowDev = opts.allowDevelopment ?? true;
  const now = opts.now ?? Date.now();
  if (clientDataHash.length !== 32) fail("clientDataHash must be 32 bytes");

  const top = cborDecode(attestationObject);
  if (!(top instanceof Map)) fail("attestation object is not a CBOR map");
  const m = top as Map<unknown, unknown>;
  if (m.get("fmt") !== APP_ATTEST_FORMAT) fail(`fmt is not ${APP_ATTEST_FORMAT}`);
  const attStmt = m.get("attStmt");
  const authData = m.get("authData");
  if (!(attStmt instanceof Map)) fail("attStmt missing");
  if (!(authData instanceof Uint8Array)) fail("authData missing");
  const stmt = attStmt as Map<unknown, unknown>;
  const ad = authData as Uint8Array;
  const x5c = stmt.get("x5c");
  if (!Array.isArray(x5c) || x5c.length < 2 || !x5c.every((c) => c instanceof Uint8Array)) fail("x5c must hold the credential and intermediate certificates");
  const receipt = stmt.get("receipt");

  // 1. chain: credCert ← intermediate ← pinned root, every certificate valid at `now`.
  const [credDer, interDer] = x5c as Uint8Array[];
  const cred = new X509Certificate(credDer as Uint8Array);
  const inter = new X509Certificate(interDer as Uint8Array);
  const roots = (opts.roots ?? [APPLE_APP_ATTEST_ROOT_CA]).map((p) => new X509Certificate(p));
  const issued = Date.parse(cred.validFrom);
  if (!(issued <= now)) fail("credential certificate is issued in the future");
  const at = opts.validity === "issuance" ? issued : now;
  const valid = (c: X509Certificate, what: string) => {
    if (at < Date.parse(c.validFrom) || at > Date.parse(c.validTo)) fail(`${what} certificate is not valid ${opts.validity === "issuance" ? "at issuance" : "now"}`);
  };
  valid(cred, "credential");
  valid(inter, "intermediate");
  if (!inter.ca) fail("intermediate certificate is not a CA");
  if (!cred.checkIssued(inter) || !cred.verify(inter.publicKey)) fail("credential certificate is not signed by the intermediate");
  const root = roots.find((r) => inter.checkIssued(r) && inter.verify(r.publicKey));
  if (!root) fail("certificate chain does not lead to the Apple App Attestation Root CA");
  valid(root as X509Certificate, "root");

  // 2–3. nonce in the credential certificate's extension.
  const nonce = sha256(ad, clientDataHash);
  const ext = certExtension(new Uint8Array(cred.raw), NONCE_OID);
  if (!ext) fail("credential certificate has no App Attest nonce extension");
  // extnValue = SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
  const seq = derRead(ext as Uint8Array, 0);
  if (seq.tag !== 0x30) fail("nonce extension is not a SEQUENCE");
  const tagged = derRead(seq.value, 0);
  if (tagged.tag !== 0xa1) fail("nonce extension has no [1] element");
  const oct = derRead(tagged.value, 0);
  if (oct.tag !== 0x04 || !eq(oct.value, nonce)) fail("nonce does not match authData and the device key");

  // 4. keyId = SHA-256 of the credential public key as an uncompressed point.
  const jwk = cred.publicKey.export({ format: "jwk" }) as { kty?: string; crv?: string; x?: string; y?: string };
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) fail("credential key is not P-256");
  const point = new Uint8Array([4, ...base64url.decode(jwk.x as string), ...base64url.decode(jwk.y as string)]);
  const keyId = sha256(point);

  // 5–8. authData: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId(len) …
  if (ad.length < 55) fail("authData too short");
  const rpIdHash = ad.subarray(0, 32);
  const appId = appIds.find((id) => eq(sha256(new TextEncoder().encode(id)), rpIdHash));
  if (!appId) fail("attestation is for a different app");
  const view = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
  if (view.getUint32(33) !== 0) fail("sign count is not zero");
  const aaguid = ad.subarray(37, 53);
  const environment: AppAttestEnvironment | undefined = eq(aaguid, AAGUID_PRODUCTION) ? "production" : eq(aaguid, AAGUID_DEVELOPMENT) ? "development" : undefined;
  if (!environment) fail("aaguid is not an App Attest environment");
  if (environment === "development" && !allowDev) fail("development-build attestations are not accepted");
  const credLen = view.getUint16(53);
  if (ad.length < 55 + credLen) fail("authData credential id truncated");
  if (!eq(ad.subarray(55, 55 + credLen), keyId)) fail("credential id does not match the credential certificate key");

  return { ok: true, environment: environment as AppAttestEnvironment, app_id: appId as string, key_id: base64url.encode(keyId), receipt: receipt instanceof Uint8Array ? receipt : null };
}

// ---- DER (just enough to find one extension) -----------------------------------------------------------

interface Der {
  tag: number;
  value: Uint8Array;
  end: number;
}

function derRead(buf: Uint8Array, pos: number): Der {
  if (pos + 2 > buf.length) fail("DER truncated");
  const tag = buf[pos] as number;
  let len = buf[pos + 1] as number;
  let off = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + n > buf.length) fail("DER length invalid");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (buf[off + i] as number);
    off += n;
  }
  if (off + len > buf.length) fail("DER value truncated");
  return { tag, value: buf.subarray(off, off + len), end: off + len };
}

function derChildren(buf: Uint8Array): Der[] {
  const out: Der[] = [];
  for (let p = 0; p < buf.length; ) {
    const d = derRead(buf, p);
    out.push(d);
    p = d.end;
  }
  return out;
}

function oidString(b: Uint8Array): string {
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
function certExtension(certDer: Uint8Array, oid: string): Uint8Array | undefined {
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

// ---- CBOR (the subset an attestation object uses) ------------------------------------------------------

function cborDecode(buf: Uint8Array): unknown {
  let pos = 0;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const need = (n: number) => {
    if (pos + n > buf.length) fail("CBOR truncated");
  };
  const arg = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) return need(1), buf[pos++] as number;
    if (info === 25) return need(2), (pos += 2), view.getUint16(pos - 2);
    if (info === 26) return need(4), (pos += 4), view.getUint32(pos - 4);
    if (info === 27) {
      need(8);
      const v = view.getBigUint64(pos);
      pos += 8;
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail("CBOR integer too large");
      return Number(v);
    }
    return fail("CBOR indefinite lengths are not supported");
  };
  const item = (depth: number): unknown => {
    if (depth > 16) fail("CBOR nested too deeply");
    need(1);
    const b = buf[pos++] as number;
    const major = b >> 5;
    const n = arg(b & 0x1f);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
        need(n);
        return buf.slice(pos, (pos += n));
      case 3:
        need(n);
        return new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(pos, (pos += n)));
      case 4: {
        const a: unknown[] = [];
        for (let i = 0; i < n; i++) a.push(item(depth + 1));
        return a;
      }
      case 5: {
        const mp = new Map<unknown, unknown>();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          mp.set(k, item(depth + 1));
        }
        return mp;
      }
      default:
        return fail(`CBOR major type ${major} is not supported`);
    }
  };
  const v = item(0);
  if (pos !== buf.length) fail("trailing bytes after CBOR item");
  return v;
}
