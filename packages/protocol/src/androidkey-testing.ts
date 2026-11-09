// Test support, exported as `@signeto/protocol/androidkey/testing`: builds Android Key Attestation chains
// shaped like the Keystore's (root → intermediate(s) → leaf with the KeyDescription extension) under a
// throwaway test root. Pass TEST_ANDROID_ROOT_PEM as `roots` and TEST_ANDROID_SIGNER as a signer to accept
// them. Never trusted by default: the verifier pins Google's roots unless told otherwise.
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { canonicalize } from "./jcs.js";
import { base64url } from "./encoding.js";
import type { PublicJwk } from "./ids.js";
import { ANDROID_KEY_FORMAT, KEY_DESCRIPTION_OID, SIGNETO_ANDROID_PACKAGE } from "./androidkey.js";
import { bool, ctx, derToPem, enumerated, int, makeCert, nul, octet, oid, seq, set } from "./der-build.js";

const ec = (curve: string) => generateKeyPairSync("ec", { namedCurve: curve });
const rootKeys = ec("secp384r1");
const ROOT = "Test Key Attestation Root";
const rootDer = makeCert({ subject: ROOT, issuer: ROOT, publicKey: rootKeys.publicKey, signer: rootKeys.privateKey, ca: true, serial: 1 });
/** The same root key under an expired certificate, as older phones return Google's reissued RSA root. */
const expiredRootDer = makeCert({ subject: ROOT, issuer: ROOT, publicKey: rootKeys.publicKey, signer: rootKeys.privateKey, ca: true, serial: 9, notBefore: new Date("2016-01-01T00:00:00Z"), notAfter: new Date("2026-01-01T00:00:00Z") });
export const TEST_ANDROID_ROOT_PEM = derToPem(rootDer);

/** SHA-256 (lowercase hex) of a pretend signing certificate; pass it as a production or development signer. */
export const TEST_ANDROID_SIGNER = createHash("sha256").update("signeto test signing certificate").digest("hex");
export const TEST_ANDROID_OTHER_SIGNER = createHash("sha256").update("someone else's signing certificate").digest("hex");

export interface AndroidFixtureOptions {
  attestationVersion?: number;
  /** 0 Software, 1 TrustedEnvironment, 2 StrongBox. Default 1. */
  attestationSecurityLevel?: number;
  keyMintSecurityLevel?: number;
  origin?: number;
  purposes?: number[];
  algorithm?: number;
  /** null leaves the tag out. Default 1 (P_256). */
  ecCurve?: number | null;
  noAuthRequired?: boolean;
  userAuthType?: number;
  authTimeout?: number;
  allowWhileOnBody?: boolean;
  verifiedBootState?: number;
  deviceLocked?: boolean;
  /** Where rootOfTrust goes. Default "hardware". */
  rootOfTrustIn?: "hardware" | "software";
  /** Where attestationApplicationId goes. Default "software", as the OS supplies it. */
  appIdIn?: "hardware" | "software";
  packages?: string[];
  /** Lowercase hex SHA-256 signer digests. Default [TEST_ANDROID_SIGNER]. */
  signers?: string[];
  /** Put an unrelated key in the leaf (the statement is for another key). */
  leafKeyMismatch?: boolean;
  /** Sign the intermediate with a key that is not the root's. */
  rogueIntermediate?: boolean;
  /** The intermediate lacks basicConstraints CA. */
  intermediateNotCa?: boolean;
  /** Also put a KeyDescription on the intermediate. */
  keyDescriptionOnIntermediate?: boolean;
  /** 3: leaf, intermediate, root. 4: leaf, attestation key, intermediate, root. Default 4. */
  chainLength?: 3 | 4;
  /** Leave the root out (the chain ends at a certificate the root signed). Default false. */
  omitRoot?: boolean;
  /** End the chain with an expired certificate for the same root key. */
  expiredRootCopy?: boolean;
  intermediateNotBefore?: Date;
  intermediateNotAfter?: Date;
  /** Serial numbers. Defaults: leaf 1, attestation key 0x0a1b2c, intermediate 0x3d4e5f. */
  leafSerial?: number;
  intermediateSerial?: number;
  /** Bytes of `data` before base64url (to test malformed input). */
  rawData?: string;
}

export interface AndroidFixture {
  rootPem: string;
  devicePublicKey: PublicJwk;
  attestation: { format: string; data: string };
  chain: Uint8Array[];
}

function authList(items: [number, Uint8Array][]): Uint8Array {
  return seq(...items.sort((a, b) => a[0] - b[0]).map(([n, v]) => ctx(n, v)));
}

export function makeAndroidAttestation(o: AndroidFixtureOptions = {}): AndroidFixture {
  const device = ec("prime256v1");
  const devicePublicKey = device.publicKey.export({ format: "jwk" }) as PublicJwk;
  const leafKey = o.leafKeyMismatch ? ec("prime256v1").publicKey : device.publicKey;

  const hw: [number, Uint8Array][] = [];
  const sw: [number, Uint8Array][] = [];
  hw.push([1, set(...(o.purposes ?? [2]).map(int))]);
  hw.push([2, int(o.algorithm ?? 3)]);
  hw.push([3, int(256)]);
  hw.push([5, set(int(4))]);
  if (o.ecCurve !== null) hw.push([10, int(o.ecCurve ?? 1)]);
  if (o.noAuthRequired) hw.push([503, nul()]);
  hw.push([504, int(o.userAuthType ?? 2)]);
  if (o.authTimeout !== undefined) hw.push([505, int(o.authTimeout)]);
  if (o.allowWhileOnBody) hw.push([506, nul()]);
  hw.push([702, int(o.origin ?? 0)]);
  const rot = seq(octet(new Uint8Array(randomBytes(32))), bool(o.deviceLocked ?? true), enumerated(o.verifiedBootState ?? 0), octet(new Uint8Array(randomBytes(32))));
  (o.rootOfTrustIn === "software" ? sw : hw).push([704, rot]);
  hw.push([705, int(160000)]);
  hw.push([706, int(202610)]);
  const pkgs = (o.packages ?? [SIGNETO_ANDROID_PACKAGE]).map((p) => seq(octet(new TextEncoder().encode(p)), int(1)));
  const digests = (o.signers ?? [TEST_ANDROID_SIGNER]).map((h) => octet(new Uint8Array(Buffer.from(h, "hex"))));
  const appId = octet(seq(set(...pkgs), set(...digests)));
  (o.appIdIn === "hardware" ? hw : sw).push([709, appId]);
  sw.push([701, int(Date.parse("2026-11-01T00:00:00Z"))]); // creationDateTime, a tag the verifier ignores

  const level = o.attestationSecurityLevel ?? 1;
  const keyDescription = seq(
    int(o.attestationVersion ?? 300),
    enumerated(level),
    int(300),
    enumerated(o.keyMintSecurityLevel ?? level),
    octet(new Uint8Array(randomBytes(32))), // challenge: device-chosen
    octet(new Uint8Array(0)),
    authList(sw),
    authList(hw),
  );
  const kdExt = seq(oid(KEY_DESCRIPTION_OID), octet(keyDescription));

  const interKeys = ec("prime256v1");
  const interSigner = o.rogueIntermediate ? ec("secp384r1").privateKey : rootKeys.privateKey;
  const interDer = makeCert({
    subject: "Test Key Attestation Intermediate",
    issuer: ROOT,
    publicKey: interKeys.publicKey,
    signer: interSigner,
    ca: !o.intermediateNotCa,
    serial: o.intermediateSerial ?? 0x3d4e5f,
    ...(o.keyDescriptionOnIntermediate ? { extensions: [kdExt] } : {}),
    ...(o.intermediateNotBefore ? { notBefore: o.intermediateNotBefore } : {}),
    ...(o.intermediateNotAfter ? { notAfter: o.intermediateNotAfter } : {}),
  });
  const chain: Uint8Array[] = [];
  let leafIssuer = "Test Key Attestation Intermediate";
  let leafSigner = interKeys.privateKey;
  let middle: Uint8Array[] = [interDer];
  if ((o.chainLength ?? 4) === 4) {
    const attKeys = ec("prime256v1");
    const attDer = makeCert({ subject: "Test Device Attestation Key", issuer: "Test Key Attestation Intermediate", publicKey: attKeys.publicKey, signer: interKeys.privateKey, ca: true, serial: 0x0a1b2c });
    middle = [attDer, interDer];
    leafIssuer = "Test Device Attestation Key";
    leafSigner = attKeys.privateKey;
  }
  const leafDer = makeCert({
    subject: "Android Keystore Key",
    issuer: leafIssuer,
    publicKey: leafKey,
    signer: leafSigner,
    serial: o.leafSerial ?? 1,
    extensions: [kdExt],
    notBefore: new Date("1970-01-01T00:00:00Z"),
    notAfter: new Date("2048-01-01T00:00:00Z"),
  });
  chain.push(leafDer, ...middle);
  if (!o.omitRoot) chain.push(o.expiredRootCopy ? expiredRootDer : rootDer);

  const data = o.rawData !== undefined ? base64url.encode(new TextEncoder().encode(o.rawData)) : base64url.encode(new TextEncoder().encode(canonicalize({ x5c: chain.map((c) => base64url.encode(c)) })));
  return { rootPem: TEST_ANDROID_ROOT_PEM, devicePublicKey, attestation: { format: ANDROID_KEY_FORMAT, data }, chain };
}
