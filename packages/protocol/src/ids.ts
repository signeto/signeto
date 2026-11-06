// docs/protocol.md §2.6 (action_id), §5.1 (gateway_id / device_id from RFC 7638 thumbprints).
import { canonicalize } from "./jcs.js";
import { base64url, hex, randomBytesU8, sha256 } from "./encoding.js";

export interface EcPublicJwk { kty: "EC"; crv: "P-256"; x: string; y: string }
export interface OkpPublicJwk { kty: "OKP"; crv: "Ed25519"; x: string }
export type PublicJwk = EcPublicJwk | OkpPublicJwk;
export type PrivateJwk = (EcPublicJwk & { d: string }) | (OkpPublicJwk & { d: string });

export type SignatureAlg = "ES256" | "Ed25519";

/** Algorithm implied by a JWK's key type. Only the two from ADR-0002. */
export function algForJwk(jwk: { kty: string; crv?: string }): SignatureAlg {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "Ed25519";
  throw new Error(`unsupported key type ${jwk.kty}/${jwk.crv ?? ""}`);
}

/** RFC 7638 thumbprint: SHA-256 over the JCS of the required public members. */
export function jwkThumbprint(jwk: PublicJwk | PrivateJwk): Uint8Array {
  const members: Record<string, string> =
    jwk.kty === "EC" ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return sha256(canonicalize(members));
}

export function gatewayIdFromJwk(jwk: PublicJwk | PrivateJwk): string {
  return "gw_" + base64url.encode(jwkThumbprint(jwk));
}
export function deviceIdFromJwk(jwk: PublicJwk | PrivateJwk): string {
  return "dev_" + base64url.encode(jwkThumbprint(jwk));
}

/** Human fingerprint: first 16 hex chars of the thumbprint in groups of four. */
export function fingerprint(jwk: PublicJwk | PrivateJwk): string {
  const h = hex.encode(jwkThumbprint(jwk)).slice(0, 16);
  return [h.slice(0, 4), h.slice(4, 8), h.slice(8, 12), h.slice(12, 16)].join(" ");
}

export const GATEWAY_ID_RE = /^gw_[A-Za-z0-9_-]{43}$/;
export const DEVICE_ID_RE = /^dev_[A-Za-z0-9_-]{43}$/;
export const ACTION_ID_RE = /^act_[0-9A-HJKMNP-TV-Z]{26}$/;
export const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

/** 16 CSPRNG bytes, base64url without padding (22 chars). */
export function newNonce(rng: (n: number) => Uint8Array = randomBytesU8): string {
  return base64url.encode(rng(16));
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** ULID: 48-bit ms timestamp + 80 random bits, Crockford base32, 26 chars. */
export function ulid(time: number = Date.now(), rng: (n: number) => Uint8Array = randomBytesU8): string {
  let t = Math.floor(time);
  let ts = "";
  for (let i = 0; i < 10; i++) {
    ts = CROCKFORD[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  const r = rng(10);
  // 80 bits -> 16 chars of 5 bits
  let bits = 0n;
  for (const b of r) bits = (bits << 8n) | BigInt(b);
  let rs = "";
  for (let i = 0; i < 16; i++) {
    rs = CROCKFORD[Number(bits & 31n)] + rs;
    bits >>= 5n;
  }
  return ts + rs;
}

export function newActionId(time?: number, rng?: (n: number) => Uint8Array): string {
  return "act_" + ulid(time, rng);
}
