// docs/protocol.md §7.2: device-signed account messages. A paired, hardware-attested device may revoke a
// gateway of its own account with an object signed by its device key, the same key and the same
// user-presence gate (Face ID, biometric unlock) as a receipt (§4.2) or a freeze object (§7.9).
//
// Signing input: UTF-8 of JCS {gateway_id, purpose: "gateway.revoke", signed_at}. `purpose` keeps the
// object apart from every other device-signed object (receipts carry `canonical_bytes_sha256` and
// `decision`, freeze objects `frozen`), so a signature made for one can never verify as another.
import { canonicalize } from "./jcs.js";
import { base64url, utf8 } from "./encoding.js";
import type { PrivateJwk, PublicJwk } from "./ids.js";
import { GATEWAY_ID_RE } from "./ids.js";
import { signWithJwk, verifyWithJwk } from "./signing.js";
import { CLOCK_SKEW_MS, TIMESTAMP_RE, parseTimestamp } from "./timestamps.js";

export const GATEWAY_REVOKE_PURPOSE = "gateway.revoke";

/** `POST /v1/gateways/{gateway_id}/revoke` body (§7.2). */
export interface GatewayRevokeObject {
  gateway_id: string;
  signed_at: string;
  /** base64url (no padding) of the device key's signature over `gatewayRevokeSigningInput`. */
  signature: string;
}

export function gatewayRevokeSigningInput(f: { gateway_id: string; signed_at: string }): string {
  return canonicalize({ gateway_id: f.gateway_id, purpose: GATEWAY_REVOKE_PURPOSE, signed_at: f.signed_at });
}

/** Sign a gateway revocation with the device key (tests, the CLI device). */
export function signGatewayRevoke(f: { gateway_id: string; signed_at: string }, devicePrivateJwk: PrivateJwk): GatewayRevokeObject {
  const { signature } = signWithJwk(utf8.encode(gatewayRevokeSigningInput(f)), devicePrivateJwk);
  return { gateway_id: f.gateway_id, signed_at: f.signed_at, signature: base64url.encode(signature) };
}

export type VerifyGatewayRevokeResult = { ok: true; signed_at_ms: number } | { ok: false; code: "request_malformed" | "signature_invalid" | "clock_skew" };

/**
 * Relay side: the object is well formed, names `gateway_id` (the path), verifies with the device's key,
 * and `signed_at` is within ±60 s of `now`. Replay inside the window is the caller's to refuse.
 */
export function verifyGatewayRevoke(o: GatewayRevokeObject, opts: { gateway_id: string; public_key: PublicJwk; now: number }): VerifyGatewayRevokeResult {
  if (!GATEWAY_ID_RE.test(o.gateway_id) || o.gateway_id !== opts.gateway_id || !TIMESTAMP_RE.test(o.signed_at) || !/^[A-Za-z0-9_-]{86}$/.test(o.signature)) return { ok: false, code: "request_malformed" };
  const at = parseTimestamp(o.signed_at);
  if (at === undefined) return { ok: false, code: "request_malformed" };
  let good = false;
  try {
    good = verifyWithJwk(utf8.encode(gatewayRevokeSigningInput(o)), base64url.decode(o.signature), opts.public_key);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, code: "signature_invalid" };
  if (Math.abs(opts.now - at) > CLOCK_SKEW_MS) return { ok: false, code: "clock_skew" };
  return { ok: true, signed_at_ms: at };
}
