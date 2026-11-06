// docs/protocol.md §7.5: gateway_signature on every approval request, whatever the transport.
import { canonicalize } from "./jcs.js";
import { base64url, sha256hex, utf8 } from "./encoding.js";
import type { PrivateJwk, PublicJwk } from "./ids.js";
import { signWithJwk, verifyWithJwk } from "./signing.js";
import { parseCanonicalAction } from "./action.js";

export interface ApprovalRequestSigningFields {
  action_id: string;
  canonical_bytes_sha256: string;
  expires_at: string;
  gateway_id: string;
  nonce: string;
}

export function approvalRequestSigningInput(f: ApprovalRequestSigningFields): string {
  return canonicalize({
    action_id: f.action_id,
    canonical_bytes_sha256: f.canonical_bytes_sha256,
    expires_at: f.expires_at,
    gateway_id: f.gateway_id,
    nonce: f.nonce,
  });
}

export interface ApprovalRequest {
  action_id: string;
  canonical_bytes: string;
  expires_at: string;
  gateway_signature: string;
  [extra: string]: unknown;
}

/** Derive the signing fields from the request body itself (nonce and gateway_id come from inside canonical_bytes). */
export function approvalRequestFields(req: { action_id: string; canonical_bytes: string; expires_at: string }): ApprovalRequestSigningFields | null {
  const parsed = parseCanonicalAction(req.canonical_bytes);
  if (!parsed.ok) return null;
  const a = parsed.value.action;
  if (a.expires_at !== req.expires_at) return null;
  return {
    action_id: req.action_id,
    canonical_bytes_sha256: parsed.value.canonical_bytes_sha256,
    expires_at: a.expires_at,
    gateway_id: a.requester.gateway_id,
    nonce: a.nonce,
  };
}

export function signApprovalRequest<T extends { action_id: string; canonical_bytes: string; expires_at: string }>(req: T, gatewayPrivateJwk: PrivateJwk): T & { gateway_signature: string } {
  const f = approvalRequestFields(req);
  if (!f) throw new Error("request does not carry a valid canonical action");
  const { signature } = signWithJwk(utf8.encode(approvalRequestSigningInput(f)), gatewayPrivateJwk);
  return { ...req, gateway_signature: base64url.encode(signature) };
}

export type VerifyRequestResult = { ok: true; gateway_id: string; canonical_bytes_sha256: string } | { ok: false; code: "gateway_signature_invalid" | "gateway_not_pinned" | "request_malformed" };

/**
 * Device side: before rendering, rebuild the signing input from the request as received and verify
 * against the gateway key pinned at pairing. `pinned` maps gateway_id → public JWK.
 */
export function verifyApprovalRequest(req: ApprovalRequest, pinned: ReadonlyMap<string, PublicJwk> | Record<string, PublicJwk>): VerifyRequestResult {
  const f = approvalRequestFields(req);
  if (!f) return { ok: false, code: "request_malformed" };
  const key = pinned instanceof Map ? pinned.get(f.gateway_id) : (pinned as Record<string, PublicJwk>)[f.gateway_id];
  if (!key) return { ok: false, code: "gateway_not_pinned" };
  let sig: Uint8Array;
  try {
    sig = base64url.decode(req.gateway_signature);
  } catch {
    return { ok: false, code: "gateway_signature_invalid" };
  }
  if (!verifyWithJwk(utf8.encode(approvalRequestSigningInput(f)), sig, key)) return { ok: false, code: "gateway_signature_invalid" };
  return { ok: true, gateway_id: f.gateway_id, canonical_bytes_sha256: sha256hex(req.canonical_bytes) };
}
