// docs/protocol.md §4: receipts, signing input, standalone verification (steps 1, 2, 9, 10, 11, 12 and §4.4).
import { z } from "zod";
import { canonicalize } from "./jcs.js";
import { base64url, concat, sha256, sha256hex, timingSafeEqualStr, utf8 } from "./encoding.js";
import { ACTION_ID_RE, DEVICE_ID_RE, algForJwk, type PrivateJwk, type PublicJwk, type SignatureAlg } from "./ids.js";
import { publicKeyFromJwk, signWithJwk, verifyRaw } from "./signing.js";
import { CLOCK_SKEW_MS, TIMESTAMP_RE, parseTimestamp } from "./timestamps.js";

export const RECEIPT_VERSION = "1.0";
export const RECEIPT_MAJOR = 1;

export const ReceiptSchema = z
  .object({
    receipt_version: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/),
    action_id: z.string().regex(ACTION_ID_RE),
    decision: z.enum(["approve", "deny"]),
    reason: z.string().max(512).optional(),
    approver_id: z.string().min(1).max(64),
    device_id: z.string().regex(DEVICE_ID_RE),
    alg: z.enum(["ES256", "Ed25519"]),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
    signed_at: z.string().regex(TIMESTAMP_RE),
    canonical_bytes_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    webauthn: z
      .object({ authenticator_data: z.string(), client_data_json: z.string() })
      .strict()
      .optional(),
    relay_id: z.string().max(128).optional(),
  })
  .strict()
  .superRefine((r, ctx) => {
    if (r.reason !== undefined && Buffer.byteLength(r.reason, "utf8") > 512)
      ctx.addIssue({ code: "custom", path: ["reason"], message: "reason exceeds 512 UTF-8 bytes" });
    if (r.webauthn !== undefined && r.alg !== "ES256")
      ctx.addIssue({ code: "custom", path: ["alg"], message: "webauthn receipts must use ES256" });
  });

export type Receipt = z.infer<typeof ReceiptSchema>;
export type Decision = Receipt["decision"];

export interface SigningInputFields {
  canonical_bytes_sha256: string;
  decision: Decision;
  reason?: string | undefined;
  signed_at: string;
}

/** §4.2: JCS of {canonical_bytes_sha256, decision, reason?, signed_at}; `reason` omitted entirely when absent. */
export function receiptSigningInput(f: SigningInputFields): string {
  const obj: Record<string, string> = { canonical_bytes_sha256: f.canonical_bytes_sha256, decision: f.decision, signed_at: f.signed_at };
  if (f.reason !== undefined) obj.reason = f.reason;
  return canonicalize(obj);
}

/** §4.4: WebAuthn challenge is the 32-byte SHA-256 of the signing input. */
export function webauthnChallenge(signingInput: string): Uint8Array {
  return sha256(signingInput);
}

export interface SignReceiptInput {
  action_id: string;
  canonical_bytes_sha256: string;
  decision: Decision;
  reason?: string | undefined;
  approver_id: string;
  device_id: string;
  signed_at: string;
}

/** Software signer (CLI, tests). Hardware and WebAuthn signers produce the same fields their own way. */
export function signReceipt(input: SignReceiptInput, devicePrivateJwk: PrivateJwk): Receipt {
  const si = receiptSigningInput(input);
  const { alg, signature } = signWithJwk(utf8.encode(si), devicePrivateJwk);
  const r: Receipt = {
    receipt_version: RECEIPT_VERSION,
    action_id: input.action_id,
    decision: input.decision,
    ...(input.reason !== undefined ? { reason: input.reason } : {}),
    approver_id: input.approver_id,
    device_id: input.device_id,
    alg,
    signature: base64url.encode(signature),
    signed_at: input.signed_at,
    canonical_bytes_sha256: input.canonical_bytes_sha256,
  };
  return ReceiptSchema.parse(r);
}

export type VerifyCode =
  | "receipt_malformed"
  | "receipt_version_unsupported"
  | "alg_not_allowed"
  | "hash_mismatch"
  | "clock_skew"
  | "invalid_signature"
  | "webauthn_type"
  | "webauthn_challenge"
  | "webauthn_origin"
  | "webauthn_rp_id"
  | "webauthn_user_flags";

export interface WebAuthnPolicy {
  /** Allowed approver origins. Empty rejects every WebAuthn receipt (§4.4 step 3). */
  allowed_origins: readonly string[];
  rp_id: string;
  /** MUST be true for Tier 3. */
  require_user_verified: boolean;
}

export interface VerifyReceiptInput {
  receipt: unknown;
  /** Either the canonical bytes themselves or their SHA-256 (the gateway hashes its own stored bytes). */
  canonical_bytes?: string;
  canonical_bytes_sha256?: string;
  issued_at: string;
  expires_at: string;
  /** The key pinned for `receipt.device_id` at pairing. */
  device_public_key: PublicJwk;
  webauthn?: WebAuthnPolicy;
}

export type VerifyResult = { ok: true; receipt: Receipt; signing_input: string } | { ok: false; code: VerifyCode; detail?: string };

/**
 * Standalone receipt verification. Does not consult an action store, device registry, policy or nonce store;
 * the gateway runs those steps around this (§4.5 steps 3–8, 13–15).
 */
export function verifyReceipt(input: VerifyReceiptInput): VerifyResult {
  const parsed = ReceiptSchema.safeParse(input.receipt);
  if (!parsed.success) return { ok: false, code: "receipt_malformed", detail: parsed.error.issues.map((i) => i.message).join("; ") };
  const r = parsed.data;
  if (Number(r.receipt_version.split(".")[0]) !== RECEIPT_MAJOR) return { ok: false, code: "receipt_version_unsupported" };

  let keyAlg: SignatureAlg;
  try {
    keyAlg = algForJwk(input.device_public_key);
  } catch {
    return { ok: false, code: "alg_not_allowed", detail: "pinned key type unsupported" };
  }
  if (keyAlg !== r.alg) return { ok: false, code: "alg_not_allowed" };

  const ownHash = input.canonical_bytes_sha256 ?? (input.canonical_bytes !== undefined ? sha256hex(input.canonical_bytes) : undefined);
  if (ownHash === undefined) throw new TypeError("canonical_bytes or canonical_bytes_sha256 is required");
  if (!timingSafeEqualStr(ownHash, r.canonical_bytes_sha256)) return { ok: false, code: "hash_mismatch" };

  const signedAt = parseTimestamp(r.signed_at);
  const issuedAt = parseTimestamp(input.issued_at);
  const expiresAt = parseTimestamp(input.expires_at);
  if (signedAt === undefined || issuedAt === undefined || expiresAt === undefined) return { ok: false, code: "receipt_malformed", detail: "timestamp" };
  if (signedAt < issuedAt - CLOCK_SKEW_MS || signedAt > expiresAt + CLOCK_SKEW_MS) return { ok: false, code: "clock_skew" };

  const si = receiptSigningInput({ canonical_bytes_sha256: ownHash, decision: r.decision, reason: r.reason, signed_at: r.signed_at });
  let sig: Uint8Array;
  try {
    sig = base64url.decode(r.signature);
  } catch {
    return { ok: false, code: "receipt_malformed", detail: "signature encoding" };
  }
  const pub = publicKeyFromJwk(input.device_public_key);

  if (r.webauthn !== undefined) {
    const wa = verifyWebAuthn(r.webauthn, si, sig, input.webauthn, pub);
    if (wa !== null) return wa;
    return { ok: true, receipt: r, signing_input: si };
  }
  if (!verifyRaw(r.alg, utf8.encode(si), sig, pub)) return { ok: false, code: "invalid_signature" };
  return { ok: true, receipt: r, signing_input: si };
}

function verifyWebAuthn(
  wa: { authenticator_data: string; client_data_json: string },
  signingInput: string,
  sig: Uint8Array,
  policy: WebAuthnPolicy | undefined,
  pub: ReturnType<typeof publicKeyFromJwk>,
): Extract<VerifyResult, { ok: false }> | null {
  let authData: Uint8Array;
  let cdjBytes: Uint8Array;
  let cdj: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    authData = base64url.decode(wa.authenticator_data);
    cdjBytes = base64url.decode(wa.client_data_json);
    cdj = JSON.parse(utf8.decode(cdjBytes)) as typeof cdj;
  } catch {
    return { ok: false, code: "receipt_malformed", detail: "webauthn encoding" };
  }
  // §4.4 order: type → challenge → origin → rpIdHash/flags → signature.
  if (cdj.type !== "webauthn.get") return { ok: false, code: "webauthn_type" };
  const expectedChallenge = base64url.encode(webauthnChallenge(signingInput));
  if (typeof cdj.challenge !== "string" || !timingSafeEqualStr(cdj.challenge, expectedChallenge)) return { ok: false, code: "webauthn_challenge" };
  if (!policy || policy.allowed_origins.length === 0 || typeof cdj.origin !== "string" || !policy.allowed_origins.includes(cdj.origin))
    return { ok: false, code: "webauthn_origin" };
  if (authData.length < 37) return { ok: false, code: "receipt_malformed", detail: "authenticator_data too short" };
  const rpIdHash = Buffer.from(authData.subarray(0, 32)).toString("hex");
  if (!timingSafeEqualStr(rpIdHash, sha256hex(policy.rp_id))) return { ok: false, code: "webauthn_rp_id" };
  const flags = authData[32] as number;
  const up = (flags & 0x01) !== 0;
  const uv = (flags & 0x04) !== 0;
  if (!up || (policy.require_user_verified && !uv)) return { ok: false, code: "webauthn_user_flags" };
  const data = concat(authData, sha256(cdjBytes));
  if (!verifyRaw("ES256", data, sig, pub)) return { ok: false, code: "invalid_signature" };
  return null;
}
