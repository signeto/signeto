// docs/protocol.md §5.6: gateway succession ("handoff"). A gateway G1 that is being replaced (moving between a
// self-hosted machine and Signeto Cloud) names its successor G2 in a Tier 3 canonical action of the built-in tool
// `signeto.gateway_handoff`. The request is signed by G1 like every approval request (`gateway_signature`, §7.5) and
// approved on the phone like every action (a receipt over the exact canonical bytes, §4). G1 then signs a completion
// that fixes its last ledger entry and the devices it hands over.
//
//   - A device that pinned G1 pins G2 (same approver binding, same template pins) when G1's signature verifies under
//     its pin and its OWN receipt approves those bytes: `verifyHandoffForDevice`.
//   - G2, or an auditor, checks the whole record (request, completion, every receipt in it): `verifyHandoffRecord`.
//
// Nothing here trusts the relay: G1's key comes from the device's pin (or, for G2, from a key whose thumbprint is
// the handoff's own `requester.gateway_id`), and device keys from G1's signed completion.
import { z } from "zod";
import { canonicalize, type JsonValue } from "./jcs.js";
import { base64url, sha256hex, utf8 } from "./encoding.js";
import { DEVICE_ID_RE, GATEWAY_ID_RE, algForJwk, deviceIdFromJwk, gatewayIdFromJwk, type PrivateJwk, type PublicJwk } from "./ids.js";
import { ACTION_ID_RE, buildCanonicalAction, parseCanonicalAction, type CanonicalAction, type EncodedAction } from "./action.js";
import { ReceiptSchema, receiptSigningInput, verifyReceipt, type Receipt } from "./receipt.js";
import { approvalRequestFields, approvalRequestSigningInput } from "./request.js";
import { publicKeyFromJwk, signWithJwk, verifyWithJwk } from "./signing.js";
import { CLOCK_SKEW_MS, TIMESTAMP_RE, parseTimestamp } from "./timestamps.js";
import { isDisplaySafe } from "./display.js";
import { isWeakPublicJwk } from "./weakkeys.js";

/** The built-in tool, and the `template_id` of its bundled template (`signetoRegistry`). */
export const HANDOFF_TOOL = "signeto.gateway_handoff";
/** The one handoff format this package implements. A device MUST NOT act on another version. */
export const HANDOFF_TEMPLATE_VERSION = 1;
/** `purpose` member of the completion's signing input: signed, never sent. */
export const HANDOFF_COMPLETE_PURPOSE = "gateway.handoff.complete";
/** How long after `expires_at` the relay still accepts G1's completion (§5.6.4). */
export const HANDOFF_COMPLETION_GRACE_MS = 5 * 60_000;
/** Bounds on a completion (a relay's body limit is 256 KiB). */
export const HANDOFF_MAX_DEVICES = 64;
export const HANDOFF_SUCCESSOR_NAME_MAX = 64;

/** `args_resolved` of a handoff action (§5.6.1). Exactly these members. */
export interface HandoffArgs {
  /** G2: `gw_` + thumbprint of `successor_public_key`. */
  successor_gateway_id: string;
  /** G2's public key, RFC 7638 required members only. */
  successor_public_key: PublicJwk;
  /** Shown on the card ("Move this gateway to …"). 1–64 code units, nothing the §3.6 display escape would change. */
  successor_name: string;
  /** G1's ledger head when the handoff was issued: its `seq` and `entry_hash`. */
  ledger_seq: number;
  ledger_head: string;
  /** G1's policy in force (docs/policy.md §11); G2 starts with exactly this policy. */
  policy_hash: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const ARG_KEYS = ["ledger_head", "ledger_seq", "policy_hash", "successor_gateway_id", "successor_name", "successor_public_key"];

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const sameKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => {
  const k = Object.keys(o);
  return k.length === keys.length && keys.every((x) => Object.prototype.hasOwnProperty.call(o, x));
};

/** A public JWK with exactly its RFC 7638 required members, a valid point, and not a small-order Ed25519 key. */
export function strictPublicJwk(v: unknown): PublicJwk | undefined {
  if (!isObj(v)) return undefined;
  let jwk: PublicJwk;
  if (v["kty"] === "OKP" && v["crv"] === "Ed25519" && sameKeys(v, ["crv", "kty", "x"]) && typeof v["x"] === "string" && B64_32.test(v["x"])) jwk = { kty: "OKP", crv: "Ed25519", x: v["x"] };
  else if (v["kty"] === "EC" && v["crv"] === "P-256" && sameKeys(v, ["crv", "kty", "x", "y"]) && typeof v["x"] === "string" && typeof v["y"] === "string" && B64_32.test(v["x"]) && B64_32.test(v["y"]))
    jwk = { kty: "EC", crv: "P-256", x: v["x"], y: v["y"] };
  else return undefined;
  try {
    publicKeyFromJwk(jwk);
  } catch {
    return undefined;
  }
  return isWeakPublicJwk(jwk) ? undefined : jwk;
}

/** The successor's display name rule (§5.6.1). */
export function isValidSuccessorName(s: unknown): s is string {
  return typeof s === "string" && s.length >= 1 && s.length <= HANDOFF_SUCCESSOR_NAME_MAX && s.trim() === s && isDisplaySafe(s);
}

/** Why `args` is not a well-formed handoff `args_resolved`, or null. Does not compare with the predecessor. */
export function handoffArgsError(args: unknown): string | null {
  if (!isObj(args)) return "args_resolved is not an object";
  if (!sameKeys(args, ARG_KEYS)) return `args_resolved must have exactly ${ARG_KEYS.join(", ")}`;
  if (typeof args["successor_gateway_id"] !== "string" || !GATEWAY_ID_RE.test(args["successor_gateway_id"])) return "successor_gateway_id is not a gateway_id";
  if (strictPublicJwk(args["successor_public_key"]) === undefined) return "successor_public_key is not a valid public JWK with exactly its required members";
  if (!isValidSuccessorName(args["successor_name"])) return "successor_name must be 1-64 printable characters without surrounding spaces";
  const seq = args["ledger_seq"];
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) return "ledger_seq must be a positive integer";
  if (typeof args["ledger_head"] !== "string" || !HEX64.test(args["ledger_head"])) return "ledger_head must be a lowercase hex SHA-256";
  if (typeof args["policy_hash"] !== "string" || !HEX64.test(args["policy_hash"])) return "policy_hash must be a lowercase hex SHA-256";
  return null;
}

export type HandoffErrorCode =
  | "handoff_malformed"
  | "not_a_handoff"
  | "handoff_unsupported"
  | "successor_mismatch"
  | "gateway_not_pinned"
  | "gateway_signature_invalid"
  | "receipt_malformed"
  | "receipt_not_own"
  | "receipt_mismatch"
  | "approver_mismatch"
  | "handoff_not_approved"
  | "hash_mismatch"
  | "invalid_signature"
  | "clock_skew"
  | "completion_invalid";

export interface ParsedHandoff {
  action: CanonicalAction;
  args: HandoffArgs;
  canonical_bytes: string;
  canonical_bytes_sha256: string;
  predecessor_gateway_id: string;
}

export type ParseHandoffResult = { ok: true; value: ParsedHandoff } | { ok: false; code: "handoff_malformed" | "not_a_handoff" | "handoff_unsupported" | "successor_mismatch"; detail?: string };

/**
 * §5.6.1: canonical bytes that are a handoff, and nothing else: the built-in tool and template, version 1, tier 3,
 * enforce, no batch or cooling-off, well-formed arguments, and a successor whose id is its key's thumbprint and is
 * not the predecessor. Signatures are not checked here.
 */
export function parseHandoffAction(canonical_bytes: string): ParseHandoffResult {
  const p = parseCanonicalAction(canonical_bytes);
  if (!p.ok) return { ok: false, code: "handoff_malformed", detail: p.code };
  const a = p.value.action;
  if (a.tool !== HANDOFF_TOOL || a.template_id !== HANDOFF_TOOL) return { ok: false, code: "not_a_handoff" };
  if (a.template_version !== HANDOFF_TEMPLATE_VERSION) return { ok: false, code: "handoff_unsupported", detail: `template_version ${a.template_version}` };
  if (a.tier !== 3 || a.mode !== "enforce") return { ok: false, code: "handoff_malformed", detail: "a handoff is tier 3, enforce" };
  if (a.batch_id !== undefined || a.effective_at !== undefined) return { ok: false, code: "handoff_malformed", detail: "a handoff is not batched and has no effective_at" };
  const err = handoffArgsError(a.args_resolved);
  if (err) return { ok: false, code: "handoff_malformed", detail: err };
  const args = a.args_resolved as unknown as HandoffArgs;
  if (gatewayIdFromJwk(args.successor_public_key) !== args.successor_gateway_id) return { ok: false, code: "successor_mismatch", detail: "successor_gateway_id is not the thumbprint of successor_public_key" };
  if (args.successor_gateway_id === a.requester.gateway_id) return { ok: false, code: "successor_mismatch", detail: "a gateway cannot hand off to itself" };
  return { ok: true, value: { action: a, args, canonical_bytes, canonical_bytes_sha256: p.value.canonical_bytes_sha256, predecessor_gateway_id: a.requester.gateway_id } };
}

/** Test and tooling builder: the canonical action a gateway issues for a handoff (the reference gateway builds the same through its pipeline). */
export function buildHandoffAction(
  input: { predecessor_gateway_id: string; host: string; args: HandoffArgs; agent?: string; session_id?: string; origin_hash?: string; expiry_ms?: number },
  opts: { now?: number; nonce?: string } = {},
): EncodedAction {
  const err = handoffArgsError(input.args);
  if (err) throw new TypeError(err);
  return buildCanonicalAction(
    {
      tool: HANDOFF_TOOL,
      template_version: HANDOFF_TEMPLATE_VERSION,
      args_resolved: input.args as unknown as Record<string, unknown>,
      requester: { agent: input.agent ?? "signeto gateway", session_id: input.session_id ?? "handoff", host: input.host, gateway_id: input.predecessor_gateway_id },
      origin_hash: input.origin_hash ?? sha256hex(`handoff\n${input.args.successor_gateway_id}`),
      tier: 3,
      mode: "enforce",
      ...(input.expiry_ms !== undefined ? { expiry_ms: input.expiry_ms } : {}),
    },
    opts,
  );
}

// ---- the request as a device or G2 receives it ----------------------------------------------------------

/** The approved handoff as it travels: the §7.5 request's action id, canonical bytes and G1's `gateway_signature`. */
export interface HandoffRequest {
  action_id: string;
  canonical_bytes: string;
  gateway_signature: string;
}

function checkGatewaySignature(h: HandoffRequest, key: PublicJwk): boolean {
  if (typeof h.action_id !== "string" || !ACTION_ID_RE.test(h.action_id) || typeof h.gateway_signature !== "string") return false;
  let a: CanonicalAction;
  try {
    a = JSON.parse(h.canonical_bytes) as CanonicalAction;
  } catch {
    return false;
  }
  const f = approvalRequestFields({ action_id: h.action_id, canonical_bytes: h.canonical_bytes, expires_at: a.expires_at });
  if (!f) return false;
  try {
    return verifyWithJwk(utf8.encode(approvalRequestSigningInput(f)), base64url.decode(h.gateway_signature), key);
  } catch {
    return false;
  }
}

// ---- completion (§5.6.3) ----------------------------------------------------------------------------------

/** One device G1 hands over: what G2 needs to pin it exactly as G1 did. */
export interface HandoffDevice {
  device_id: string;
  public_key: PublicJwk;
  /** The approver G1 pinned it under (ledger `owner`, the device's `approver_id`). */
  approver_id: string;
  attested: boolean;
  platform: string | null;
  name: string | null;
  attestation_sha256: string | null;
}

export interface HandoffCompletionFields {
  action_id: string;
  canonical_bytes_sha256: string;
  predecessor_gateway_id: string;
  successor_gateway_id: string;
  /** G1's last ledger entry: G2's first entry chains to `final_entry_hash`. G1 appends nothing after it. */
  final_seq: number;
  final_entry_hash: string;
  completed_at: string;
  /** Every active device of G1, sorted by `device_id`. */
  devices: HandoffDevice[];
  /** The approving receipts G1 verified for the handoff, in arrival order. */
  receipts: Receipt[];
}

export interface HandoffCompletion extends HandoffCompletionFields {
  /** G1's signature over `handoffCompletionSigningInput`, base64url without padding. */
  signature: string;
}

const ts = z.string().regex(TIMESTAMP_RE).refine((s) => parseTimestamp(s) !== undefined);
const DeviceSchema = z
  .object({
    device_id: z.string().regex(DEVICE_ID_RE),
    public_key: z.unknown(),
    approver_id: z.string().min(1).max(64),
    attested: z.boolean(),
    platform: z.string().min(1).max(32).nullable(),
    name: z.string().min(1).max(128).nullable(),
    attestation_sha256: z.string().regex(HEX64).nullable(),
  })
  .strict();
export const HandoffCompletionSchema = z
  .object({
    action_id: z.string().regex(ACTION_ID_RE),
    canonical_bytes_sha256: z.string().regex(HEX64),
    predecessor_gateway_id: z.string().regex(GATEWAY_ID_RE),
    successor_gateway_id: z.string().regex(GATEWAY_ID_RE),
    final_seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    final_entry_hash: z.string().regex(HEX64),
    completed_at: ts,
    devices: z.array(DeviceSchema).min(1).max(HANDOFF_MAX_DEVICES),
    receipts: z.array(z.unknown()).min(1).max(HANDOFF_MAX_DEVICES),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();

/**
 * UTF-8 JCS of the completion without `signature`, with `purpose: "gateway.handoff.complete"` added. `purpose` keeps
 * it apart from every other gateway-signed object (approval requests, pairing confirmations, chain heads).
 */
export function handoffCompletionSigningInput(c: HandoffCompletionFields | Record<string, unknown>): string {
  const { signature: _s, ...rest } = c as Record<string, unknown>;
  return canonicalize({ ...rest, purpose: HANDOFF_COMPLETE_PURPOSE } as unknown as JsonValue);
}

export function signHandoffCompletion(fields: HandoffCompletionFields, predecessorKey: PrivateJwk): HandoffCompletion {
  const devices = [...fields.devices].sort((a, b) => (a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0));
  const body: HandoffCompletionFields = { ...fields, devices };
  const { signature } = signWithJwk(utf8.encode(handoffCompletionSigningInput(body)), predecessorKey);
  return { ...body, signature: base64url.encode(signature) };
}

export type CompletionResult = { ok: true; completion: HandoffCompletion; devices: Map<string, HandoffDevice> } | { ok: false; detail: string };

/**
 * §5.6.3: the completion is well formed, names this handoff, is signed by the predecessor's key, comes after the
 * handoff's ledger head, lists devices whose ids are their keys' thumbprints (sorted, unique), and every receipt in
 * it is an approval of these bytes by a listed device under its approver, inside the action's window.
 */
export function verifyHandoffCompletion(c: unknown, opts: { handoff: ParsedHandoff; action_id: string; predecessor_public_key: PublicJwk }): CompletionResult {
  const s = HandoffCompletionSchema.safeParse(c);
  if (!s.success) return { ok: false, detail: `completion malformed: ${s.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}` };
  const comp = c as HandoffCompletion;
  const h = opts.handoff;
  if (comp.action_id !== opts.action_id || comp.canonical_bytes_sha256 !== h.canonical_bytes_sha256) return { ok: false, detail: "completion names another handoff" };
  if (comp.predecessor_gateway_id !== h.predecessor_gateway_id || comp.successor_gateway_id !== h.args.successor_gateway_id) return { ok: false, detail: "completion names other gateways" };
  let good = false;
  try {
    good = verifyWithJwk(utf8.encode(handoffCompletionSigningInput(comp)), base64url.decode(comp.signature), opts.predecessor_public_key);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, detail: "completion signature does not verify with the predecessor's key" };
  if (comp.final_seq <= h.args.ledger_seq) return { ok: false, detail: "final_seq is not after the handoff's ledger head" };
  const devices = new Map<string, HandoffDevice>();
  let prev = "";
  for (const d of comp.devices) {
    const key = strictPublicJwk(d.public_key);
    if (!key) return { ok: false, detail: `device ${d.device_id}: public_key invalid` };
    if (deviceIdFromJwk(key) !== d.device_id) return { ok: false, detail: `device ${d.device_id} is not the thumbprint of its key` };
    if (d.device_id <= prev) return { ok: false, detail: "devices must be sorted by device_id and unique" };
    prev = d.device_id;
    devices.set(d.device_id, { ...d, public_key: key });
  }
  for (const [i, raw] of comp.receipts.entries()) {
    const r = ReceiptSchema.safeParse(raw);
    if (!r.success) return { ok: false, detail: `receipt ${i} malformed` };
    const dev = devices.get(r.data.device_id);
    if (!dev) return { ok: false, detail: `receipt ${i} is from ${r.data.device_id}, which the completion does not list` };
    if (r.data.action_id !== comp.action_id) return { ok: false, detail: `receipt ${i} is for another action` };
    if (r.data.approver_id !== dev.approver_id) return { ok: false, detail: `receipt ${i}: approver ${r.data.approver_id} does not own ${dev.device_id}` };
    if (r.data.decision !== "approve") return { ok: false, detail: `receipt ${i} is not an approval` };
    const v = verifyReceipt({ receipt: raw, canonical_bytes: h.canonical_bytes, issued_at: h.action.issued_at, expires_at: h.action.expires_at, device_public_key: dev.public_key });
    if (!v.ok) return { ok: false, detail: `receipt ${i} does not verify (${v.code})` };
  }
  return { ok: true, completion: comp, devices };
}

// ---- device side (§5.6.5) ----------------------------------------------------------------------------------

/** What a device holds for the gateway it pinned (§5.3, §5.4). */
export interface GatewayPin {
  gateway_id: string;
  public_key: PublicJwk;
  approver_id: string;
  templates_pinned?: Array<{ template_id: string; template_version: number; sha256: string }>;
}

export interface SuccessorPin {
  gateway_id: string;
  public_key: PublicJwk;
  /** For display: the successor's name as G1 signed it. */
  name: string;
  approver_id: string;
  templates_pinned: Array<{ template_id: string; template_version: number; sha256: string }>;
  predecessor_gateway_id: string;
}

export type DeviceHandoffResult =
  | {
      ok: true;
      successor: SuccessorPin;
      handoff: ParsedHandoff;
      /** A completion was supplied and verified: G1 says it handed over and appends nothing more. */
      completed: boolean;
      /** The receipt was signed after the approval window, accepted because the completion names this device. */
      late: boolean;
    }
  | { ok: false; code: HandoffErrorCode; detail?: string };

/**
 * §5.6.5, on the device: may this device pin the successor? Only if the handoff is signed by the gateway it pinned
 * (G1's key from its own pin, never from the network) and its own receipt approves exactly these bytes under the
 * approver it was paired as. A receipt signed after the approval window counts only with G1's completion naming
 * this device. The result carries the new pin: same approver binding and template pins as G1's.
 */
export function verifyHandoffForDevice(input: { handoff: HandoffRequest; pin: GatewayPin; device_public_key: PublicJwk; receipt: unknown; completion?: unknown }): DeviceHandoffResult {
  const { handoff: h, pin } = input;
  // 1–3: G1's signature, under the pin.
  let action: CanonicalAction;
  try {
    action = JSON.parse(h.canonical_bytes) as CanonicalAction;
  } catch {
    return { ok: false, code: "handoff_malformed", detail: "canonical_bytes is not JSON" };
  }
  if (!parseCanonicalAction(h.canonical_bytes).ok || typeof action.requester?.gateway_id !== "string") return { ok: false, code: "handoff_malformed", detail: "not a canonical action" };
  if (action.requester.gateway_id !== pin.gateway_id) return { ok: false, code: "gateway_not_pinned" };
  if (!checkGatewaySignature(h, pin.public_key)) return { ok: false, code: "gateway_signature_invalid" };
  // 4–7: a handoff, of a version this device implements, well formed.
  const parsed = parseHandoffAction(h.canonical_bytes);
  if (!parsed.ok) return parsed;
  const ph = parsed.value;
  // 8–14: the device's own receipt approved exactly these bytes.
  const r = ReceiptSchema.safeParse(input.receipt);
  if (!r.success || r.data.webauthn !== undefined) return { ok: false, code: "receipt_malformed" };
  const rc = r.data;
  if (rc.device_id !== deviceIdFromJwk(input.device_public_key)) return { ok: false, code: "receipt_not_own" };
  if (rc.action_id !== h.action_id) return { ok: false, code: "receipt_mismatch" };
  if (rc.approver_id !== pin.approver_id) return { ok: false, code: "approver_mismatch" };
  if (rc.decision !== "approve") return { ok: false, code: "handoff_not_approved" };
  if (rc.canonical_bytes_sha256 !== ph.canonical_bytes_sha256) return { ok: false, code: "hash_mismatch" };
  // The signature over the §4.2 signing input rebuilt from this device's own hash; the window is judged below.
  let sigOk = false;
  try {
    const si = receiptSigningInput({ canonical_bytes_sha256: ph.canonical_bytes_sha256, decision: rc.decision, reason: rc.reason, signed_at: rc.signed_at });
    sigOk = algForJwk(input.device_public_key) === rc.alg && verifyWithJwk(utf8.encode(si), base64url.decode(rc.signature), input.device_public_key);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, code: "invalid_signature" };
  // 15: the completion, when supplied, is G1's and names this device.
  let completed = false;
  let listed = false;
  if (input.completion !== undefined) {
    const c = verifyHandoffCompletion(input.completion, { handoff: ph, action_id: h.action_id, predecessor_public_key: pin.public_key });
    if (!c.ok) return { ok: false, code: "completion_invalid", detail: c.detail };
    completed = true;
    listed = c.devices.has(rc.device_id);
  }
  // 16: inside the approval window, or later with the completion naming this device (a phone that missed the window).
  const at = parseTimestamp(rc.signed_at) as number;
  const issued = parseTimestamp(ph.action.issued_at) as number;
  const expires = parseTimestamp(ph.action.expires_at) as number;
  const inWindow = at >= issued - CLOCK_SKEW_MS && at <= expires + CLOCK_SKEW_MS;
  const late = !inWindow && listed && at > expires;
  if (!inWindow && !late) return { ok: false, code: "clock_skew" };
  return {
    ok: true,
    successor: {
      gateway_id: ph.args.successor_gateway_id,
      public_key: ph.args.successor_public_key,
      name: ph.args.successor_name,
      approver_id: pin.approver_id,
      templates_pinned: pin.templates_pinned ?? [],
      predecessor_gateway_id: pin.gateway_id,
    },
    handoff: ph,
    completed,
    late,
  };
}

// ---- successor and auditor side (§5.6.6) -----------------------------------------------------------------

/** A completed handoff as the relay serves it and G2's first ledger entry records it. */
export interface HandoffRecord extends HandoffRequest {
  /** G1's public key. Not trusted for itself: its thumbprint must be the handoff's `requester.gateway_id`. */
  predecessor_public_key: PublicJwk;
  completion: HandoffCompletion;
}

export type RecordResult =
  | { ok: true; handoff: ParsedHandoff; completion: HandoffCompletion; devices: Map<string, HandoffDevice>; predecessor_public_key: PublicJwk }
  | { ok: false; code: HandoffErrorCode; detail?: string };

/**
 * §5.6.6: everything in a completed handoff verifies on its own: the predecessor key is the one the handoff names, its
 * signature covers the request, the bytes are a handoff (to `successor_gateway_id` when given), and the completion
 * and every receipt in it verify. Does not decide whether the approving devices were allowed to approve under the
 * predecessor's policy: the gateway does that with the policy (`policy_hash`) in hand.
 */
export function verifyHandoffRecord(rec: unknown, opts: { successor_gateway_id?: string } = {}): RecordResult {
  if (!isObj(rec)) return { ok: false, code: "handoff_malformed", detail: "record is not an object" };
  const h = rec as unknown as HandoffRecord;
  if (typeof h.canonical_bytes !== "string") return { ok: false, code: "handoff_malformed", detail: "canonical_bytes missing" };
  const key = strictPublicJwk(h.predecessor_public_key);
  if (!key) return { ok: false, code: "handoff_malformed", detail: "predecessor_public_key invalid" };
  const parsed = parseHandoffAction(h.canonical_bytes);
  if (!parsed.ok) return parsed;
  const ph = parsed.value;
  if (gatewayIdFromJwk(key) !== ph.predecessor_gateway_id) return { ok: false, code: "gateway_not_pinned", detail: "predecessor_public_key is not the key of requester.gateway_id" };
  if (!checkGatewaySignature(h, key)) return { ok: false, code: "gateway_signature_invalid" };
  if (opts.successor_gateway_id !== undefined && ph.args.successor_gateway_id !== opts.successor_gateway_id) return { ok: false, code: "successor_mismatch", detail: `the handoff names ${ph.args.successor_gateway_id}` };
  const c = verifyHandoffCompletion(h.completion, { handoff: ph, action_id: h.action_id, predecessor_public_key: key });
  if (!c.ok) return { ok: false, code: "completion_invalid", detail: c.detail };
  return { ok: true, handoff: ph, completion: c.completion, devices: c.devices, predecessor_public_key: key };
}
