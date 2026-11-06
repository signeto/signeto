// docs/protocol.md §2: the canonical action. The gateway builds it; the agent never does.
import { z } from "zod";
import { canonicalize } from "./jcs.js";
import { sha256hex } from "./encoding.js";
import { ACTION_ID_RE, GATEWAY_ID_RE, NONCE_RE, newNonce } from "./ids.js";
import { DEFAULT_EXPIRY_MS, MAX_EXPIRY_MS, TIMESTAMP_RE, formatTimestamp, parseTimestamp } from "./timestamps.js";

export const PROTOCOL_VERSION = "1.0";
export const PROTOCOL_MAJOR = 1;

const ts = z.string().regex(TIMESTAMP_RE, "timestamp must be RFC 3339 UTC with 3 fractional digits");
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

export const RequesterSchema = z
  .object({
    agent: z.string().min(1).max(128),
    session_id: z.string().min(1).max(256),
    host: z.string().min(1).max(253),
    gateway_id: z.string().regex(GATEWAY_ID_RE),
  })
  .strict();

export const CanonicalActionSchema = z
  .object({
    protocol_version: z.string().regex(/^1\.(0|[1-9][0-9]*)$/),
    tool: z.string().regex(/^[a-z0-9_]+(\.[a-z0-9_]+)+$/),
    template_id: z.string().min(1).max(128),
    template_version: z.number().int().min(1),
    args_resolved: z.record(z.unknown()),
    requester: RequesterSchema,
    nonce: z.string().regex(NONCE_RE),
    idempotency_key: hex64,
    issued_at: ts,
    expires_at: ts,
    origin_hash: hex64,
    tier: z.union([z.literal(1), z.literal(2), z.literal(3)]),
    mode: z.enum(["enforce", "advisory"]),
    batch_id: z.string().regex(NONCE_RE).optional(),
    batch_index: z.number().int().min(0).optional(),
    atomic: z.boolean().optional(),
    effective_at: ts.optional(),
  })
  .strict()
  .superRefine((a, ctx) => {
    const hasBatch = a.batch_id !== undefined;
    if (hasBatch && (a.batch_index === undefined || a.atomic === undefined))
      ctx.addIssue({ code: "custom", message: "batch_id requires batch_index and atomic" });
    if (!hasBatch && (a.batch_index !== undefined || a.atomic !== undefined))
      ctx.addIssue({ code: "custom", message: "batch_index/atomic require batch_id" });
    const issued = parseTimestamp(a.issued_at);
    const expires = parseTimestamp(a.expires_at);
    if (issued === undefined) ctx.addIssue({ code: "custom", path: ["issued_at"], message: "invalid timestamp" });
    if (expires === undefined) ctx.addIssue({ code: "custom", path: ["expires_at"], message: "invalid timestamp" });
    if (issued !== undefined && expires !== undefined) {
      if (expires <= issued) ctx.addIssue({ code: "custom", path: ["expires_at"], message: "expires_at must be after issued_at" });
      if (expires - issued > MAX_EXPIRY_MS) ctx.addIssue({ code: "custom", path: ["expires_at"], message: "expiry exceeds 5 minutes" });
      if (a.effective_at !== undefined) {
        const eff = parseTimestamp(a.effective_at);
        if (eff === undefined || eff <= issued) ctx.addIssue({ code: "custom", path: ["effective_at"], message: "effective_at must be after issued_at" });
      }
    }
  });

export type CanonicalAction = z.infer<typeof CanonicalActionSchema>;
export type Requester = z.infer<typeof RequesterSchema>;

/** §2.4: SHA-256 of the JCS of the action minus nonce, idempotency_key, issued_at, expires_at, effective_at. */
export function idempotencyKey(action: Omit<CanonicalAction, "nonce" | "idempotency_key" | "issued_at" | "expires_at" | "effective_at"> & Partial<CanonicalAction>): string {
  const { nonce: _n, idempotency_key: _k, issued_at: _i, expires_at: _e, effective_at: _f, ...rest } = action;
  return sha256hex(canonicalize(rest));
}

export interface EncodedAction {
  action: CanonicalAction;
  /** The canonical bytes as a string (UTF-8 encode for hashing/transport). Immutable once produced. */
  canonical_bytes: string;
  canonical_bytes_sha256: string;
}

/** Serialize a validated action to canonical bytes. */
export function encodeAction(action: CanonicalAction): EncodedAction {
  const parsed = CanonicalActionSchema.parse(action);
  const bytes = canonicalize(parsed);
  return { action: parsed, canonical_bytes: bytes, canonical_bytes_sha256: sha256hex(bytes) };
}

export type ParseActionError = "action_malformed" | "not_canonical" | "protocol_version_unsupported" | "idempotency_key_mismatch";

export type ParseActionResult = { ok: true; value: EncodedAction } | { ok: false; code: ParseActionError; detail?: string };

/**
 * Receiver side (§2.3): parse canonical bytes as received, validate the schema, and refuse
 * anything whose JCS re-serialization differs from the bytes. Hashes the received bytes, never a re-serialization.
 */
export function parseCanonicalAction(bytes: string): ParseActionResult {
  let raw: unknown;
  try {
    raw = JSON.parse(bytes);
  } catch (e) {
    return { ok: false, code: "action_malformed", detail: String(e) };
  }
  if (typeof raw === "object" && raw !== null && typeof (raw as { protocol_version?: unknown }).protocol_version === "string") {
    const major = Number((raw as { protocol_version: string }).protocol_version.split(".")[0]);
    if (major !== PROTOCOL_MAJOR) return { ok: false, code: "protocol_version_unsupported" };
  }
  const res = CanonicalActionSchema.safeParse(raw);
  if (!res.success) return { ok: false, code: "action_malformed", detail: res.error.issues.map((i) => i.message).join("; ") };
  if (canonicalize(res.data) !== bytes) return { ok: false, code: "not_canonical" };
  if (idempotencyKey(res.data) !== res.data.idempotency_key) return { ok: false, code: "idempotency_key_mismatch" };
  return { ok: true, value: { action: res.data, canonical_bytes: bytes, canonical_bytes_sha256: sha256hex(bytes) } };
}

export interface BuildActionInput {
  tool: string;
  /** Defaults to `tool`. */
  template_id?: string;
  template_version: number;
  args_resolved: Record<string, unknown>;
  requester: Requester;
  origin_hash: string;
  tier: 1 | 2 | 3;
  mode: "enforce" | "advisory";
  batch?: { batch_id: string; batch_index: number; atomic: boolean };
  /** Cooling-off: earliest execution time. */
  effective_at?: Date | number;
  /** Overrides the 3-minute default; must be ≤ 5 minutes. */
  expiry_ms?: number;
}

export interface BuildActionOptions {
  now?: Date | number;
  nonce?: string;
}

/** Gateway side: build, validate and freeze a canonical action. */
export function buildCanonicalAction(input: BuildActionInput, opts: BuildActionOptions = {}): EncodedAction {
  const expiry = input.expiry_ms ?? DEFAULT_EXPIRY_MS;
  if (expiry <= 0 || expiry > MAX_EXPIRY_MS) throw new RangeError("expiry_ms must be in (0, 300000]");
  const nowMs = opts.now === undefined ? Date.now() : typeof opts.now === "number" ? opts.now : opts.now.getTime();
  const base = {
    protocol_version: PROTOCOL_VERSION,
    tool: input.tool,
    template_id: input.template_id ?? input.tool,
    template_version: input.template_version,
    args_resolved: input.args_resolved,
    requester: input.requester,
    origin_hash: input.origin_hash,
    tier: input.tier,
    mode: input.mode,
    ...(input.batch ? input.batch : {}),
  };
  const action: CanonicalAction = {
    ...base,
    nonce: opts.nonce ?? newNonce(),
    idempotency_key: idempotencyKey(base),
    issued_at: formatTimestamp(nowMs),
    expires_at: formatTimestamp(nowMs + expiry),
    ...(input.effective_at !== undefined ? { effective_at: formatTimestamp(input.effective_at) } : {}),
  };
  return encodeAction(action);
}

/** §2.8 origin_hash inputs. Correlation metadata only; never a policy input. */
export const originHash = {
  mcp: (session_id: string, tool_use_id: string): string => sha256hex(`${session_id}\n${tool_use_id}`),
  hook: (payload: unknown): string => sha256hex(canonicalize(payload)),
  ci: (run_id: string, job_id: string): string => sha256hex(`${run_id}\n${job_id}`),
};

export { ACTION_ID_RE };
