// docs/adapters.md §2–§4. The adapter is the only code that talks to an upstream; the gateway sits between it and the agent.
import type { JsonValue } from "@signeto/protocol";

export type JSONSchema = Record<string, unknown>;

export interface DisplayTemplate {
  /** Stable identifier, e.g. "github.merge_pull_request". Travels inside the signed bytes. */
  id: string;
  /** Integer. Bumped whenever `text`, `elide`, `note`, `links` or `link_hosts` changes. Travels inside the signed bytes. */
  version: number;
  /** One line. Placeholders are `{field}` paths into resolved args. */
  text: string;
  detail?: string[];
  /** Resolved keys the template intentionally omits (protocol.md §3.4). */
  elide?: string[];
  /** Optional second line, same placeholders as `text` plus `{field:short}` (protocol.md §3.2). */
  note?: string;
  /** Review links built on the device from resolved args, at most 4 (protocol.md §3.5). */
  links?: { label: string; url: string }[];
  /** Exact hostnames the links may point to (protocol.md §3.5). Required when `links` is set. */
  link_hosts?: string[];
}

export interface ToolSpec {
  name: string;
  description: string;
  input: JSONSchema;
  resolved: JSONSchema;
  classification: "public" | "internal" | "pii" | "secret";
  effect: "read" | "write";
  template: DisplayTemplate;
}

export interface AdapterManifest {
  name: string;
  version: string;
  mode: "mint" | "custody";
  egress: string[];
  secrets: { name: string; description: string }[];
  tools: ToolSpec[];
}

export interface Logger {
  debug(msg: string, data?: Record<string, unknown>): void;
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
}

/** Read-only upstream access handed to `resolve`. Adapter-specific; the gateway only guarantees it carries no write credential. */
export type ReadOnlyClient = unknown;
export type AdapterSecrets = Readonly<Record<string, string>>;

export interface ResolveContext {
  upstream: ReadOnlyClient;
  deadline: Date;
  logger: Logger;
}
export interface ResolvedArgs {
  args: Record<string, JsonValue>;
  facts?: Record<string, JsonValue>;
}

export interface CredentialContext {
  secrets: AdapterSecrets;
  deadline: Date;
  logger: Logger;
  /** Egress-restricted fetch, same as ExecuteContext. Adapters MUST use it for mint/custody upstream calls. */
  fetch: typeof fetch;
}
export interface Credential {
  material: unknown;
  expiresAt: Date;
  scope: string;
  revoke?(): Promise<void>;
}

/**
 * Who approved the action, for adapters that record the approval upstream (e.g. a GitHub check run).
 * Informational only: the gateway has already verified the receipt and written it to the ledger.
 */
export interface ApprovalInfo {
  action_id: string;
  approver_id: string;
  device_id: string;
  /** The device's name from its pairing entry, when known. */
  device_name?: string;
  signed_at: string;
  /** SHA-256 (hex) of the JCS receipt, as in the ledger `approved` entry. */
  receipt_sha256: string;
  /** Number of approvals when a quorum rule applied. */
  approvals: number;
}

export interface ExecuteContext {
  deadline: Date;
  logger: Logger;
  fetch: typeof fetch;
  /** Present for tier 2 and 3 actions (absent for tier 1, which nobody signs). */
  approval?: ApprovalInfo;
}
export interface FrozenAction {
  readonly id: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, JsonValue>>;
  readonly canonicalBytes: Uint8Array;
  readonly templateId: string;
  readonly templateVersion: number;
}
export interface ToolResult {
  content: JsonValue;
  evidence: Record<string, JsonValue>;
}

export interface Adapter {
  manifest: AdapterManifest;
  resolve(ctx: ResolveContext, tool: string, args: unknown): Promise<ResolvedArgs>;
  mint?(ctx: CredentialContext, action: FrozenAction): Promise<Credential>;
  custody?(ctx: CredentialContext, action: FrozenAction): Promise<Credential>;
  execute(ctx: ExecuteContext, action: FrozenAction, credential: Credential): Promise<ToolResult>;
}

export type AdapterErrorCode = "resolve_failed" | "upstream_unreachable" | "upstream_rejected" | "credential_failed" | "precondition_failed" | "timeout";

export class AdapterError extends Error {
  override name = "AdapterError";
  constructor(
    readonly code: AdapterErrorCode,
    message: string,
    readonly retryable = false,
    readonly detail?: Record<string, JsonValue>,
  ) {
    super(message);
  }
}
