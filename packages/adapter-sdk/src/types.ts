// docs/adapters.md §2–§4. The adapter is the only code that talks to an upstream; the gateway sits between it and the agent.
import type { JsonValue } from "@signeto/protocol";

export type JSONSchema = Record<string, unknown>;

export interface DisplayTemplate {
  /** Stable identifier, e.g. "github.merge_pull_request". Travels inside the signed bytes. */
  id: string;
  /** Integer. Bumped whenever `text` changes. Travels inside the signed bytes. */
  version: number;
  /** One line. Placeholders are `{field}` paths into resolved args. */
  text: string;
  detail?: string[];
  /** Resolved keys the template intentionally omits (protocol.md §3.4). */
  elide?: string[];
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

export interface ExecuteContext {
  deadline: Date;
  logger: Logger;
  fetch: typeof fetch;
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
