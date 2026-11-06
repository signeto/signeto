// Offline test plumbing: a routed mock fetch that records every call, a test GitHub App key pair, and canonical-action helpers.
import { generateKeyPairSync } from "node:crypto";
import { buildCanonicalAction, gatewayIdFromJwk, sha256hex } from "@signeto/protocol";
import type { FrozenAction, Logger, ResolveContext, CredentialContext, ExecuteContext } from "@signeto/adapter-sdk";
import { createReadOnlyClient, type GithubReadOnlyClient } from "../src/index.js";

export interface RecordedCall {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface Route {
  method: string;
  /** Exact path (including query) or a RegExp tested against the path. */
  path: string | RegExp;
  status?: number;
  body?: unknown;
  /** Throw this instead of responding (network failure). */
  throws?: Error;
  /** Raw text body (for malformed JSON cases). */
  text?: string;
}

export function mockFetch(routes: Route[]) {
  const calls: RecordedCall[] = [];
  const fetchFn: typeof fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(url);
    const path = u.pathname + u.search;
    const method = (init.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const body = typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method, url, path, headers, body });
    const route = routes.find((r) => r.method === method && (typeof r.path === "string" ? r.path === path : r.path.test(path)));
    if (!route) return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
    if (route.throws) throw route.throws;
    const status = route.status ?? 200;
    if (route.text !== undefined) return new Response(route.text, { status });
    if (status === 204 || route.body === undefined) return new Response(null, { status });
    return new Response(JSON.stringify(route.body), { status, headers: { "content-type": "application/json" } });
  };
  return { fetch: fetchFn, calls };
}

export const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
export function recordingLogger() {
  const warnings: Array<{ msg: string; data?: Record<string, unknown> }> = [];
  const l: Logger = { debug() {}, info() {}, warn(msg, data) { warnings.push(data ? { msg, data } : { msg }); }, error() {} };
  return { logger: l, warnings };
}

export const futureDeadline = () => new Date(Date.now() + 30_000);

export function resolveCtx(upstream: GithubReadOnlyClient | unknown): ResolveContext {
  return { upstream, deadline: futureDeadline(), logger };
}
export function credentialCtx(secrets: Record<string, string>): CredentialContext {
  return { secrets, deadline: futureDeadline(), logger };
}
export function executeCtx(fetchFn: typeof fetch): ExecuteContext {
  return { fetch: fetchFn, deadline: futureDeadline(), logger };
}

export function readOnlyClient(routes: Route[]) {
  const m = mockFetch(routes);
  return { client: createReadOnlyClient({ token: "read-only-token", fetch: m.fetch }), calls: m.calls };
}

// ---- GitHub App test key pair ----
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
export const TEST_PRIVATE_KEY_PEM = pair.privateKey.export({ type: "pkcs1", format: "pem" }) as string;
export const TEST_PUBLIC_KEY = pair.publicKey;
export const TEST_APP_ID = "123456";

// ---- upstream state fixtures ----
export const HEAD_SHA = "0123456789abcdef0123456789abcdef01234567";
export const REF_SHA = "fedcba9876543210fedcba9876543210fedcba98";
export const MERGE_SHA = "89abcdef0123456789abcdef0123456789abcdef";

export function pullRequest(over: Record<string, unknown> = {}) {
  return {
    number: 42,
    state: "open",
    draft: false,
    merged: false,
    title: "Ship it",
    mergeable: true,
    mergeable_state: "clean",
    html_url: "https://github.com/acme/api/pull/42",
    user: { login: "octocat" },
    head: { ref: "feature/x", sha: HEAD_SHA },
    base: { ref: "main", repo: { full_name: "acme/api" } },
    ...over,
  };
}

export function workflow(over: Record<string, unknown> = {}) {
  return { id: 161335, name: "Deploy", path: ".github/workflows/deploy.yml", state: "active", ...over };
}

// ---- canonical action helpers ----
const gwJwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
export const requester = { agent: "test-agent", session_id: "sess-1", host: "localhost", gateway_id: gatewayIdFromJwk(gwJwk) };

export function canonicalFor(tool: string, templateVersion: number, args: Record<string, unknown>) {
  return buildCanonicalAction(
    { tool, template_version: templateVersion, args_resolved: args, requester, origin_hash: sha256hex("origin"), tier: 2, mode: "enforce" },
    { now: 1_700_000_000_000, nonce: "a".repeat(22) },
  );
}

export function frozen(tool: string, args: Record<string, unknown>, templateVersion = 1): FrozenAction {
  const enc = canonicalFor(tool, templateVersion, args);
  return {
    id: "act_test",
    tool,
    args: enc.action.args_resolved as FrozenAction["args"],
    canonicalBytes: new TextEncoder().encode(enc.canonical_bytes),
    templateId: enc.action.template_id,
    templateVersion: enc.action.template_version,
  };
}
