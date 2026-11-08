// The github adapter: resolve → mint (GitHub App installation token) → execute. docs/adapters.md §3, §6; SPEC.md §6.1.
import type { JsonValue } from "@signeto/protocol";
import { AdapterError } from "@signeto/adapter-sdk";
import type { Adapter, Credential, CredentialContext, ExecuteContext, FrozenAction, Logger, ResolveContext, ResolvedArgs, ToolResult } from "@signeto/adapter-sdk";
import {
  GITHUB_API_BASE,
  GithubApiError,
  asRecord,
  errorMessage,
  getNumber,
  getString,
  githubHeaders,
  isAbortError,
  isGithubReadOnlyClient,
  parseJson,
  signalFor,
  toAdapterError,
  type FetchFn,
  type GithubReadOnlyClient,
} from "./client.js";
import { IMPLICIT_PERMISSIONS, appHeaders, findInstallation, mintInstallationToken, revokeToken, type PermissionSet } from "./installation.js";
import { MERGE_METHODS, OPTIONAL_SECRET_INSTALLATION_ID, REPO_PATTERN, SHA_PATTERN, manifest, type MergeMethod } from "./manifest.js";

export type GithubToolName = "merge_pull_request" | "dispatch_workflow" | "read_pull_request";
export type { PermissionLevel, PermissionSet } from "./installation.js";

/**
 * Installation-token permissions requested per tool, the narrowest set GitHub accepts for the one call `execute` makes.
 * merge: GitHub's merge endpoint needs pull_requests:write and creates a commit on the base branch (contents:write).
 * dispatch: actions:write for the dispatch; contents:read so execute can confirm `ref` still points at the signed `ref_sha`.
 */
export const MINT_PERMISSIONS: Readonly<Record<GithubToolName, PermissionSet>> = {
  merge_pull_request: { contents: "write", pull_requests: "write" },
  dispatch_workflow: { actions: "write", contents: "read" },
  read_pull_request: { pull_requests: "read" },
};

export interface GithubAdapterOptions {
  /** Used by `mint` and `revoke` (CredentialContext carries no fetch). `execute` always uses the gateway's egress-restricted `ctx.fetch`. */
  fetch?: FetchFn;
  /** Millisecond clock, injectable for tests. */
  now?: () => number;
}

const REPO_RE = new RegExp(REPO_PATTERN);
const SHA_RE = new RegExp(SHA_PATTERN);

export function createGithubAdapter(opts: GithubAdapterOptions = {}): Adapter {
  const now = opts.now ?? (() => Date.now());
  const mintFetch: FetchFn = (input, init) => (opts.fetch ?? globalThis.fetch)(input, init);

  return {
    manifest,

    async resolve(ctx: ResolveContext, tool: string, args: unknown): Promise<ResolvedArgs> {
      if (!isGithubReadOnlyClient(ctx.upstream)) throw new AdapterError("resolve_failed", "github adapter needs a GithubReadOnlyClient as the read-only upstream");
      const a = asRecord(args);
      if (!a) throw new AdapterError("resolve_failed", "arguments must be an object");
      const client = ctx.upstream;
      const signal = signalFor(ctx.deadline);
      switch (shortTool(tool)) {
        case "merge_pull_request":
          return resolveMerge(client, a, signal, ctx.logger);
        case "dispatch_workflow":
          return resolveDispatch(client, a, signal, ctx.logger);
        case "read_pull_request":
          return resolveRead(client, a, signal, ctx.logger);
        default:
          throw new AdapterError("resolve_failed", `unknown tool ${tool}`);
      }
    },

    async mint(ctx: CredentialContext, action: FrozenAction): Promise<Credential> {
      const tool = shortTool(action.tool);
      const permissions = MINT_PERMISSIONS[tool as GithubToolName];
      if (!permissions) throw new AdapterError("credential_failed", `unknown tool ${action.tool}`);
      const repo = requireRepo(action.args.repo, "credential_failed");
      const [owner, name] = repo.split("/") as [string, string];

      const appId = ctx.secrets.app_id;
      const privateKey = ctx.secrets.private_key;
      if (!appId || !privateKey) throw new AdapterError("credential_failed", "secrets app_id and private_key are required");
      const headers = appHeaders(appId, privateKey, now());
      const signal = signalFor(ctx.deadline);
      const installationId = await findInstallation(mintFetch, headers, ctx.secrets[OPTIONAL_SECRET_INSTALLATION_ID], owner, name, signal);
      const { token, expiresAt } = await mintInstallationToken(mintFetch, { headers, installationId, repo, permissions, implicit: IMPLICIT_PERMISSIONS, signal, nowMs: now() });

      const permText = Object.entries(permissions)
        .map(([k, v]) => `${k}:${v}`)
        .sort()
        .join(" ");
      const logger = ctx.logger;
      return {
        material: token,
        expiresAt,
        scope: `github installation token: repo=${repo} ${permText} installation=${installationId} expires=${expiresAt.toISOString()}`,
        revoke: () => revokeToken(mintFetch, token, logger),
      };
    },

    async execute(ctx: ExecuteContext, action: FrozenAction, credential: Credential): Promise<ToolResult> {
      const token = credential.material;
      if (typeof token !== "string" || token.length === 0) throw new AdapterError("credential_failed", "credential material is not an installation token");
      const headers = githubHeaders(`Bearer ${token}`, { "content-type": "application/json" });
      const signal = signalFor(ctx.deadline);
      const call = (path: string, init: RequestInit) => executeRequest(ctx.fetch, path, { ...init, headers, signal });
      switch (shortTool(action.tool)) {
        case "merge_pull_request":
          return executeMerge(call, action);
        case "dispatch_workflow":
          return executeDispatch(call, action, ctx.logger, now);
        case "read_pull_request":
          return executeRead(call, action);
        default:
          throw new AdapterError("upstream_rejected", `unknown tool ${action.tool}`);
      }
    },
  };
}

/** Default instance: global fetch, wall clock. */
export const githubAdapter: Adapter = createGithubAdapter();

// ---------- resolve ----------

async function resolveMerge(client: GithubReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, logger: Logger): Promise<ResolvedArgs> {
  const repo = normaliseRepo(a.repo);
  const pr = requirePrNumber(a.pr);
  const method = normaliseMethod(a.method);
  const body = await lookupPullRequest(client, repo, pr, signal, logger);
  const state = getString(body, "state");
  if (state !== "open") throw new AdapterError("resolve_failed", `PR #${pr} on ${repo} is ${state ?? "in an unknown state"}, not open`);
  if (asRecord(body)?.merged === true) throw new AdapterError("resolve_failed", `PR #${pr} on ${repo} is already merged`);
  if (asRecord(body)?.draft === true) throw new AdapterError("resolve_failed", `PR #${pr} on ${repo} is a draft`);
  const headSha = getString(asRecord(body)?.head, "sha");
  const base = getString(asRecord(body)?.base, "ref");
  const baseRepo = getString(asRecord(asRecord(body)?.base)?.repo, "full_name");
  if (!headSha || !SHA_RE.test(headSha)) throw new AdapterError("resolve_failed", `PR #${pr} has no usable head sha`);
  if (!base) throw new AdapterError("resolve_failed", `PR #${pr} has no base ref`);
  if (baseRepo && baseRepo.toLowerCase() !== repo) throw new AdapterError("resolve_failed", `PR #${pr} belongs to ${baseRepo.toLowerCase()}, not ${repo} (repository moved or renamed)`);
  return { args: { repo, pr, base, head_sha: headSha, method } };
}

async function resolveDispatch(client: GithubReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, logger: Logger): Promise<ResolvedArgs> {
  const repo = normaliseRepo(a.repo);
  const workflowIn = typeof a.workflow === "string" ? a.workflow.trim() : "";
  if (!workflowIn) throw new AdapterError("resolve_failed", "workflow is required");
  const ref = typeof a.ref === "string" ? a.ref.trim() : "";
  if (!ref) throw new AdapterError("resolve_failed", "ref is required");
  if (SHA_RE.test(ref)) throw new AdapterError("resolve_failed", "ref must be a branch or tag, not a commit sha (workflow_dispatch does not accept shas)");
  const inputs = normaliseInputs(a.inputs);

  logger.debug("github.resolve dispatch_workflow", { repo, workflow: workflowIn, ref });
  const wf = await clientGet(client, `/repos/${repo}/actions/workflows/${encodeURIComponent(workflowIn)}`, signal, `workflow ${workflowIn} not found on ${repo}`);
  const wfState = getString(wf, "state");
  if (wfState !== "active") throw new AdapterError("resolve_failed", `workflow ${workflowIn} on ${repo} is ${wfState ?? "in an unknown state"}, not active`);
  const wfPath = getString(wf, "path");
  if (!wfPath) throw new AdapterError("resolve_failed", `workflow ${workflowIn} on ${repo} has no path`);
  // Normalise id or file name to the file name so both spellings sign the same bytes.
  const workflow = wfPath.slice(wfPath.lastIndexOf("/") + 1);

  const commit = await clientGet(client, `/repos/${repo}/commits/${encodeURIComponent(ref)}`, signal, `ref ${ref} not found on ${repo}`);
  const refSha = getString(commit, "sha");
  if (!refSha || !SHA_RE.test(refSha)) throw new AdapterError("resolve_failed", `ref ${ref} on ${repo} did not resolve to a commit`);

  return { args: { repo, workflow, ref, ref_sha: refSha, inputs } };
}

async function resolveRead(client: GithubReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, logger: Logger): Promise<ResolvedArgs> {
  const repo = normaliseRepo(a.repo);
  const pr = requirePrNumber(a.pr);
  await lookupPullRequest(client, repo, pr, signal, logger);
  return { args: { repo, pr } };
}

async function lookupPullRequest(client: GithubReadOnlyClient, repo: string, pr: number, signal: AbortSignal, logger: Logger): Promise<unknown> {
  logger.debug("github.resolve pull request lookup", { repo, pr });
  return clientGet(client, `/repos/${repo}/pulls/${pr}`, signal, `PR #${pr} not found on ${repo}`);
}

async function clientGet(client: GithubReadOnlyClient, path: string, signal: AbortSignal, notFound: string): Promise<unknown> {
  try {
    return await client.get(path, { signal });
  } catch (e) {
    if (e instanceof GithubApiError && e.status === 404) throw new AdapterError("resolve_failed", notFound);
    throw toAdapterError(e, "upstream_rejected");
  }
}

function normaliseRepo(x: unknown): string {
  if (typeof x !== "string") throw new AdapterError("resolve_failed", "repo must be a string owner/name");
  return requireRepo(x.trim().toLowerCase(), "resolve_failed");
}

function requireRepo(x: unknown, code: "resolve_failed" | "credential_failed"): string {
  if (typeof x !== "string" || !REPO_RE.test(x)) throw new AdapterError(code, "repo must be lowercase owner/name");
  return x;
}

function requirePrNumber(x: unknown): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < 1) throw new AdapterError("resolve_failed", "pr must be a positive integer");
  return x;
}

function normaliseMethod(x: unknown): MergeMethod {
  if (x === undefined || x === null) return "squash";
  const m = typeof x === "string" ? x.trim().toLowerCase() : "";
  if (!(MERGE_METHODS as readonly string[]).includes(m)) throw new AdapterError("resolve_failed", `method must be one of ${MERGE_METHODS.join(", ")}`);
  return m as MergeMethod;
}

function normaliseInputs(x: unknown): Record<string, string> {
  if (x === undefined || x === null) return {};
  const r = asRecord(x);
  if (!r) throw new AdapterError("resolve_failed", "inputs must be an object of string values");
  const out: Record<string, string> = {};
  for (const k of Object.keys(r)) {
    const v = r[k];
    if (typeof v !== "string") throw new AdapterError("resolve_failed", `input ${k} must be a string`);
    out[k] = v;
  }
  return out;
}

// ---------- execute ----------

type Call = (path: string, init: RequestInit) => Promise<Response>;

async function executeRequest(f: FetchFn, path: string, init: RequestInit): Promise<Response> {
  try {
    return await f(GITHUB_API_BASE + path, init);
  } catch (e) {
    if (isAbortError(e)) throw new AdapterError("timeout", "GitHub request timed out", true);
    throw new AdapterError("upstream_unreachable", `GitHub unreachable: ${errorMessage(e)}`, true);
  }
}

async function executeMerge(call: Call, action: FrozenAction): Promise<ToolResult> {
  const { repo, pr, head_sha, method, base } = action.args;
  if (typeof repo !== "string" || typeof pr !== "number" || typeof head_sha !== "string" || typeof method !== "string") {
    throw new AdapterError("upstream_rejected", "frozen action is missing merge arguments");
  }
  // `sha` makes GitHub itself refuse the merge if the branch head moved after the approver signed.
  const res = await call(`/repos/${repo}/pulls/${pr}/merge`, { method: "PUT", body: JSON.stringify({ sha: head_sha, merge_method: method }) });
  if (res.status === 409) throw new AdapterError("precondition_failed", `head sha of PR #${pr} moved since approval`, false, { repo, pr, head_sha });
  if (res.status === 405) throw new AdapterError("precondition_failed", `PR #${pr} is no longer mergeable`, false, { repo, pr, head_sha });
  if (!res.ok) throw new AdapterError("upstream_rejected", `GitHub ${res.status} merging PR #${pr}`, res.status >= 500, { repo, pr, status: res.status });
  const body = await parseJson(res, "merge").catch(() => undefined);
  const mergeSha = getString(body, "sha");
  if (asRecord(body)?.merged !== true || !mergeSha) throw new AdapterError("upstream_rejected", `GitHub did not confirm the merge of PR #${pr}`, false, { repo, pr });
  return {
    content: { merged: true, sha: mergeSha, message: getString(body, "message") ?? "" },
    evidence: { merge_sha: mergeSha, repo, pr, head_sha, base: typeof base === "string" ? base : null, method },
  };
}

async function executeDispatch(call: Call, action: FrozenAction, logger: Logger, now: () => number): Promise<ToolResult> {
  const { repo, workflow, ref, ref_sha, inputs } = action.args;
  if (typeof repo !== "string" || typeof workflow !== "string" || typeof ref !== "string" || typeof ref_sha !== "string") {
    throw new AdapterError("upstream_rejected", "frozen action is missing dispatch arguments");
  }
  // workflow_dispatch has no sha parameter, so confirm the ref still points at the signed commit before mutating anything.
  const head = await call(`/repos/${repo}/commits/${encodeURIComponent(ref)}`, { method: "GET" });
  if (!head.ok) throw new AdapterError("upstream_rejected", `GitHub ${head.status} checking ${ref} on ${repo}`, head.status >= 500, { repo, ref, status: head.status });
  const currentSha = getString(await parseJson(head, "commits").catch(() => undefined), "sha");
  if (currentSha !== ref_sha) throw new AdapterError("precondition_failed", `${ref} on ${repo} moved since approval`, false, { repo, ref, ref_sha, current_sha: currentSha ?? null });

  const dispatchedAt = now();
  const res = await call(`/repos/${repo}/actions/workflows/${encodeURIComponent(workflow)}/dispatches`, {
    method: "POST",
    body: JSON.stringify({ ref, inputs: asRecord(inputs) ?? {} }),
  });
  if (res.status !== 204) throw new AdapterError("upstream_rejected", `GitHub ${res.status} dispatching ${workflow}`, res.status >= 500, { repo, workflow, ref, status: res.status });

  // Best-effort evidence: one GET for the run this dispatch created. Failure here never turns the dispatch into a failure.
  let run: { id: number; url: string | null } | undefined;
  try {
    const q = `event=workflow_dispatch&head_sha=${ref_sha}&per_page=1`;
    const runs = await call(`/repos/${repo}/actions/workflows/${encodeURIComponent(workflow)}/runs?${q}`, { method: "GET" });
    if (runs.ok) {
      const list = asRecord(await parseJson(runs, "runs"))?.workflow_runs;
      const first = Array.isArray(list) ? list[0] : undefined;
      const id = getNumber(first, "id");
      const created = getString(first, "created_at");
      if (id !== undefined && created && Date.parse(created) >= dispatchedAt - 30_000) run = { id, url: getString(first, "html_url") ?? null };
    }
  } catch (e) {
    logger.warn("github: run lookup after dispatch failed", { err: errorMessage(e) });
  }
  return {
    content: { dispatched: true, ...(run ? { run_id: run.id, run_url: run.url } : {}) },
    evidence: { dispatched: true, status: 204, repo, workflow, ref, ref_sha, run_id: run?.id ?? null, run_url: run?.url ?? null },
  };
}

async function executeRead(call: Call, action: FrozenAction): Promise<ToolResult> {
  const { repo, pr } = action.args;
  if (typeof repo !== "string" || typeof pr !== "number") throw new AdapterError("upstream_rejected", "frozen action is missing read arguments");
  const res = await call(`/repos/${repo}/pulls/${pr}`, { method: "GET" });
  if (!res.ok) throw new AdapterError("upstream_rejected", `GitHub ${res.status} reading PR #${pr}`, res.status >= 500, { repo, pr, status: res.status });
  const body = await parseJson(res, "pulls").catch(() => undefined);
  const b = asRecord(body);
  if (!b) throw new AdapterError("upstream_rejected", `GitHub returned a malformed PR #${pr}`);
  const content: Record<string, JsonValue> = {
    repo,
    pr,
    title: getString(b, "title") ?? null,
    state: getString(b, "state") ?? null,
    draft: b.draft === true,
    merged: b.merged === true,
    mergeable: typeof b.mergeable === "boolean" ? b.mergeable : null,
    mergeable_state: getString(b, "mergeable_state") ?? null,
    head: { ref: getString(b.head, "ref") ?? null, sha: getString(b.head, "sha") ?? null },
    base: { ref: getString(b.base, "ref") ?? null },
    author: getString(b.user, "login") ?? null,
    html_url: getString(b, "html_url") ?? null,
  };
  return { content, evidence: { repo, pr, state: content.state ?? null, head_sha: getString(b.head, "sha") ?? null } };
}

function shortTool(tool: string): string {
  const prefix = `${manifest.name}.`;
  return tool.startsWith(prefix) ? tool.slice(prefix.length) : tool;
}
