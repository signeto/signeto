// GitHub App installation-token plumbing shared by `mint` (write-scoped, one token per approved action) and the
// App-backed read-only client (read-scoped, one cached token per repository for `resolve`). Every failure is an
// AdapterError in the fail-closed vocabulary of docs/adapters.md §4; nothing here ever echoes a key, JWT or token.
import { AdapterError } from "@signeto/adapter-sdk";
import type { Logger } from "@signeto/adapter-sdk";
import { GITHUB_API_BASE, asRecord, errorMessage, getNumber, getString, githubHeaders, isAbortError, parseJson, type FetchFn } from "./client.js";
import { buildAppJwt } from "./jwt.js";

export type PermissionLevel = "read" | "write";
export type PermissionSet = Readonly<Record<string, PermissionLevel>>;

/** GitHub installation tokens live one hour; anything longer is not the credential we asked for. */
export const MAX_TOKEN_TTL_MS = 3_600_000;
export const EXPIRY_SKEW_MS = 60_000;

/** Headers authenticated as the App itself (RS256 JWT). Throws `credential_failed` without echoing the key. */
export function appHeaders(appId: string, privateKey: string, nowMs: number): Record<string, string> {
  let jwt: string;
  try {
    jwt = buildAppJwt(appId, privateKey, { nowS: nowMs / 1000 });
  } catch (e) {
    throw new AdapterError("credential_failed", `cannot build GitHub App JWT: ${errorMessage(e)}`);
  }
  return githubHeaders(`Bearer ${jwt}`, { "content-type": "application/json" });
}

export async function mintRequest(f: FetchFn, path: string, init: RequestInit): Promise<Response> {
  try {
    return await f(GITHUB_API_BASE + path, init);
  } catch (e) {
    if (isAbortError(e)) throw new AdapterError("timeout", "GitHub request timed out while minting", true);
    throw new AdapterError("upstream_unreachable", `GitHub unreachable while minting: ${errorMessage(e)}`, true);
  }
}

/** The installation id: from the `installation_id` secret when set, else `GET /repos/{owner}/{repo}/installation`. */
export async function findInstallation(f: FetchFn, headers: Record<string, string>, fromSecrets: string | undefined, owner: string, name: string, signal: AbortSignal): Promise<number> {
  if (fromSecrets !== undefined && fromSecrets !== "") {
    if (!/^\d+$/.test(fromSecrets)) throw new AdapterError("credential_failed", "secret installation_id must be numeric");
    return Number(fromSecrets);
  }
  const res = await mintRequest(f, `/repos/${owner}/${name}/installation`, { method: "GET", headers, signal });
  if (res.status === 404) throw new AdapterError("credential_failed", `GitHub App is not installed on ${owner}/${name}`);
  if (!res.ok) throw new AdapterError("credential_failed", `GitHub ${res.status} looking up the installation`, res.status >= 500, { status: res.status });
  const body = await parseJson(res, "/repos/*/installation").catch(() => undefined);
  const id = getNumber(body, "id");
  if (id === undefined) throw new AdapterError("credential_failed", "GitHub installation lookup returned no id");
  return id;
}

export interface InstallationInfo {
  id: number;
  /** What the installation has accepted (`{checks: "write", ...}`); empty when GitHub did not say. */
  permissions: Readonly<Record<string, string>>;
}

/**
 * Like `findInstallation`, plus the permissions the installation has accepted, so `mint` can ask for an optional
 * permission (checks:write) only where the owner granted it. With `installation_id` in secrets this is one
 * `GET /app/installations/{id}`; a failure there leaves `permissions` empty (the mint itself still decides).
 */
export async function lookupInstallation(f: FetchFn, headers: Record<string, string>, fromSecrets: string | undefined, owner: string, name: string, signal: AbortSignal): Promise<InstallationInfo> {
  let body: unknown;
  let id: number;
  if (fromSecrets !== undefined && fromSecrets !== "") {
    id = await findInstallation(f, headers, fromSecrets, owner, name, signal);
    try {
      const res = await mintRequest(f, `/app/installations/${id}`, { method: "GET", headers, signal });
      body = res.ok ? await parseJson(res, "/app/installations/*").catch(() => undefined) : undefined;
    } catch {
      body = undefined;
    }
  } else {
    const res = await mintRequest(f, `/repos/${owner}/${name}/installation`, { method: "GET", headers, signal });
    if (res.status === 404) throw new AdapterError("credential_failed", `GitHub App is not installed on ${owner}/${name}`);
    if (!res.ok) throw new AdapterError("credential_failed", `GitHub ${res.status} looking up the installation`, res.status >= 500, { status: res.status });
    body = await parseJson(res, "/repos/*/installation").catch(() => undefined);
    const found = getNumber(body, "id");
    if (found === undefined) throw new AdapterError("credential_failed", "GitHub installation lookup returned no id");
    id = found;
  }
  const permissions: Record<string, string> = {};
  const p = asRecord(asRecord(body)?.permissions);
  if (p) for (const [k, v] of Object.entries(p)) if (typeof v === "string") permissions[k] = v;
  return { id, permissions };
}

export interface InstallationTokenRequest {
  headers: Record<string, string>;
  installationId: number;
  /** Lowercase `owner/name`; the token is scoped to `repositories: [name]`. */
  repo: string;
  permissions: PermissionSet;
  signal: AbortSignal;
  nowMs: number;
  /** Permissions GitHub adds on its own and that are acceptable in the grant (e.g. `metadata: read`). */
  implicit?: PermissionSet;
}

export interface InstallationToken {
  token: string;
  expiresAt: Date;
}

/**
 * `POST /app/installations/{id}/access_tokens` for one repository and exactly `permissions`. Refuses a response
 * without a token, without a usable `expires_at`, already expired, valid for more than an hour, or broader than requested.
 */
export async function mintInstallationToken(f: FetchFn, req: InstallationTokenRequest): Promise<InstallationToken> {
  const name = req.repo.slice(req.repo.indexOf("/") + 1);
  const res = await mintRequest(f, `/app/installations/${req.installationId}/access_tokens`, {
    method: "POST",
    headers: req.headers,
    body: JSON.stringify({ repositories: [name], permissions: req.permissions }),
    signal: req.signal,
  });
  if (res.status !== 201) throw new AdapterError("credential_failed", `GitHub ${res.status} minting installation token`, res.status >= 500, { status: res.status });
  const body = await parseJson(res, "/app/installations/*/access_tokens").catch(() => {
    throw new AdapterError("credential_failed", "GitHub returned a malformed token response");
  });
  const token = getString(body, "token");
  if (!token) throw new AdapterError("credential_failed", "GitHub token response has no token");
  const expiresAtRaw = getString(body, "expires_at");
  const expiresAt = expiresAtRaw ? new Date(expiresAtRaw) : undefined;
  if (!expiresAt || Number.isNaN(expiresAt.getTime())) throw new AdapterError("credential_failed", "GitHub token response has no usable expires_at");
  if (expiresAt.getTime() <= req.nowMs) throw new AdapterError("credential_failed", "GitHub returned an already-expired token");
  if (expiresAt.getTime() > req.nowMs + MAX_TOKEN_TTL_MS + EXPIRY_SKEW_MS) throw new AdapterError("credential_failed", "GitHub returned a token valid for more than one hour");
  assertNotBroader(body, req.repo, req.permissions, req.implicit);
  return { token, expiresAt };
}

const LEVEL_RANK: Record<PermissionLevel, number> = { read: 1, write: 2 };

/** docs/adapters.md §3.2: refuse a credential broader than requested where we can tell. */
export function assertNotBroader(body: unknown, repo: string, requested: PermissionSet, implicit: PermissionSet = {}): void {
  const granted = asRecord(asRecord(body)?.permissions);
  if (granted) {
    for (const [k, v] of Object.entries(granted)) {
      const want = requested[k] ?? implicit[k];
      const got = typeof v === "string" ? LEVEL_RANK[v as PermissionLevel] : undefined;
      if (!want || got === undefined || got > LEVEL_RANK[want]) throw new AdapterError("credential_failed", `GitHub granted permission ${k}:${String(v)} beyond the requested scope`);
    }
  }
  const repos = asRecord(body)?.repositories;
  if (Array.isArray(repos)) {
    for (const r of repos) {
      const full = getString(r, "full_name");
      if (!full || full.toLowerCase() !== repo) throw new AdapterError("credential_failed", `GitHub granted access to ${full ?? "an unknown repository"} beyond ${repo}`);
    }
  }
}

/** Best effort `DELETE /installation/token`: a failure is logged; the token expires within the hour anyway. */
export async function revokeToken(f: FetchFn, token: string, logger: Logger): Promise<void> {
  try {
    const res = await f(`${GITHUB_API_BASE}/installation/token`, {
      method: "DELETE",
      headers: githubHeaders(`Bearer ${token}`),
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status !== 204) logger.warn("github: installation token revoke returned non-204", { status: res.status });
  } catch (e) {
    logger.warn("github: installation token revoke failed", { err: errorMessage(e) });
  }
}

/** GitHub adds `metadata: read` to every installation token whatever was requested; it is read-only repository metadata. */
export const IMPLICIT_PERMISSIONS: PermissionSet = Object.freeze({ metadata: "read" });
