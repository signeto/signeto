// The App-backed read-only client for `resolve`: no stored PAT, just the App credentials `mint` already uses.
// Each `get` is confined to one repository (`/repos/{owner}/{repo}/...`) and authenticated with an installation token
// minted for that repository alone with read permissions only, cached until shortly before it expires.
import { AdapterError } from "@signeto/adapter-sdk";
import type { Logger } from "@signeto/adapter-sdk";
import { GITHUB_API_BASE, GithubApiError, errorMessage, githubHeaders, parseJson, type FetchFn, type GithubReadOnlyClient } from "./client.js";
import { appHeaders, findInstallation, mintInstallationToken, type PermissionSet } from "./installation.js";
import { parsePrivateKey } from "./jwt.js";

/** What `resolve` reads: pull requests, commits/refs, workflows. Never a write level on this path. */
export const READ_ONLY_PERMISSIONS: PermissionSet = Object.freeze({ contents: "read", pull_requests: "read", actions: "read" });
/** Per request, only what that path needs, so an App without Actions access still resolves pull requests. */
export function readPermissionsFor(path: string): PermissionSet {
  return /^\/repos\/[^/]+\/[^/]+\/actions(\/|$|\?)/.test(path)
    ? Object.freeze({ contents: "read", actions: "read" })
    : Object.freeze({ contents: "read", pull_requests: "read" });
}

/** GitHub adds `metadata: read` to every installation token; accepted in the grant, never requested. */
import { IMPLICIT_PERMISSIONS } from "./installation.js";

/** A cached read token is replaced this long before its `expires_at`. */
export const READ_TOKEN_REFRESH_MS = 5 * 60_000;

/** Applied to minting when the caller passes no signal. */
const DEFAULT_MINT_TIMEOUT_MS = 15_000;

export interface AppReadOnlyClientOptions {
  /** Numeric GitHub App id (the `app_id` secret). */
  appId: string;
  /**
   * The App's RSA private key, PEM (the `private_key` secret). A function is called for every mint, so a gateway can
   * hand over a credential-store lookup instead of keeping the decrypted key for the client's lifetime.
   */
  privateKey: string | (() => string);
  /** The `installation_id` secret, when set; otherwise looked up per repository. */
  installationId?: string | number;
  fetch?: FetchFn;
  logger?: Logger;
  /** Millisecond clock, injectable for tests. */
  clock?: () => number;
}

interface CachedToken {
  token: string;
  expiresAt: number;
}

const OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const NAME_RE = /^[A-Za-z0-9._-]+$/;
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/**
 * `{ owner, name }` for a path under `/repos/{owner}/{repo}/`, checked after URL normalisation so `..`, encoded dots
 * or a second slash cannot walk the request out of the repository the token was minted for. Anything else is refused.
 */
export function repoOfPath(path: string): { owner: string; name: string } {
  const refuse = (): never => {
    throw new GithubApiError(400, path, "the GitHub App read-only client only serves GET /repos/{owner}/{repo}/... paths");
  };
  if (typeof path !== "string" || !path.startsWith("/repos/") || /[\s#\\]/.test(path)) refuse();
  const raw = path.split("?", 1)[0]!.split("/");
  const owner = raw[2] ?? "";
  const name = raw[3] ?? "";
  if (!OWNER_RE.test(owner) || !NAME_RE.test(name) || name === "." || name === ".." || raw.length < 5) refuse();
  let url: URL;
  try {
    url = new URL(GITHUB_API_BASE + path);
  } catch {
    return refuse();
  }
  const norm = url.pathname.split("/");
  if (url.origin !== GITHUB_API_BASE || norm[1] !== "repos" || norm[2] !== owner || norm[3] !== name || norm.length < 5) refuse();
  return { owner: owner.toLowerCase(), name: name.toLowerCase() };
}

/**
 * A GET-only client authenticated as the GitHub App. Construction checks the App id and key (without echoing the
 * key) so a bad secret is reported at gateway start rather than at the first `resolve`.
 *
 * Failures: a non-2xx GET is a GithubApiError (404 → `resolve` reports "not found"); a path outside
 * `/repos/{owner}/{repo}/` is a GithubApiError(400); a token GitHub will not mint, or mints broader than
 * requested, is an AdapterError `resolve_failed` (timeouts and unreachable stay `timeout` / `upstream_unreachable`).
 */
export function createAppReadOnlyClient(opts: AppReadOnlyClientOptions): GithubReadOnlyClient {
  const appId = String(opts.appId ?? "").trim();
  const privateKey = (): string => (typeof opts.privateKey === "function" ? opts.privateKey() : opts.privateKey);
  if (!/^\d+$/.test(appId)) throw new Error("GitHub App id must be numeric");
  try {
    parsePrivateKey(privateKey());
  } catch {
    throw new Error("GitHub App private key is not a usable RSA private key in PEM format");
  }
  const installationSecret = opts.installationId === undefined || opts.installationId === "" ? undefined : String(opts.installationId);
  if (installationSecret !== undefined && !/^\d+$/.test(installationSecret)) throw new Error("GitHub App installation id must be numeric");
  const f: FetchFn = (input, init) => (opts.fetch ?? globalThis.fetch)(input, init);
  const now = opts.clock ?? (() => Date.now());
  const logger = opts.logger ?? silent;

  if (Object.values(READ_ONLY_PERMISSIONS).some((v) => v !== "read")) throw new Error("read-only client permissions must all be read");

  const tokens = new Map<string, CachedToken>();
  const inflight = new Map<string, Promise<CachedToken>>();
  const installations = new Map<string, number>();

  async function mint(owner: string, name: string, permissions: PermissionSet, signal: AbortSignal): Promise<CachedToken> {
    const repo = `${owner}/${name}`;
    try {
      const headers = appHeaders(appId, privateKey(), now());
      let installationId = installations.get(repo);
      if (installationId === undefined) {
        installationId = await findInstallation(f, headers, installationSecret, owner, name, signal);
        installations.set(repo, installationId);
      }
      let minted;
      try {
        minted = await mintInstallationToken(f, { headers, installationId, repo, permissions, implicit: IMPLICIT_PERMISSIONS, signal, nowMs: now() });
      } catch (e) {
        installations.delete(repo); // an uninstalled or moved App is looked up again next time
        throw e;
      }
      logger.debug("github: minted read-only installation token", { repo, installation: installationId, expires: minted.expiresAt.toISOString() });
      return { token: minted.token, expiresAt: minted.expiresAt.getTime() };
    } catch (e) {
      if (e instanceof AdapterError && e.code === "credential_failed") {
        throw new AdapterError("resolve_failed", `cannot mint a read-only GitHub App token for ${repo}: ${e.message}`, e.retryable, e.detail);
      }
      if (e instanceof AdapterError) throw e;
      throw new AdapterError("resolve_failed", `cannot mint a read-only GitHub App token for ${repo}: ${errorMessage(e)}`);
    }
  }

  async function tokenFor(owner: string, name: string, permissions: PermissionSet, signal: AbortSignal): Promise<string> {
    const key = `${owner}/${name}|${Object.keys(permissions).sort().join(",")}`;
    const cached = tokens.get(key);
    if (cached && now() < cached.expiresAt - READ_TOKEN_REFRESH_MS) return cached.token;
    let p = inflight.get(key);
    if (!p) {
      p = mint(owner, name, permissions, signal).finally(() => inflight.delete(key));
      inflight.set(key, p);
    }
    const fresh = await p;
    tokens.set(key, fresh);
    return fresh.token;
  }

  return {
    async get(path, o = {}) {
      const { owner, name } = repoOfPath(path);
      const signal = o.signal ?? AbortSignal.timeout(DEFAULT_MINT_TIMEOUT_MS);
      const permissions = readPermissionsFor(path);
      const token = await tokenFor(owner, name, permissions, signal);
      let res: Response;
      try {
        res = await f(GITHUB_API_BASE + path, { method: "GET", headers: githubHeaders(`Bearer ${token}`), signal });
      } catch (e) {
        throw new GithubApiError(0, path, `GitHub unreachable on GET ${path}: ${errorMessage(e)}`);
      }
      if (res.status === 401) tokens.delete(`${owner}/${name}|${Object.keys(permissions).sort().join(",")}`); // revoked or expired early: mint afresh next call
      if (!res.ok) throw new GithubApiError(res.status, path);
      return parseJson(res, path);
    },
  };
}
