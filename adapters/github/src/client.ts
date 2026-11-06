// HTTP plumbing for api.github.com. Everything here is fetch-injectable so tests run offline.
import { AdapterError } from "@signeto/adapter-sdk";
import { GITHUB_API_HOST } from "./manifest.js";

export const GITHUB_API_BASE = `https://${GITHUB_API_HOST}`;
export const API_VERSION = "2022-11-28";
export const USER_AGENT = "signeto-adapter-github";

export type FetchFn = typeof fetch;

/** Thrown by the read-only client on a non-2xx response. Carries the status and a short message, never the raw body. */
export class GithubApiError extends Error {
  override name = "GithubApiError";
  constructor(
    readonly status: number,
    readonly path: string,
    message?: string,
  ) {
    super(message ?? `GitHub ${status} on GET ${path}`);
  }
}

/**
 * What `resolve` needs from the gateway's read-only upstream client. The gateway types it as `unknown`;
 * the adapter checks the shape at runtime and refuses anything else (`resolve_failed`).
 */
export interface GithubReadOnlyClient {
  /** GET `path` (relative to https://api.github.com) and return the parsed JSON body. Rejects with GithubApiError on non-2xx. */
  get(path: string, opts?: { signal?: AbortSignal }): Promise<unknown>;
}

export function isGithubReadOnlyClient(x: unknown): x is GithubReadOnlyClient {
  return typeof x === "object" && x !== null && typeof (x as { get?: unknown }).get === "function";
}

export interface ReadOnlyClientOptions {
  /** A read-scoped credential: an installation token minted with read permissions, or a fine-grained PAT with read-only access. Never a write credential. */
  token: string;
  fetch?: FetchFn;
  baseUrl?: string;
}

/** A GET-only client over api.github.com. There is no method parameter, so it cannot write by construction. */
export function createReadOnlyClient(opts: ReadOnlyClientOptions): GithubReadOnlyClient {
  const f = opts.fetch ?? globalThis.fetch;
  const base = opts.baseUrl ?? GITHUB_API_BASE;
  return {
    async get(path, o = {}) {
      let res: Response;
      try {
        res = await f(base + path, {
          method: "GET",
          headers: githubHeaders(`Bearer ${opts.token}`),
          ...(o.signal ? { signal: o.signal } : {}),
        });
      } catch (e) {
        throw new GithubApiError(0, path, `GitHub unreachable on GET ${path}: ${errorMessage(e)}`);
      }
      if (!res.ok) throw new GithubApiError(res.status, path);
      return parseJson(res, path);
    },
  };
}

export function githubHeaders(authorization: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    authorization,
    "x-github-api-version": API_VERSION,
    "user-agent": USER_AGENT,
    ...extra,
  };
}

export async function parseJson(res: Response, path: string): Promise<unknown> {
  const text = await res.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new GithubApiError(res.status, path, `GitHub returned a malformed body on ${path}`);
  }
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function isAbortError(e: unknown): boolean {
  return e instanceof Error && (e.name === "AbortError" || e.name === "TimeoutError");
}

/** Milliseconds left before `deadline`; throws `timeout` if none. */
export function remainingMs(deadline: Date, now = Date.now()): number {
  const ms = deadline.getTime() - now;
  if (ms <= 0) throw new AdapterError("timeout", "deadline already passed", true);
  return ms;
}

export function signalFor(deadline: Date): AbortSignal {
  return AbortSignal.timeout(remainingMs(deadline));
}

/** Translate a low-level failure into the fail-closed vocabulary of docs/adapters.md §4. */
export function toAdapterError(e: unknown, fallback: "resolve_failed" | "upstream_rejected" | "credential_failed"): AdapterError {
  if (e instanceof AdapterError) return e;
  if (isAbortError(e)) return new AdapterError("timeout", "GitHub request timed out", true);
  if (e instanceof GithubApiError) {
    if (e.status === 0) return new AdapterError("upstream_unreachable", e.message, true);
    return new AdapterError(fallback, e.message, e.status >= 500, { status: e.status });
  }
  return new AdapterError(fallback, errorMessage(e));
}

export function asRecord(x: unknown): Record<string, unknown> | undefined {
  return typeof x === "object" && x !== null && !Array.isArray(x) ? (x as Record<string, unknown>) : undefined;
}

export function getString(x: unknown, key: string): string | undefined {
  const v = asRecord(x)?.[key];
  return typeof v === "string" ? v : undefined;
}

export function getNumber(x: unknown, key: string): number | undefined {
  const v = asRecord(x)?.[key];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
