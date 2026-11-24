// HTTP plumbing for Alpaca's paper trading and market data APIs. Everything is fetch-injectable so tests run offline.
//
// `resolve` needs to read the account, an asset and a price before anything is approved. Alpaca has no read-only
// keys, so the only key there is the account's full trading key. The read-only client is therefore read-only by
// construction, not by credential: it has no method parameter and sends GET only, to an allowlisted set of paths.
// The key itself comes from the gateway's store for each call and is never kept here.
import { AdapterError } from "@signeto/adapter-sdk";
import { ALPACA_DATA_HOST, ALPACA_PAPER_HOST, SYMBOL_BODY } from "./manifest.js";

export const ALPACA_PAPER_BASE = `https://${ALPACA_PAPER_HOST}`;
export const ALPACA_DATA_BASE = `https://${ALPACA_DATA_HOST}`;
export const USER_AGENT = "signeto-adapter-alpaca";

export type FetchFn = typeof fetch;
export type AlpacaApi = "trading" | "data";

/** The key pair, as the gateway's store holds it. */
export interface AlpacaKey {
  key_id: string;
  secret_key: string;
}

/**
 * An OAuth access token for one paper account. Signeto Cloud only: held by its custody service, never by a gateway.
 * Self-hosted gateways use the key pair.
 */
export interface AlpacaOAuthToken {
  access_token: string;
}

/** What an Alpaca request is authorized with. */
export type AlpacaCredential = AlpacaKey | AlpacaOAuthToken;

export function isOAuthToken(c: unknown): c is AlpacaOAuthToken {
  return typeof c === "object" && c !== null && "access_token" in c;
}

/** Thrown on a non-2xx answer. Carries the status and Alpaca's short message, never the request's headers. */
export class AlpacaApiError extends Error {
  override name = "AlpacaApiError";
  constructor(
    readonly status: number,
    readonly path: string,
    message?: string,
  ) {
    super(message ?? `Alpaca ${status} on ${path}`);
  }
}

/**
 * A key part as Alpaca issues it: printable ASCII, no spaces or line breaks. Checked before the key goes into a
 * header, because fetch rejects a bad header value with an error that quotes the whole value, key included.
 */
const KEY_PART_RE = /^[\x21-\x7e]{1,256}$/;

export function isWellFormedKey(key: AlpacaKey | undefined): key is AlpacaKey {
  return !!key && typeof key.key_id === "string" && typeof key.secret_key === "string" && KEY_PART_RE.test(key.key_id) && KEY_PART_RE.test(key.secret_key);
}

/** The fixed message for a stored key that is not well formed. It never quotes the key. */
export const MALFORMED_KEY_MESSAGE = "the stored Alpaca key has characters a key can't have (a space or a line break?): set it again with signeto secrets set alpaca key_id, then secret_key";

/** A token as Alpaca issues it (printable ASCII, no spaces), checked before it goes into a header for the same reason. */
const TOKEN_RE = /^[\x21-\x7e]{8,512}$/;

/** The fixed message for an OAuth token that is not well formed. It never quotes the token. */
export const MALFORMED_TOKEN_MESSAGE = "the Alpaca OAuth token has characters a token can't have: connect the Alpaca account again";

/** A key pair or a token that is safe to put in a header. A value carrying both forms is refused: one or the other. */
export function isWellFormedCredential(c: unknown): c is AlpacaCredential {
  if (isOAuthToken(c)) return typeof c.access_token === "string" && TOKEN_RE.test(c.access_token) && !("key_id" in c) && !("secret_key" in c);
  return isWellFormedKey(c as AlpacaKey | undefined);
}

/** The fixed message for a credential that is not well formed, by its kind. */
export function malformedMessage(c: unknown): string {
  return isOAuthToken(c) ? MALFORMED_TOKEN_MESSAGE : MALFORMED_KEY_MESSAGE;
}

/**
 * Why a request that carried the key failed, without its message: fetch's own errors can quote request headers.
 * Only the error's class name is kept (TypeError, AbortError), which never carries data.
 */
export function failureName(e: unknown): string {
  const name = (e as { name?: unknown })?.name;
  return typeof name === "string" && /^[A-Za-z]{1,40}$/.test(name) ? name : "Error";
}

/** The request headers for a key pair (`APCA-API-*`) or an OAuth token (`Authorization: Bearer`). `extra` can't replace them. */
export function alpacaHeaders(cred: AlpacaCredential, extra: Record<string, string> = {}): Record<string, string> {
  const auth: Record<string, string> = isOAuthToken(cred) ? { authorization: `Bearer ${cred.access_token}` } : { "apca-api-key-id": cred.key_id, "apca-api-secret-key": cred.secret_key };
  return { accept: "application/json", "user-agent": USER_AGENT, ...extra, ...auth };
}

/** Alpaca's error body is `{code, message}`; only the message is kept, cut short (it may echo a symbol, never a key). */
export async function errorMessage(res: Response): Promise<string | undefined> {
  try {
    const b = (await res.json()) as { message?: unknown };
    return typeof b.message === "string" ? b.message.slice(0, 200) : undefined;
  } catch {
    return undefined;
  }
}

/** What `resolve` gets as its read-only upstream. The gateway types it as `unknown`; the adapter checks the shape. */
export interface AlpacaReadOnlyClient {
  /** GET `path` on the trading or data API and return the parsed body. Rejects with AlpacaApiError on non-2xx. */
  get(api: AlpacaApi, path: string, opts?: { signal?: AbortSignal }): Promise<unknown>;
}

export function isAlpacaReadOnlyClient(x: unknown): x is AlpacaReadOnlyClient {
  return typeof x === "object" && x !== null && typeof (x as { get?: unknown }).get === "function";
}

/** The only reads `resolve` makes: the account, the market clock, one asset, one position, one order, the latest trade of one symbol. */
export const READ_PATHS: Readonly<Record<AlpacaApi, RegExp>> = {
  trading: new RegExp(`^/v2/(account|clock|assets/${SYMBOL_BODY}|positions/${SYMBOL_BODY}|orders/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`),
  data: new RegExp(`^/v2/stocks/${SYMBOL_BODY}/trades/latest(\\?feed=(iex|sip))?$`),
};

/** Whether `path` is one of the reads `resolve` makes on `api`. Signeto Cloud checks reads with this same list. */
export function isAllowedRead(api: unknown, path: unknown): api is AlpacaApi {
  return (api === "trading" || api === "data") && typeof path === "string" && READ_PATHS[api].test(path);
}

export interface ReadOnlyClientOptions {
  /** Reads the credential (the key pair from the gateway's store, or an OAuth token) for each request; nothing is cached here. */
  key: () => AlpacaCredential | undefined;
  fetch?: FetchFn;
}

/** A GET-only client over Alpaca's paper trading and data APIs, limited to the reads `resolve` makes. */
export function createReadOnlyClient(opts: ReadOnlyClientOptions): AlpacaReadOnlyClient {
  const f = opts.fetch ?? globalThis.fetch;
  return {
    async get(api, path, o = {}) {
      if (!isAllowedRead(api, path)) throw new AdapterError("resolve_failed", `read-only client refuses ${api} ${path}`);
      const key = opts.key();
      if (!key || (!isOAuthToken(key) && (!key.key_id || !key.secret_key))) throw new AdapterError("resolve_failed", "the Alpaca key is not set: signeto secrets set alpaca key_id, then secret_key");
      if (!isWellFormedCredential(key)) throw new AdapterError("resolve_failed", malformedMessage(key));
      const base = api === "trading" ? ALPACA_PAPER_BASE : ALPACA_DATA_BASE;
      let res: Response;
      try {
        res = await f(base + path, { method: "GET", headers: alpacaHeaders(key), redirect: "error", ...(o.signal ? { signal: o.signal } : {}) });
      } catch (e) {
        const name = failureName(e);
        if (name === "AbortError" || name === "TimeoutError") throw new AdapterError("timeout", "Alpaca did not answer in time", true);
        throw new AdapterError("upstream_unreachable", `Alpaca not reachable (${name})`, true);
      }
      if (!res.ok) throw new AlpacaApiError(res.status, path, await errorMessage(res));
      return res.json();
    },
  };
}
