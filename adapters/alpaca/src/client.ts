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

export function alpacaHeaders(key: AlpacaKey, extra: Record<string, string> = {}): Record<string, string> {
  return { "apca-api-key-id": key.key_id, "apca-api-secret-key": key.secret_key, accept: "application/json", "user-agent": USER_AGENT, ...extra };
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

/** The only reads `resolve` makes: the account, one asset, one order, the latest trade of one symbol. */
const READ_PATHS: Record<AlpacaApi, RegExp> = {
  trading: new RegExp(`^/v2/(account|assets/${SYMBOL_BODY}|orders/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`),
  data: new RegExp(`^/v2/stocks/${SYMBOL_BODY}/trades/latest(\\?feed=(iex|sip))?$`),
};

export interface ReadOnlyClientOptions {
  /** Reads the key pair from the gateway's store for each request; nothing is cached here. */
  key: () => AlpacaKey | undefined;
  fetch?: FetchFn;
}

/** A GET-only client over Alpaca's paper trading and data APIs, limited to the reads `resolve` makes. */
export function createReadOnlyClient(opts: ReadOnlyClientOptions): AlpacaReadOnlyClient {
  const f = opts.fetch ?? globalThis.fetch;
  return {
    async get(api, path, o = {}) {
      if (!READ_PATHS[api].test(path)) throw new AdapterError("resolve_failed", `read-only client refuses ${api} ${path}`);
      const key = opts.key();
      if (!key?.key_id || !key.secret_key) throw new AdapterError("resolve_failed", "the Alpaca key is not set: signeto secrets set alpaca key_id, then secret_key");
      const base = api === "trading" ? ALPACA_PAPER_BASE : ALPACA_DATA_BASE;
      let res: Response;
      try {
        res = await f(base + path, { method: "GET", headers: alpacaHeaders(key), redirect: "error", ...(o.signal ? { signal: o.signal } : {}) });
      } catch (e) {
        throw new AdapterError("upstream_unreachable", `Alpaca not reachable: ${e instanceof Error ? e.message : String(e)}`, true);
      }
      if (!res.ok) throw new AlpacaApiError(res.status, path, await errorMessage(res));
      return res.json();
    },
  };
}
