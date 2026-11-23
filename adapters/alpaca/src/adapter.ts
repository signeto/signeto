// The Alpaca adapter (custody mode, paper trading). docs/adapters.md §3; the signed surface is in manifest.ts.
//
// resolve    checks the account and the asset and prices the order: the limit price, or for a market order the
//            latest trade, times the quantity. That notional value is signed, and policy thresholds test it.
// custody    hands the stored key pair to execute for this one approved action. Alpaca keys are all or nothing, so
//            the narrowing is the adapter's discipline: one order request per approval, then the key is dropped.
// execute    sends exactly one write request (the order, or the cancel). The order carries the action id as its
//            `client_order_id`, so Alpaca itself refuses a second order for the same approval. A market order is
//            re-priced first and refused if the value moved more than `maxDriftPct` from what was signed. After the
//            order, it reads the order back for a few seconds to record the fill when it is quick.
import type { Adapter, CredentialContext, Credential, ExecuteContext, FrozenAction, Logger, ResolveContext, ResolvedArgs, ToolResult } from "@signeto/adapter-sdk";
import type { JsonValue } from "@signeto/protocol";
import { AdapterError } from "@signeto/adapter-sdk";
import { ALPACA_DATA_BASE, ALPACA_PAPER_BASE, AlpacaApiError, alpacaHeaders, errorMessage, isAlpacaReadOnlyClient, type AlpacaKey, type AlpacaReadOnlyClient, type FetchFn } from "./client.js";
import { centsOf, formatPrice, notional, notionalCents, parsePrice } from "./decimal.js";
import { ACCOUNT_LABEL, MAX_QTY, ORDER_ID_PATTERN, ORDER_STATUSES, ORDER_TYPES, SECRET_KEY_ID, SECRET_SECRET_KEY, SIDES, SYMBOL_PATTERN, TIMES_IN_FORCE, manifest } from "./manifest.js";

export type AlpacaToolName = "place_order" | "cancel_order" | "read_positions" | "read_orders";

export interface AlpacaAdapterOptions {
  /** Wall clock (tests). */
  now?: () => number;
  /** Sleep between fill reads (tests). */
  sleep?: (ms: number) => Promise<void>;
  /** How long execute reads the order back for a fill. Default 3 s. */
  settleMs?: number;
  /** A market order is refused if its value moved more than this from what was signed. Default 5 (%). */
  maxDriftPct?: number;
  /** The data feed for latest trades: `iex` (free plans, the default) or `sip`. */
  feed?: "iex" | "sip";
}

/** What custody hands to execute: the key pair for one request, dropped by `revoke` when the gateway is done. */
interface CustodyMaterial {
  key: AlpacaKey | undefined;
  /** Set when the one write request is sent: a second one with the same credential is refused. */
  spent: boolean;
}

const SYMBOL_RE = new RegExp(SYMBOL_PATTERN);
const ORDER_ID_RE = new RegExp(ORDER_ID_PATTERN);
/** Alpaca statuses of an order that can still be cancelled. */
const OPEN_STATUSES = new Set(["new", "accepted", "pending_new", "partially_filled", "held", "accepted_for_bidding", "calculated", "pending_replace"]);
/** Statuses after which reading the order back stops. */
const SETTLED_STATUSES = new Set(["filled", "canceled", "expired", "rejected", "done_for_day", "replaced", "stopped", "suspended"]);

export function createAlpacaAdapter(opts: AlpacaAdapterOptions = {}): Adapter {
  const now = opts.now ?? (() => Date.now());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const settleMs = opts.settleMs ?? 3000;
  const maxDriftPct = opts.maxDriftPct ?? 5;
  const feed = opts.feed ?? "iex";

  return {
    manifest,

    async resolve(ctx: ResolveContext, tool: string, args: unknown): Promise<ResolvedArgs> {
      if (!isAlpacaReadOnlyClient(ctx.upstream)) throw new AdapterError("resolve_failed", "alpaca adapter needs an AlpacaReadOnlyClient as the read-only upstream");
      const a = asRecord(args);
      if (!a) throw new AdapterError("resolve_failed", "arguments must be an object");
      const signal = signalFor(ctx.deadline);
      switch (shortTool(tool)) {
        case "place_order":
          return resolvePlace(ctx.upstream, a, signal, feed, ctx.logger);
        case "cancel_order":
          return resolveCancel(ctx.upstream, a, signal);
        case "read_positions":
          return { args: { account: ACCOUNT_LABEL } };
        case "read_orders": {
          const status = a["status"] ?? "open";
          const limit = a["limit"] ?? 50;
          if (typeof status !== "string" || !(ORDER_STATUSES as readonly string[]).includes(status)) throw new AdapterError("resolve_failed", "status must be open, closed or all");
          if (!Number.isInteger(limit) || (limit as number) < 1 || (limit as number) > 50) throw new AdapterError("resolve_failed", "limit must be 1 to 50");
          return { args: { account: ACCOUNT_LABEL, status, limit: limit as number } };
        }
        default:
          throw new AdapterError("resolve_failed", `unknown tool ${tool}`);
      }
    },

    async custody(ctx: CredentialContext, action: FrozenAction): Promise<Credential> {
      const key_id = ctx.secrets[SECRET_KEY_ID];
      const secret_key = ctx.secrets[SECRET_SECRET_KEY];
      if (!key_id || !secret_key) throw new AdapterError("credential_failed", "secrets key_id and secret_key are required (signeto secrets set alpaca key_id, then secret_key)");
      const material: CustodyMaterial = { key: { key_id, secret_key }, spent: false };
      return {
        material,
        // The credential lives as long as the approval it serves (docs/adapters.md §3.3).
        expiresAt: actionExpiry(action, ctx.deadline),
        // Only the key id's last 4 characters: the scope goes into the ledger.
        scope: `custody: alpaca paper key …${key_id.slice(-4)}, one ${shortTool(action.tool)} request for ${action.id}`,
        revoke: async () => {
          material.key = undefined;
        },
      };
    },

    async execute(ctx: ExecuteContext, action: FrozenAction, credential: Credential): Promise<ToolResult> {
      const m = credential.material as Partial<CustodyMaterial> | undefined;
      if (!m || typeof m !== "object" || !m.key?.key_id || !m.key.secret_key) throw new AdapterError("credential_failed", "credential material is not an Alpaca key pair");
      const key = m.key;
      const signal = signalFor(ctx.deadline);
      const call = (base: string, path: string, init: RequestInit = {}) => request(ctx.fetch, base + path, { ...init, headers: alpacaHeaders(key, init.body ? { "content-type": "application/json" } : {}), signal });
      const spend = () => {
        if (m.spent) throw new AdapterError("credential_failed", "this custody credential already sent its one request");
        m.spent = true;
      };
      switch (shortTool(action.tool)) {
        case "place_order":
          return executePlace(call, spend, action, ctx.logger, { now, sleep, settleMs, maxDriftPct, feed, deadline: ctx.deadline });
        case "cancel_order":
          return executeCancel(call, spend, action);
        case "read_positions":
          return executeReadPositions(call);
        case "read_orders":
          return executeReadOrders(call, action);
        default:
          throw new AdapterError("upstream_rejected", `unknown tool ${action.tool}`);
      }
    },
  };
}

/** Default instance: global fetch, wall clock. */
export const alpacaAdapter: Adapter = createAlpacaAdapter();

// ---------- resolve ----------

async function resolvePlace(client: AlpacaReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, feed: string, logger: Logger): Promise<ResolvedArgs> {
  const symbol = typeof a["symbol"] === "string" ? a["symbol"].trim().toUpperCase() : "";
  if (!SYMBOL_RE.test(symbol)) throw new AdapterError("resolve_failed", "symbol must be a US stock symbol, e.g. AAPL");
  const side = a["side"];
  if (typeof side !== "string" || !(SIDES as readonly string[]).includes(side)) throw new AdapterError("resolve_failed", "side must be buy or sell");
  const qty = a["qty"];
  if (!Number.isInteger(qty) || (qty as number) < 1 || (qty as number) > MAX_QTY) throw new AdapterError("resolve_failed", `qty must be a whole number of shares, 1 to ${MAX_QTY}`);
  const type = a["type"];
  if (typeof type !== "string" || !(ORDER_TYPES as readonly string[]).includes(type)) throw new AdapterError("resolve_failed", "type must be market or limit");
  const tif = a["time_in_force"] ?? "day";
  if (typeof tif !== "string" || !(TIMES_IN_FORCE as readonly string[]).includes(tif)) throw new AdapterError("resolve_failed", "time_in_force must be day or gtc");
  if (type === "limit" && a["limit_price"] === undefined) throw new AdapterError("resolve_failed", "a limit order needs limit_price");
  if (type === "market" && a["limit_price"] !== undefined) throw new AdapterError("resolve_failed", "a market order takes no limit_price");
  const limit = type === "limit" ? parsePrice(a["limit_price"]) : null;

  await requireTradingAccount(client, signal);
  const asset = await readGet(client, "trading", `/v2/assets/${encodeURIComponent(symbol)}`, signal, `no such asset ${symbol}`);
  if (!isRecord(asset) || asset["tradable"] !== true || asset["status"] !== "active") throw new AdapterError("resolve_failed", `${symbol} is not tradable on Alpaca`);

  const price = limit ?? (await latestPrice(client, symbol, feed, signal));
  const notional_usd = notional(qty as number, price);
  logger.debug("alpaca order priced", { symbol, type, notional_usd });
  return {
    args: { account: ACCOUNT_LABEL, side, qty: qty as number, symbol, type, limit_price: limit === null ? null : formatPrice(limit), time_in_force: tif, notional_usd },
    // Facts are copied into the signed args (docs/adapters.md §1.2): the same values, so policy tests what is signed.
    facts: { notional_usd },
  };
}

async function resolveCancel(client: AlpacaReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal): Promise<ResolvedArgs> {
  const id = typeof a["order_id"] === "string" ? a["order_id"].trim().toLowerCase() : "";
  if (!ORDER_ID_RE.test(id)) throw new AdapterError("resolve_failed", "order_id must be an Alpaca order id (a UUID)");
  const o = await readGet(client, "trading", `/v2/orders/${id}`, signal, `no order ${id}`);
  if (!isRecord(o)) throw new AdapterError("resolve_failed", "Alpaca answered without the order");
  if (typeof o["status"] !== "string" || !OPEN_STATUSES.has(o["status"])) throw new AdapterError("resolve_failed", `order ${id} is ${String(o["status"])}, not open`);
  const sig = orderSignature(o);
  if (!sig) throw new AdapterError("resolve_failed", `order ${id} is not a whole-share market or limit stock order, which this adapter can describe`);
  return { args: { account: ACCOUNT_LABEL, order_id: id, ...sig } };
}

/** The account must be an active, unblocked paper account. */
async function requireTradingAccount(client: AlpacaReadOnlyClient, signal: AbortSignal): Promise<void> {
  const acct = await readGet(client, "trading", "/v2/account", signal, "no account");
  if (!isRecord(acct)) throw new AdapterError("resolve_failed", "Alpaca answered without the account");
  if (acct["status"] !== "ACTIVE") throw new AdapterError("resolve_failed", `the Alpaca account is ${String(acct["status"])}, not ACTIVE`);
  if (acct["trading_blocked"] === true || acct["account_blocked"] === true) throw new AdapterError("resolve_failed", "trading is blocked on the Alpaca account");
  // Paper accounts are numbered PA…: a defence in depth next to the paper-only host.
  if (typeof acct["account_number"] !== "string" || !acct["account_number"].startsWith("PA")) throw new AdapterError("resolve_failed", "the key is not for an Alpaca paper account");
}

async function latestPrice(client: AlpacaReadOnlyClient, symbol: string, feed: string, signal: AbortSignal): Promise<bigint> {
  const body = await readGet(client, "data", `/v2/stocks/${encodeURIComponent(symbol)}/trades/latest?feed=${feed}`, signal, `no trades for ${symbol}`);
  return tradePrice(body, symbol);
}

function tradePrice(body: unknown, symbol: string): bigint {
  const p = isRecord(body) && isRecord(body["trade"]) ? body["trade"]["p"] : undefined;
  if (typeof p !== "number" || !Number.isFinite(p) || p <= 0) throw new AdapterError("resolve_failed", `no recent trade price for ${symbol}`);
  // A trade price may carry more than 4 decimals: rounded to ten-thousandths for the estimate.
  return BigInt(Math.round(p * 10_000));
}

async function readGet(client: AlpacaReadOnlyClient, api: "trading" | "data", path: string, signal: AbortSignal, notFound: string): Promise<unknown> {
  try {
    return await client.get(api, path, { signal });
  } catch (e) {
    if (e instanceof AlpacaApiError) {
      if (e.status === 404) throw new AdapterError("resolve_failed", notFound);
      if (e.status === 401 || e.status === 403) throw new AdapterError("resolve_failed", `Alpaca refused the key (${e.status}): is it a paper trading key?`);
      throw new AdapterError("upstream_rejected", e.message, e.status >= 500);
    }
    throw e;
  }
}

// ---------- execute ----------

type Call = (base: string, path: string, init?: RequestInit) => Promise<Response>;

interface PlaceDeps {
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  settleMs: number;
  maxDriftPct: number;
  feed: string;
  deadline: Date;
}

async function executePlace(call: Call, spend: () => void, action: FrozenAction, logger: Logger, d: PlaceDeps): Promise<ToolResult> {
  const s = action.args;
  const symbol = s["symbol"] as string;
  const type = s["type"] as string;
  // §3.4: a market order executes at today's price. Re-price it, and refuse if it moved past what was signed.
  if (type === "market") {
    const res = await call(ALPACA_DATA_BASE, `/v2/stocks/${encodeURIComponent(symbol)}/trades/latest?feed=${d.feed}`);
    if (!res.ok) throw new AdapterError("precondition_failed", `could not re-price ${symbol} before the order (${res.status}); nothing was sent`, res.status >= 500);
    const nowValue = notionalCents(s["qty"] as number, tradePrice(await res.json(), symbol));
    const signed = centsOf(s["notional_usd"] as number);
    const drift = signed === 0n ? 0 : Number(((nowValue > signed ? nowValue - signed : signed - nowValue) * 10_000n) / signed) / 100;
    if (drift > d.maxDriftPct) throw new AdapterError("precondition_failed", `${symbol} moved ${drift.toFixed(2)}% since approval (more than ${d.maxDriftPct}%); nothing was sent`, false, { signed_notional_usd: s["notional_usd"] as number, drift_pct: drift });
  }
  const body: Record<string, string> = {
    symbol,
    qty: String(s["qty"]),
    side: s["side"] as string,
    type,
    time_in_force: s["time_in_force"] as string,
    // One order per approval: Alpaca refuses a second order with the same client_order_id.
    client_order_id: action.id,
  };
  if (type === "limit") body["limit_price"] = s["limit_price"] as string;
  spend();
  let order = await sendOrder(call, action.id, body);
  if (orderMismatch(order, s)) throw new AdapterError("upstream_rejected", "Alpaca's order does not match the signed one; check the account now", false, { order_id: String(order["id"] ?? "") });

  // Read the order back for a few seconds: a paper market order in market hours usually fills at once.
  const id = String(order["id"]);
  const until = Math.min(d.now() + d.settleMs, d.deadline.getTime() - 500);
  while (typeof order["status"] === "string" && !SETTLED_STATUSES.has(order["status"]) && d.now() < until) {
    await d.sleep(500);
    const r = await call(ALPACA_PAPER_BASE, `/v2/orders/${id}`).catch(() => undefined);
    if (r?.ok) order = asRecord(await r.json()) ?? order;
  }
  const view = orderView(order);
  logger.info("alpaca order sent", { order_id: id, status: String(view["status"]) });
  return { content: view, evidence: { ...view, client_order_id: action.id } };
}

/**
 * The one order request. When it doesn't complete, or Alpaca calls it a duplicate, the order is looked up by its
 * client id instead of guessing: an order that did reach Alpaca is reported, never sent again.
 */
async function sendOrder(call: Call, clientId: string, body: Record<string, string>): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await call(ALPACA_PAPER_BASE, "/v2/orders", { method: "POST", body: JSON.stringify(body) });
  } catch (e) {
    const found = await findByClientId(call, clientId).catch(() => undefined);
    if (found) return found;
    throw new AdapterError("upstream_unreachable", `the order request did not complete and Alpaca has no order ${clientId}: ${e instanceof Error ? e.message : String(e)}`, false);
  }
  if (res.ok) return asRecord(await res.json()) ?? {};
  const message = (await errorMessage(res)) ?? "no message";
  if (res.status === 422 && /client_order_id/i.test(message)) {
    const found = await findByClientId(call, clientId);
    if (found) return found;
    throw new AdapterError("upstream_rejected", "Alpaca refused the order as a duplicate but has no order with its id");
  }
  throw new AdapterError("upstream_rejected", `Alpaca refused the order (${res.status}): ${message}`, false, { status: res.status });
}

async function executeCancel(call: Call, spend: () => void, action: FrozenAction): Promise<ToolResult> {
  const id = action.args["order_id"] as string;
  spend();
  const res = await call(ALPACA_PAPER_BASE, `/v2/orders/${id}`, { method: "DELETE" });
  if (res.status === 204 || res.ok) return { content: { order_id: id, cancel_requested: true }, evidence: { order_id: id, cancel_requested: true } };
  if (res.status === 422) throw new AdapterError("upstream_rejected", `order ${id} can no longer be cancelled (${(await errorMessage(res)) ?? "not open"})`, false, { order_id: id });
  if (res.status === 404) throw new AdapterError("upstream_rejected", `no order ${id}`, false, { order_id: id });
  throw new AdapterError("upstream_rejected", `Alpaca refused the cancel (${res.status})`, res.status >= 500, { order_id: id });
}

async function executeReadPositions(call: Call): Promise<ToolResult> {
  const res = await call(ALPACA_PAPER_BASE, "/v2/positions");
  if (!res.ok) throw new AdapterError("upstream_rejected", `Alpaca refused the read (${res.status})`, res.status >= 500);
  const list = (await res.json()) as unknown;
  const positions = (Array.isArray(list) ? list : []).filter(isRecord).map((p) => pick(p, ["symbol", "qty", "side", "avg_entry_price", "market_value", "unrealized_pl", "current_price"]));
  return { content: { account: ACCOUNT_LABEL, positions }, evidence: { count: positions.length } };
}

async function executeReadOrders(call: Call, action: FrozenAction): Promise<ToolResult> {
  const status = action.args["status"] as string;
  const limit = action.args["limit"] as number;
  const res = await call(ALPACA_PAPER_BASE, `/v2/orders?status=${status}&limit=${limit}&direction=desc`);
  if (!res.ok) throw new AdapterError("upstream_rejected", `Alpaca refused the read (${res.status})`, res.status >= 500);
  const list = (await res.json()) as unknown;
  const orders = (Array.isArray(list) ? list : []).filter(isRecord).map(orderView);
  return { content: { account: ACCOUNT_LABEL, status, orders }, evidence: { count: orders.length } };
}

async function findByClientId(call: Call, clientId: string): Promise<Record<string, unknown> | undefined> {
  const res = await call(ALPACA_PAPER_BASE, `/v2/orders:by_client_order_id?client_order_id=${encodeURIComponent(clientId)}`);
  if (res.status === 404) return undefined;
  if (!res.ok) throw new AdapterError("upstream_unreachable", `could not look the order up (${res.status})`, true);
  return asRecord(await res.json());
}

// ---------- helpers ----------

/** The parts of an order the cancel card describes, or undefined for an order this adapter would not have placed. */
function orderSignature(o: Record<string, unknown>): { side: string; qty: number; symbol: string; type: string } | undefined {
  const qty = Number(o["qty"]);
  const symbol = o["symbol"];
  if (typeof o["side"] !== "string" || !(SIDES as readonly string[]).includes(o["side"])) return undefined;
  if (typeof o["type"] !== "string" || !(ORDER_TYPES as readonly string[]).includes(o["type"])) return undefined;
  if (!Number.isInteger(qty) || qty < 1 || qty > MAX_QTY || typeof symbol !== "string" || !SYMBOL_RE.test(symbol)) return undefined;
  return { side: o["side"], qty, symbol, type: o["type"] };
}

function orderMismatch(o: Record<string, unknown>, s: Readonly<Record<string, JsonValue>>): boolean {
  if (o["symbol"] !== s["symbol"] || o["side"] !== s["side"] || o["type"] !== s["type"] || Number(o["qty"]) !== s["qty"]) return true;
  if (s["type"] === "limit" && Number(o["limit_price"]) !== Number(s["limit_price"])) return true;
  return false;
}

function orderView(o: Record<string, unknown>): Record<string, JsonValue> {
  return pick(o, ["id", "client_order_id", "symbol", "side", "qty", "type", "limit_price", "time_in_force", "status", "filled_qty", "filled_avg_price", "submitted_at", "filled_at"]);
}

function pick(o: Record<string, unknown>, keys: string[]): Record<string, JsonValue> {
  const out: Record<string, JsonValue> = {};
  for (const k of keys) {
    const v = o[k];
    if (v === null || typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) out[k] = v as JsonValue;
  }
  return out;
}

async function request(f: FetchFn, url: string, init: RequestInit): Promise<Response> {
  try {
    return await f(url, { ...init, redirect: "error" });
  } catch (e) {
    if ((e as { name?: string })?.name === "AbortError" || (e as { name?: string })?.name === "TimeoutError") throw new AdapterError("timeout", "Alpaca did not answer before the deadline", true);
    throw e;
  }
}

/** The action's `expires_at` from its canonical bytes; the deadline if it can't be read. */
function actionExpiry(action: FrozenAction, fallback: Date): Date {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(action.canonicalBytes)) as { expires_at?: unknown };
    const t = typeof parsed.expires_at === "string" ? Date.parse(parsed.expires_at) : NaN;
    return Number.isFinite(t) ? new Date(t) : fallback;
  } catch {
    return fallback;
  }
}

function signalFor(deadline: Date): AbortSignal {
  return AbortSignal.timeout(Math.max(1, deadline.getTime() - Date.now()));
}

function shortTool(tool: string): string {
  return tool.startsWith("alpaca.") ? tool.slice("alpaca.".length) : tool;
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function asRecord(x: unknown): Record<string, unknown> | undefined {
  return isRecord(x) ? x : undefined;
}
