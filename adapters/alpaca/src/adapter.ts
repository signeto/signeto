// The Alpaca adapter (custody mode, paper trading). docs/adapters.md §3; the signed surface is in manifest.ts.
//
// resolve    checks the account, the asset and the market clock, and values the order: quantity × the price it can
//            trade at (a buy limit: the limit; a market order: the latest trade; a sell limit: the higher of the
//            limit and the latest trade, since a sell limit below the market fills at the market). That notional
//            value is signed, and policy thresholds test it. A sell must reduce a long position you hold: shorting
//            is refused, so "sell" on the card always means selling shares you own.
// custody    hands the stored key pair to execute for this one approved action. Alpaca keys are all or nothing, so
//            the narrowing is the adapter's discipline: one order request per approval, then the key is dropped.
// execute    sends at most one write request (the order, or the cancel). The order carries the action id as its
//            `client_order_id`, so Alpaca itself refuses a second order for the same approval. An order valued from
//            the market (market orders, sell limits) is re-priced first and refused if its value moved more than
//            `maxDriftPct` from what was signed. When the order's answer is lost, the order is looked up by that id;
//            if it can't be confirmed either way, the result says the outcome is unknown and is not retryable.
import type { Adapter, CredentialContext, Credential, ExecuteContext, FrozenAction, Logger, ResolveContext, ResolvedArgs, ToolResult } from "@signeto/adapter-sdk";
import type { JsonValue } from "@signeto/protocol";
import { AdapterError } from "@signeto/adapter-sdk";
import { ACTION_ID_RE } from "@signeto/protocol";
import { ALPACA_DATA_BASE, ALPACA_PAPER_BASE, AlpacaApiError, MALFORMED_KEY_MESSAGE, alpacaHeaders, errorMessage, failureName, isAlpacaReadOnlyClient, isWellFormedKey, type AlpacaKey, type AlpacaReadOnlyClient, type FetchFn } from "./client.js";
import { centsOf, formatPrice, notionalCents, parsePrice, usd } from "./decimal.js";
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
  /** A market order needs a trade at most this old. Default 15 minutes. */
  maxTradeAgeMs?: number;
  /** execute refuses to start with less time than this before the approval expires. Default 10 s. */
  minExecuteMs?: number;
  /** The longest the order request itself may take; the rest of the time is kept for looking it up. Default 15 s. */
  orderTimeoutMs?: number;
  /** Let the agent cancel orders that were not placed through Signeto (a person's own orders). Default false. */
  cancelAnyOrder?: boolean;
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
  if (feed !== "iex" && feed !== "sip") throw new Error("alpaca adapter: feed must be iex or sip");
  const maxTradeAgeMs = opts.maxTradeAgeMs ?? 15 * 60_000;
  const minExecuteMs = opts.minExecuteMs ?? 10_000;
  const orderTimeoutMs = opts.orderTimeoutMs ?? 15_000;
  const cancelAnyOrder = opts.cancelAnyOrder ?? false;

  return {
    manifest,

    async resolve(ctx: ResolveContext, tool: string, args: unknown): Promise<ResolvedArgs> {
      if (!isAlpacaReadOnlyClient(ctx.upstream)) throw new AdapterError("resolve_failed", "alpaca adapter needs an AlpacaReadOnlyClient as the read-only upstream");
      const a = asRecord(args);
      if (!a) throw new AdapterError("resolve_failed", "arguments must be an object");
      const signal = signalFor(ctx.deadline);
      switch (shortTool(tool)) {
        case "place_order":
          return resolvePlace(ctx.upstream, a, signal, { feed, now, maxTradeAgeMs }, ctx.logger);
        case "cancel_order":
          return resolveCancel(ctx.upstream, a, signal, cancelAnyOrder);
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
      if (!isWellFormedKey({ key_id, secret_key })) throw new AdapterError("credential_failed", MALFORMED_KEY_MESSAGE);
      const material: CustodyMaterial = { key: { key_id, secret_key }, spent: false };
      return {
        material,
        // The credential lives as long as the approval it serves (docs/adapters.md §3.3).
        expiresAt: actionExpiry(action, ctx.deadline),
        // Only the key id's last 4 characters, and none of a short one: the scope goes into the ledger.
        scope: `custody: alpaca paper key …${key_id.length >= 12 ? key_id.slice(-4) : ""}, one ${shortTool(action.tool)} request for ${action.id}`,
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
      const call: Call = (base, path, init = {}, own) => request(ctx.fetch, base + path, { ...init, headers: alpacaHeaders(key, init.body ? { "content-type": "application/json" } : {}), signal: own ?? signal });
      const spend = () => {
        if (m.spent) throw new AdapterError("credential_failed", "this custody credential already sent its one request");
        m.spent = true;
      };
      switch (shortTool(action.tool)) {
        case "place_order":
          return executePlace(call, spend, action, ctx.logger, { now, sleep, settleMs, maxDriftPct, feed, maxTradeAgeMs, minExecuteMs, orderTimeoutMs, deadline: ctx.deadline });
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

interface PriceDeps {
  feed: string;
  now: () => number;
  maxTradeAgeMs: number;
}

async function resolvePlace(client: AlpacaReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, d: PriceDeps, logger: Logger): Promise<ResolvedArgs> {
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
  // An order valued from the market (a market order, any sell) needs a market that is open and a recent trade: one
  // placed while the market is closed fills at whatever the open is, and a stale trade (a thin symbol on the IEX
  // feed) could value it far below what it fills at. A buy limit can't fill above its limit, so it needs neither.
  const fromMarket = type === "market" || side === "sell";
  if (fromMarket && !(await marketOpen(client, signal))) throw new AdapterError("resolve_failed", "the market is closed: market orders and sells are taken only while it is open (a buy limit order is taken any time)");
  if (side === "sell") await requireLongPosition(client, symbol, qty as number, signal);

  let last: bigint | undefined;
  if (fromMarket) {
    const t = await latestTrade(client, symbol, d.feed, signal);
    requireRecent(t, symbol, d);
    last = t.price;
  }
  const cents = notionalCents(qty as number, valuationPrice(side, limit, last));
  if (cents < 100n) throw new AdapterError("resolve_failed", "orders worth less than $1 are refused");
  const notional_usd = usd(cents);
  logger.debug("alpaca order priced", { symbol, side, type, notional_usd });
  return {
    args: { account: ACCOUNT_LABEL, side, qty: qty as number, symbol, type, limit_price: limit === null ? null : formatPrice(limit), time_in_force: tif, notional_usd },
    // Facts are copied into the signed args (docs/adapters.md §1.2): the same values, so policy tests what is signed.
    facts: { notional_usd },
  };
}

/**
 * The price an order is valued at, the most it can trade at for policy's purposes: a buy limit can't fill above its
 * limit; a market order trades near the last trade; a sell limit below the market fills at the market, so a sell is
 * valued at the higher of its limit and the last trade.
 */
export function valuationPrice(side: string, limit: bigint | null, last: bigint | undefined): bigint {
  if (limit === null) {
    if (last === undefined) throw new AdapterError("resolve_failed", "a market order needs a price");
    return last;
  }
  if (side === "sell") {
    if (last === undefined) throw new AdapterError("resolve_failed", "a sell order needs the latest price");
    return last > limit ? last : limit;
  }
  return limit;
}

async function resolveCancel(client: AlpacaReadOnlyClient, a: Record<string, unknown>, signal: AbortSignal, cancelAnyOrder: boolean): Promise<ResolvedArgs> {
  const id = typeof a["order_id"] === "string" ? a["order_id"].trim().toLowerCase() : "";
  if (!ORDER_ID_RE.test(id)) throw new AdapterError("resolve_failed", "order_id must be an Alpaca order id (a UUID)");
  const o = await readGet(client, "trading", `/v2/orders/${id}`, signal, `no order ${id}`);
  if (!isRecord(o)) throw new AdapterError("resolve_failed", "Alpaca answered without the order");
  if (typeof o["status"] !== "string" || !OPEN_STATUSES.has(o["status"])) throw new AdapterError("resolve_failed", `order ${id} is ${String(o["status"])}, not open`);
  const sig = orderSignature(o);
  if (!sig) throw new AdapterError("resolve_failed", `order ${id} is not a whole-share market or limit stock order, which this adapter can describe`);
  // Orders placed through Signeto carry their action id as client_order_id. Anything else is a person's own order,
  // which the agent may not cancel unless the gateway is set up to allow it.
  if (!cancelAnyOrder && (typeof o["client_order_id"] !== "string" || !ACTION_ID_RE.test(o["client_order_id"]))) throw new AdapterError("resolve_failed", `order ${id} was not placed through Signeto, so the agent can't cancel it; cancel it in Alpaca`);
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

/** Whether the market is open now (GET /v2/clock). */
async function marketOpen(client: AlpacaReadOnlyClient, signal: AbortSignal): Promise<boolean> {
  const c = await readGet(client, "trading", "/v2/clock", signal, "no market clock");
  if (!isRecord(c) || typeof c["is_open"] !== "boolean") throw new AdapterError("resolve_failed", "Alpaca answered without the market clock");
  return c["is_open"];
}

/** A sell must reduce a long position you hold: no position, a short position or too few shares is refused. */
async function requireLongPosition(client: AlpacaReadOnlyClient, symbol: string, qty: number, signal: AbortSignal): Promise<void> {
  const p = await readGet(client, "trading", `/v2/positions/${encodeURIComponent(symbol)}`, signal, `you hold no ${symbol}: a sell can only reduce a position you hold (shorting is refused)`);
  if (!isRecord(p) || p["side"] !== "long") throw new AdapterError("resolve_failed", `your ${symbol} position is not a long position: a sell can only reduce shares you hold (shorting is refused)`);
  const available = Number(p["qty_available"] ?? p["qty"]);
  if (!Number.isFinite(available) || qty > available) throw new AdapterError("resolve_failed", `you have ${Number.isFinite(available) ? available : 0} ${symbol} available to sell; this order sells ${qty} (shorting is refused)`);
}

interface Trade {
  price: bigint;
  /** When the trade happened (ms), NaN if Alpaca didn't say. */
  at: number;
}

async function latestTrade(client: AlpacaReadOnlyClient, symbol: string, feed: string, signal: AbortSignal): Promise<Trade> {
  const body = await readGet(client, "data", `/v2/stocks/${encodeURIComponent(symbol)}/trades/latest?feed=${feed}`, signal, `no trades for ${symbol}`);
  return tradeOf(body, symbol);
}

function tradeOf(body: unknown, symbol: string): Trade {
  const trade = isRecord(body) && isRecord(body["trade"]) ? body["trade"] : undefined;
  const p = trade?.["p"];
  if (typeof p !== "number" || !Number.isFinite(p) || p <= 0) throw new AdapterError("resolve_failed", `no recent trade price for ${symbol}`);
  const t = trade?.["t"];
  // A trade price may carry more than 4 decimals: rounded to ten-thousandths for the estimate.
  return { price: BigInt(Math.round(p * 10_000)), at: typeof t === "string" ? Date.parse(t) : NaN };
}

/** A market order is valued at the latest trade, so that trade must be recent. */
function requireRecent(t: Trade, symbol: string, d: { now: () => number; maxTradeAgeMs: number }, nothingSent = false): void {
  const age = d.now() - t.at;
  if (Number.isFinite(age) && age <= d.maxTradeAgeMs) return;
  const what = Number.isFinite(age) ? `the latest ${symbol} trade is ${Math.round(age / 60_000)} minutes old` : `Alpaca didn't say when the latest ${symbol} trade was`;
  throw new AdapterError(nothingSent ? "precondition_failed" : "resolve_failed", `${what}, too old to value an order from the market (a market order or a sell)${nothingSent ? "; nothing was sent" : ""}`);
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

/** One request with the custody key. `signal` overrides the execute deadline's (the order and lookup budgets). */
type Call = (base: string, path: string, init?: RequestInit, signal?: AbortSignal) => Promise<Response>;

interface PlaceDeps {
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  settleMs: number;
  maxDriftPct: number;
  feed: string;
  maxTradeAgeMs: number;
  minExecuteMs: number;
  orderTimeoutMs: number;
  deadline: Date;
}

async function executePlace(call: Call, spend: () => void, action: FrozenAction, logger: Logger, d: PlaceDeps): Promise<ToolResult> {
  const s = action.args;
  const symbol = s["symbol"] as string;
  const type = s["type"] as string;
  const side = s["side"] as string;
  // Time to send the order and, if its answer is lost, to look it up. Without it, refuse before sending.
  const tooLate = () => {
    if (d.deadline.getTime() - d.now() < d.minExecuteMs) throw new AdapterError("precondition_failed", "too little time is left before the approval expires to send the order safely; nothing was sent", false);
  };
  tooLate();
  // §3.4: what resolve checked is checked again just before the order, with the custody key, because time has passed
  // (an approval can take minutes) and another order may have run: an order valued from the market needs the market
  // open and a recent trade, and is refused if its value moved past what was signed; a sell needs the shares.
  if (type === "market" || side === "sell") {
    const check = (base: string, path: string) => preflightGet(call, base, path, symbol);
    const clock = await check(ALPACA_PAPER_BASE, "/v2/clock");
    if (!isRecord(clock) || clock["is_open"] !== true) throw new AdapterError("precondition_failed", "the market closed since approval; nothing was sent", false);
    if (side === "sell") {
      const p = await check(ALPACA_PAPER_BASE, `/v2/positions/${encodeURIComponent(symbol)}`);
      const available = isRecord(p) && p["side"] === "long" ? Number(p["qty_available"] ?? p["qty"]) : 0;
      if (!(Number.isFinite(available) && available >= (s["qty"] as number))) throw new AdapterError("precondition_failed", `you have ${Number.isFinite(available) ? available : 0} ${symbol} available to sell now; this order sells ${String(s["qty"])} (shorting is refused); nothing was sent`, false);
    }
    const t = tradeOf(await check(ALPACA_DATA_BASE, `/v2/stocks/${encodeURIComponent(symbol)}/trades/latest?feed=${d.feed}`), symbol);
    requireRecent(t, symbol, d, true);
    const limit = type === "limit" ? parsePrice(s["limit_price"]) : null;
    const nowValue = notionalCents(s["qty"] as number, valuationPrice(side, limit, t.price));
    const signed = centsOf(s["notional_usd"] as number);
    if (signed <= 0n) throw new AdapterError("precondition_failed", "the signed notional value is not an amount; nothing was sent");
    const drift = Number(((nowValue > signed ? nowValue - signed : signed - nowValue) * 10_000n) / signed) / 100;
    if (drift > d.maxDriftPct) throw new AdapterError("precondition_failed", `${symbol} moved ${drift.toFixed(2)}% since approval (more than ${d.maxDriftPct}%); nothing was sent`, false, { signed_notional_usd: s["notional_usd"] as number, drift_pct: drift });
  }
  const body: Record<string, string> = {
    symbol,
    qty: String(s["qty"]),
    side,
    type,
    time_in_force: s["time_in_force"] as string,
    // One order per approval: Alpaca refuses a second order with the same client_order_id.
    client_order_id: action.id,
  };
  if (type === "limit") body["limit_price"] = s["limit_price"] as string;
  // the checks above took time: there must still be enough left for the order and a lookup
  tooLate();
  spend();
  let order = await sendOrder(call, action.id, body, d);
  if (orderMismatch(order, s, action.id)) throw new AdapterError("upstream_rejected", "Alpaca's order does not match the signed one; check the account now", false, { order_id: String(order["id"] ?? ""), client_order_id: action.id });

  // Read the order back for a few seconds: a paper market order in market hours usually fills at once.
  const id = String(order["id"]);
  const until = Math.min(d.now() + d.settleMs, d.deadline.getTime() - 500);
  while (ORDER_ID_RE.test(id) && typeof order["status"] === "string" && !SETTLED_STATUSES.has(order["status"]) && d.now() < until) {
    await d.sleep(500);
    const r = await call(ALPACA_PAPER_BASE, `/v2/orders/${id}`).catch(() => undefined);
    if (r?.ok) order = asRecord(await r.json().catch(() => undefined)) ?? order;
  }
  const view = orderView(order);
  logger.info("alpaca order sent", { order_id: id, status: String(view["status"]) });
  return { content: view, evidence: { ...view, client_order_id: action.id } };
}

/**
 * The one order request. It gets its own timeout, well inside the deadline, so that when its answer is lost (no
 * answer, a 5xx, an unreadable body) there is time left to look the order up by its client id. Nothing is ever
 * sent again. If the lookup can't say, the outcome is reported as unknown, not as "not placed", and not retryable.
 */
async function sendOrder(call: Call, clientId: string, body: Record<string, string>, d: PlaceDeps): Promise<Record<string, unknown>> {
  const orderMs = Math.max(1, Math.min(d.orderTimeoutMs, d.deadline.getTime() - d.now() - 6_000));
  let res: Response;
  try {
    res = await call(ALPACA_PAPER_BASE, "/v2/orders", { method: "POST", body: JSON.stringify(body) }, AbortSignal.timeout(orderMs));
  } catch {
    return lostOrder(call, clientId, d);
  }
  if (res.status >= 500) return lostOrder(call, clientId, d);
  if (res.ok) {
    const order = asRecord(await res.json().catch(() => undefined));
    return order && typeof order["id"] === "string" ? order : lostOrder(call, clientId, d);
  }
  const message = (await errorMessage(res)) ?? "no message";
  if (res.status === 422 && /client_order_id/i.test(message)) {
    const found = await findByClientId(call, clientId, lookupSignal(d)).catch(() => {
      throw unknownOutcome(clientId);
    });
    if (found) return found;
    throw new AdapterError("upstream_rejected", "Alpaca refused the order as a duplicate but has no order with its id", false, { client_order_id: clientId });
  }
  // A 4xx: Alpaca refused it, so no order was placed.
  throw new AdapterError("upstream_rejected", `Alpaca refused the order (${res.status}): ${message}`, false, { status: res.status });
}

/** A GET before the order, with a short timeout of its own; any failure means nothing is sent. A 404 is `undefined`. */
async function preflightGet(call: Call, base: string, path: string, symbol: string): Promise<unknown> {
  let res: Response;
  try {
    res = await call(base, path, {}, AbortSignal.timeout(5_000));
  } catch (e) {
    const name = failureName(e);
    throw new AdapterError("precondition_failed", `could not check ${symbol} before the order (${name}); nothing was sent`, false);
  }
  if (res.status === 404) return undefined;
  if (!res.ok) throw new AdapterError("precondition_failed", `could not check ${symbol} before the order (${res.status}); nothing was sent`, false);
  return res.json().catch(() => undefined);
}

/** The order's answer was lost: look it up by client id, twice (an order can take a moment to show). */
async function lostOrder(call: Call, clientId: string, d: PlaceDeps): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 2; attempt++) {
    if (d.deadline.getTime() - d.now() < 1_000) break;
    let found: Record<string, unknown> | undefined;
    try {
      found = await findByClientId(call, clientId, lookupSignal(d));
    } catch {
      throw unknownOutcome(clientId);
    }
    if (found) return found;
    if (attempt === 0) await d.sleep(1_000);
    else throw new AdapterError("upstream_unreachable", `the order request did not complete and Alpaca shows no order ${clientId}: it was probably not placed, but read the open orders before trying again`, false, { client_order_id: clientId, outcome: "not_found" });
  }
  throw unknownOutcome(clientId);
}

function unknownOutcome(clientId: string): AdapterError {
  return new AdapterError("upstream_unreachable", `the order request did not complete and the order could not be looked up: whether order ${clientId} was placed is unknown, so read the orders before trying again`, false, { client_order_id: clientId, outcome: "unknown" });
}

function lookupSignal(d: PlaceDeps): AbortSignal {
  return AbortSignal.timeout(Math.max(1, Math.min(4_000, d.deadline.getTime() - d.now() - 500)));
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

async function findByClientId(call: Call, clientId: string, signal: AbortSignal): Promise<Record<string, unknown> | undefined> {
  const res = await call(ALPACA_PAPER_BASE, `/v2/orders:by_client_order_id?client_order_id=${encodeURIComponent(clientId)}`, {}, signal);
  if (res.status === 404) return undefined;
  if (!res.ok) throw new AdapterError("upstream_unreachable", `could not look the order up (${res.status})`, false);
  const o = asRecord(await res.json().catch(() => undefined));
  if (!o || o["client_order_id"] !== clientId) throw new AdapterError("upstream_unreachable", "the order lookup answered with a different order", false);
  return o;
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

function orderMismatch(o: Record<string, unknown>, s: Readonly<Record<string, JsonValue>>, clientId: string): boolean {
  if (o["symbol"] !== s["symbol"] || o["side"] !== s["side"] || o["type"] !== s["type"] || Number(o["qty"]) !== s["qty"]) return true;
  if (o["time_in_force"] !== s["time_in_force"] || o["client_order_id"] !== clientId) return true;
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
    // Never the error's message: fetch's errors can quote the request's headers, and they carry the key.
    const name = failureName(e);
    if (name === "AbortError" || name === "TimeoutError") throw new AdapterError("timeout", "Alpaca did not answer in time", true);
    throw new AdapterError("upstream_unreachable", `Alpaca not reachable (${name})`, true);
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
