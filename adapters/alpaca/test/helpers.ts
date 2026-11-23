// Offline test plumbing: a fake Alpaca (paper trading + market data) behind a recording fetch, and canonical actions.
import { generateKeyPairSync } from "node:crypto";
import { buildCanonicalAction, gatewayIdFromJwk, type JsonValue } from "@signeto/protocol";
import type { CredentialContext, ExecuteContext, FrozenAction, Logger, ResolveContext } from "@signeto/adapter-sdk";
import { createReadOnlyClient, manifest } from "../src/index.js";

export const KEY = { key_id: "PKTESTKEYID0000ABCD", secret_key: "s3cr3t-paper-secret-key-do-not-leak-1234567890" };

export interface RecordedCall {
  method: string;
  host: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface FakeOrder {
  id: string;
  client_order_id: string;
  symbol: string;
  side: string;
  qty: string;
  type: string;
  limit_price: string | null;
  time_in_force: string;
  status: string;
  filled_qty: string;
  filled_avg_price: string | null;
  submitted_at: string;
}

/** A small in-memory Alpaca: account, assets, latest trades, orders (with client_order_id uniqueness), positions. */
export class FakeAlpaca {
  calls: RecordedCall[] = [];
  account: Record<string, unknown> = { account_number: "PA3ABCDEFGH", status: "ACTIVE", trading_blocked: false, account_blocked: false, buying_power: "200000" };
  assets = new Map<string, Record<string, unknown>>([
    ["AAPL", { symbol: "AAPL", tradable: true, status: "active" }],
    ["BRK.B", { symbol: "BRK.B", tradable: true, status: "active" }],
    ["DELIST", { symbol: "DELIST", tradable: false, status: "inactive" }],
  ]);
  prices = new Map<string, number>([["AAPL", 189.5], ["BRK.B", 412.33]]);
  orders: FakeOrder[] = [];
  positions: Record<string, unknown>[] = [{ symbol: "AAPL", qty: "10", qty_available: "10", side: "long", avg_entry_price: "180.00", market_value: "1895.00", unrealized_pl: "95.00", current_price: "189.50", asset_id: "x" }];
  /** The market clock. */
  isOpen = true;
  /** When the latest trade happened; now by default. */
  tradeTime: () => string | undefined = () => new Date().toISOString();
  /** The next order request fails like this (a dropped connection), after Alpaca recorded it or before. */
  dropOrder: "before" | "after" | undefined;
  /** The next order request: Alpaca records the order, then answers 503 / never answers / answers garbage. */
  orderAnswer: "503" | "hang" | "garbage" | undefined;
  /** This many client-id lookups fail (connection dropped) before they work. */
  lookupFailures = 0;
  /** This many client-id lookups answer 404 even when the order exists (it hasn't shown up yet). */
  lookupLag = 0;
  /** Market orders fill on the next read back. */
  fillOnRead = true;
  private n = 0;

  fetch: typeof fetch = async (input, init = {}) => {
    const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const method = (init.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const body = typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    const path = u.pathname + u.search;
    this.calls.push({ method, host: u.host, path, headers, body });
    const send = (status: number, b?: unknown) => (b === undefined ? new Response(null, { status }) : new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } }));
    if (headers["apca-api-key-id"] !== KEY.key_id || headers["apca-api-secret-key"] !== KEY.secret_key) return send(401, { code: 40110000, message: "request is not authorized" });
    if (u.host === "data.alpaca.markets") {
      const m = /^\/v2\/stocks\/([^/]+)\/trades\/latest$/.exec(u.pathname);
      const p = m ? this.prices.get(decodeURIComponent(m[1] as string)) : undefined;
      const t = this.tradeTime();
      return p === undefined ? send(404, { message: "not found" }) : send(200, { symbol: m![1], trade: { p, s: 100, ...(t ? { t } : {}) } });
    }
    if (u.host !== "paper-api.alpaca.markets") return send(404, { message: "wrong host" });
    if (method === "GET" && u.pathname === "/v2/account") return send(200, this.account);
    if (method === "GET" && u.pathname === "/v2/clock") return send(200, { timestamp: new Date().toISOString(), is_open: this.isOpen });
    const pos = /^\/v2\/positions\/(.+)$/.exec(u.pathname);
    if (method === "GET" && pos) {
      const p = this.positions.find((x) => x["symbol"] === decodeURIComponent(pos[1] as string));
      return p ? send(200, p) : send(404, { code: 40410000, message: "position does not exist" });
    }
    const asset = /^\/v2\/assets\/(.+)$/.exec(u.pathname);
    if (method === "GET" && asset) {
      const a = this.assets.get(decodeURIComponent(asset[1] as string));
      return a ? send(200, a) : send(404, { message: "asset not found" });
    }
    if (method === "POST" && u.pathname === "/v2/orders") {
      const b = body as Record<string, string>;
      if (this.dropOrder === "before") {
        this.dropOrder = undefined;
        throw new TypeError("fetch failed");
      }
      if (this.orders.some((o) => o.client_order_id === b["client_order_id"])) return send(422, { code: 40010001, message: "client_order_id must be unique" });
      const o: FakeOrder = {
        id: `0000000${++this.n}-aaaa-bbbb-cccc-dddddddddddd`.slice(-36),
        client_order_id: b["client_order_id"] as string,
        symbol: b["symbol"] as string,
        side: b["side"] as string,
        qty: b["qty"] as string,
        type: b["type"] as string,
        limit_price: b["limit_price"] ?? null,
        time_in_force: b["time_in_force"] as string,
        status: "accepted",
        filled_qty: "0",
        filled_avg_price: null,
        submitted_at: "2026-11-23T15:00:01Z",
      };
      this.orders.push(o);
      if (this.dropOrder === "after") {
        this.dropOrder = undefined;
        throw new TypeError("fetch failed");
      }
      const answer = this.orderAnswer;
      this.orderAnswer = undefined;
      if (answer === "503") return send(503, { message: "service unavailable" });
      if (answer === "garbage") return new Response("<html>bad gateway</html>", { status: 200 });
      if (answer === "hang") {
        return new Promise<Response>((_, reject) => {
          const sig = init.signal;
          sig?.addEventListener("abort", () => reject(sig.reason ?? new DOMException("aborted", "AbortError")));
        });
      }
      return send(200, o);
    }
    if (method === "GET" && u.pathname === "/v2/orders:by_client_order_id") {
      if (this.lookupFailures > 0) {
        this.lookupFailures--;
        throw new TypeError("fetch failed");
      }
      if (this.lookupLag > 0) {
        this.lookupLag--;
        return send(404, { message: "order not found" });
      }
      const o = this.orders.find((x) => x.client_order_id === u.searchParams.get("client_order_id"));
      return o ? send(200, o) : send(404, { message: "order not found" });
    }
    const one = /^\/v2\/orders\/([0-9a-f-]{36})$/.exec(u.pathname);
    if (one) {
      const o = this.orders.find((x) => x.id === one[1]);
      if (!o) return send(404, { message: "order not found" });
      if (method === "GET") {
        if (this.fillOnRead && o.type === "market" && o.status === "accepted") Object.assign(o, { status: "filled", filled_qty: o.qty, filled_avg_price: String(this.prices.get(o.symbol)) });
        return send(200, o);
      }
      if (method === "DELETE") {
        if (!["accepted", "new", "partially_filled"].includes(o.status)) return send(422, { message: `order is ${o.status}` });
        o.status = "canceled";
        return send(204);
      }
    }
    if (method === "GET" && u.pathname === "/v2/orders") return send(200, this.orders.slice().reverse());
    if (method === "GET" && u.pathname === "/v2/positions") return send(200, this.positions);
    return send(404, { message: "not found" });
  };

  /** Writes (POST, DELETE) Alpaca received. */
  writes = () => this.calls.filter((c) => c.method !== "GET");

  /** Add an open order directly; by default one placed through Signeto (its client id is an action id). */
  open(o: Partial<FakeOrder> & { id: string }): FakeOrder {
    const full: FakeOrder = { client_order_id: "act_01M84G7XAXDANS44CD3HWT73TD", symbol: "AAPL", side: "buy", qty: "5", type: "limit", limit_price: "150.00", time_in_force: "gtc", status: "new", filled_qty: "0", filled_avg_price: null, submitted_at: "2026-11-23T14:00:00Z", ...o };
    this.orders.push(full);
    return full;
  }
}

export const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** Every log line, for "the key never reaches a log". */
export function recordingLogger() {
  const lines: string[] = [];
  const rec = (level: string) => (msg: string, data?: Record<string, unknown>) => void lines.push(`${level} ${msg} ${data ? JSON.stringify(data) : ""}`);
  const l: Logger = { debug: rec("debug"), info: rec("info"), warn: rec("warn"), error: rec("error") };
  return { logger: l, lines };
}

export const future = (ms = 30_000) => new Date(Date.now() + ms);

export function resolveCtx(fake: FakeAlpaca, l: Logger = logger): ResolveContext {
  return { upstream: createReadOnlyClient({ key: () => KEY, fetch: fake.fetch }), deadline: future(), logger: l };
}

export function credentialCtx(fake: FakeAlpaca, secrets: Record<string, string> = KEY, l: Logger = logger): CredentialContext {
  return { secrets, deadline: future(), logger: l, fetch: fake.fetch };
}

export function executeCtx(fake: FakeAlpaca, l: Logger = logger): ExecuteContext {
  return { deadline: future(), logger: l, fetch: fake.fetch };
}

const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
let seq = 0;

/** A frozen action for `tool` with these resolved args, as the gateway would hand it over. */
export function frozen(tool: string, args: Record<string, JsonValue>): FrozenAction {
  const spec = manifest.tools.find((t) => t.name === tool)!;
  const enc = buildCanonicalAction({
    tool: `alpaca.${tool}`,
    template_version: spec.template.version,
    args_resolved: args,
    requester: { agent: "claude-code", session_id: `s${++seq}`, host: "h", gateway_id: gatewayIdFromJwk(gw) },
    origin_hash: "0".repeat(64),
    tier: 3,
    mode: "enforce",
  });
  return {
    id: `act_${String(seq).padStart(26, "0")}`,
    tool: `alpaca.${tool}`,
    args: enc.action.args_resolved as FrozenAction["args"],
    canonicalBytes: new TextEncoder().encode(enc.canonical_bytes),
    templateId: enc.action.template_id,
    templateVersion: enc.action.template_version,
  };
}
