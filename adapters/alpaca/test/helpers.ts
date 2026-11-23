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
  positions: Record<string, unknown>[] = [{ symbol: "AAPL", qty: "10", side: "long", avg_entry_price: "180.00", market_value: "1895.00", unrealized_pl: "95.00", current_price: "189.50", asset_id: "x" }];
  /** The next order request fails like this (a dropped connection), after Alpaca recorded it or before. */
  dropOrder: "before" | "after" | undefined;
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
      return p === undefined ? send(404, { message: "not found" }) : send(200, { symbol: m![1], trade: { p, s: 100, t: "2026-11-23T15:00:00Z" } });
    }
    if (u.host !== "paper-api.alpaca.markets") return send(404, { message: "wrong host" });
    if (method === "GET" && u.pathname === "/v2/account") return send(200, this.account);
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
      return send(200, o);
    }
    if (method === "GET" && u.pathname === "/v2/orders:by_client_order_id") {
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

  /** Add an open order directly (one this adapter didn't place). */
  open(o: Partial<FakeOrder> & { id: string }): FakeOrder {
    const full: FakeOrder = { client_order_id: "other", symbol: "AAPL", side: "buy", qty: "5", type: "limit", limit_price: "150.00", time_in_force: "gtc", status: "new", filled_qty: "0", filled_avg_price: null, submitted_at: "2026-11-23T14:00:00Z", ...o };
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
