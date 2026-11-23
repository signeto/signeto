import { describe, expect, it } from "vitest";
import { createAlpacaAdapter, createReadOnlyClient } from "../src/index.js";
import { FakeAlpaca, KEY, logger, resolveCtx, future } from "./helpers.js";

const adapter = createAlpacaAdapter();
const err = (code: string, message?: RegExp) => expect.objectContaining({ code, ...(message ? { message: expect.stringMatching(message) } : {}) });

describe("resolve place_order", () => {
  it("prices a market order from the latest trade and signs the notional", async () => {
    const fake = new FakeAlpaca();
    const r = await adapter.resolve(resolveCtx(fake), "alpaca.place_order", { symbol: "aapl", side: "buy", qty: 10, type: "market" });
    expect(r.args).toEqual({ account: "paper", side: "buy", qty: 10, symbol: "AAPL", type: "market", limit_price: null, time_in_force: "day", notional_usd: 1895 });
    // a number, so policy thresholds can test it; facts are copied into the signed args, so they must agree
    expect(r.facts).toEqual({ notional_usd: 1895 });
    expect(fake.calls.map((c) => `${c.method} ${c.host}${c.path}`)).toEqual([
      "GET paper-api.alpaca.markets/v2/account",
      "GET paper-api.alpaca.markets/v2/assets/AAPL",
      "GET paper-api.alpaca.markets/v2/clock",
      "GET data.alpaca.markets/v2/stocks/AAPL/trades/latest?feed=iex",
    ]);
  });

  it("prices a buy limit order at its limit, in exact decimals, without reading the market", async () => {
    const fake = new FakeAlpaca();
    const r = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "BRK.B", side: "buy", qty: 3, type: "limit", limit_price: "400.1", time_in_force: "gtc" });
    expect(r.args).toMatchObject({ symbol: "BRK.B", limit_price: "400.10", time_in_force: "gtc", notional_usd: 1200.3 });
    // a buy limit can't fill above its limit: no price read
    expect(fake.calls.some((c) => c.host === "data.alpaca.markets")).toBe(false);
  });

  it("keeps sub-dollar prices to 4 decimals and rounds the notional half up to cents", async () => {
    const fake = new FakeAlpaca();
    fake.assets.set("PENNY", { symbol: "PENNY", tradable: true, status: "active" });
    const r = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "PENNY", side: "buy", qty: 30, type: "limit", limit_price: 0.1235 });
    expect(r.args).toMatchObject({ limit_price: "0.1235", notional_usd: 3.71 });
  });

  it("refuses an order worth less than $1 (no zero-value order slips past the drift check)", async () => {
    const fake = new FakeAlpaca();
    fake.assets.set("PENNY", { symbol: "PENNY", tradable: true, status: "active" });
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "PENNY", side: "buy", qty: 3, type: "limit", limit_price: 0.1235 })).rejects.toEqual(err("resolve_failed", /less than \$1/));
  });

  it("signs cents exactly: the number serialises as the decimal", async () => {
    const fake = new FakeAlpaca();
    const r = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 33, type: "limit", limit_price: "0.1" });
    expect(JSON.stringify(r.args["notional_usd"])).toBe("3.3");
    const big = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 100000, type: "limit", limit_price: "9999999.99" });
    expect(JSON.stringify(big.args["notional_usd"])).toBe("999999999000");
  });

  it.each([
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "10000000.00" }, /below \$10,000,000/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "limit" }, /needs limit_price/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "market", limit_price: "1.00" }, /takes no limit_price/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "189.505" }, /whole cents/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "0" }, /above zero/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "1e3" }, /positive price/],
    [{ symbol: "AAPL", side: "buy", qty: 1.5, type: "market" }, /whole number/],
    [{ symbol: "AAPL", side: "buy", qty: 0, type: "market" }, /whole number/],
    [{ symbol: "AAPL", side: "buy", qty: 100001, type: "market" }, /whole number/],
    [{ symbol: "AAPL", side: "short", qty: 1, type: "market" }, /buy or sell/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "stop" }, /market or limit/],
    [{ symbol: "AAPL", side: "buy", qty: 1, type: "market", time_in_force: "ioc" }, /day or gtc/],
    [{ symbol: "../account", side: "buy", qty: 1, type: "market" }, /US stock symbol/],
    [{ symbol: "A/../..", side: "buy", qty: 1, type: "market" }, /US stock symbol/],
  ])("refuses bad input %j before any request", async (args, message) => {
    const fake = new FakeAlpaca();
    await expect(adapter.resolve(resolveCtx(fake), "place_order", args)).rejects.toEqual(err("resolve_failed", message));
    expect(fake.calls).toEqual([]);
  });

  it("refuses a live (non-paper) account", async () => {
    const fake = new FakeAlpaca();
    fake.account["account_number"] = "123456789";
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /not for an Alpaca paper account/));
  });

  it("refuses a blocked or inactive account", async () => {
    const fake = new FakeAlpaca();
    fake.account["trading_blocked"] = true;
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /blocked/));
    fake.account["trading_blocked"] = false;
    fake.account["status"] = "ACCOUNT_CLOSED";
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /not ACTIVE/));
  });

  it("refuses an asset that isn't tradable, or doesn't exist", async () => {
    const fake = new FakeAlpaca();
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "DELIST", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /not tradable/));
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "NOPE", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /no such asset NOPE/));
  });

  it("explains a refused key", async () => {
    const fake = new FakeAlpaca();
    const ctx = { ...resolveCtx(fake), upstream: createReadOnlyClient({ key: () => ({ key_id: "x", secret_key: "y" }), fetch: fake.fetch }) };
    await expect(adapter.resolve(ctx, "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /refused the key \(401\)/));
  });

  it("explains a missing key", async () => {
    const fake = new FakeAlpaca();
    const ctx = { ...resolveCtx(fake), upstream: createReadOnlyClient({ key: () => undefined, fetch: fake.fetch }) };
    await expect(adapter.resolve(ctx, "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /signeto secrets set alpaca/));
    expect(fake.calls).toEqual([]);
  });
});

describe("resolve cancel_order", () => {
  const ID = "11111111-2222-3333-4444-555555555555";

  it("describes the open order being cancelled", async () => {
    const fake = new FakeAlpaca();
    fake.open({ id: ID, symbol: "AAPL", side: "buy", qty: "5", type: "limit" });
    const r = await adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID.toUpperCase() });
    expect(r.args).toEqual({ account: "paper", order_id: ID, side: "buy", qty: 5, symbol: "AAPL", type: "limit" });
  });

  it("refuses an order that was not placed through Signeto, unless the gateway allows it", async () => {
    const fake = new FakeAlpaca();
    fake.open({ id: ID, client_order_id: "placed-by-hand-in-the-dashboard" });
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).rejects.toEqual(err("resolve_failed", /not placed through Signeto/));
    const permissive = createAlpacaAdapter({ cancelAnyOrder: true });
    await expect(permissive.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).resolves.toBeDefined();
  });

  it("refuses an order that is no longer open", async () => {
    const fake = new FakeAlpaca();
    fake.open({ id: ID, status: "filled" });
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).rejects.toEqual(err("resolve_failed", /is filled, not open/));
  });

  it("refuses an order it can't describe (fractional, other types)", async () => {
    const fake = new FakeAlpaca();
    fake.open({ id: ID, qty: "0.5" });
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).rejects.toEqual(err("resolve_failed", /can describe/));
    fake.orders[0]!.qty = "1";
    fake.orders[0]!.type = "stop_limit";
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).rejects.toEqual(err("resolve_failed", /can describe/));
  });

  it("refuses an id that isn't a UUID, and an unknown order", async () => {
    const fake = new FakeAlpaca();
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: "../positions" })).rejects.toEqual(err("resolve_failed", /UUID/));
    await expect(adapter.resolve(resolveCtx(fake), "cancel_order", { order_id: ID })).rejects.toEqual(err("resolve_failed", /no order/));
  });
});

describe("resolve reads", () => {
  it("read_positions and read_orders make no request and default their args", async () => {
    const fake = new FakeAlpaca();
    expect((await adapter.resolve(resolveCtx(fake), "read_positions", {})).args).toEqual({ account: "paper" });
    expect((await adapter.resolve(resolveCtx(fake), "read_orders", {})).args).toEqual({ account: "paper", status: "open", limit: 50 });
    expect((await adapter.resolve(resolveCtx(fake), "read_orders", { status: "all", limit: 5 })).args).toEqual({ account: "paper", status: "all", limit: 5 });
    await expect(adapter.resolve(resolveCtx(fake), "read_orders", { limit: 51 })).rejects.toEqual(err("resolve_failed"));
    expect(fake.calls).toEqual([]);
  });

  it("refuses an unknown tool and a non-object", async () => {
    const fake = new FakeAlpaca();
    await expect(adapter.resolve(resolveCtx(fake), "transfer_funds", {})).rejects.toEqual(err("resolve_failed", /unknown tool/));
    await expect(adapter.resolve(resolveCtx(fake), "read_positions", [])).rejects.toEqual(err("resolve_failed", /object/));
  });

  it("needs the Alpaca read-only client as upstream", async () => {
    await expect(adapter.resolve({ upstream: {}, deadline: future(), logger }, "read_positions", {})).rejects.toEqual(err("resolve_failed", /AlpacaReadOnlyClient/));
  });
});

describe("read-only client", () => {
  it("sends GET only, to allowlisted paths, with the key, refusing redirects", async () => {
    const fake = new FakeAlpaca();
    const seen: RequestInit[] = [];
    const client = createReadOnlyClient({ key: () => KEY, fetch: (u, i) => (seen.push(i ?? {}), fake.fetch(u, i)) });
    await client.get("trading", "/v2/account");
    expect(seen[0]).toMatchObject({ method: "GET", redirect: "error" });
    for (const [api, path] of [
      ["trading", "/v2/orders"],
      ["trading", "/v2/positions"],
      ["trading", "/v2/account/configurations"],
      ["trading", "/v2/assets/AAPL/../../orders"],
      ["trading", "/v2/assets/A/../.."],
      ["trading", "/v2/assets/.."],
      ["data", "/v2/stocks/AAPL/bars"],
      ["data", "/v2/stocks/AAPL/trades/latest?feed=x"],
    ] as const) {
      await expect(client.get(api, path)).rejects.toEqual(err("resolve_failed", /refuses/));
    }
    expect(fake.calls).toHaveLength(1);
  });
});

describe("resolve place_order: sells, market hours, stale prices (security review 2026-11-23)", () => {
  it("values a sell limit far below the market at the market: the card and policy see the real value", async () => {
    const fake = new FakeAlpaca();
    const r = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 10, type: "limit", limit_price: "0.01" });
    // 10 × max(0.01, 189.50), not 10 × 0.01
    expect(r.args).toMatchObject({ side: "sell", limit_price: "0.01", notional_usd: 1895 });
    expect(r.facts).toEqual({ notional_usd: 1895 });
  });

  it("values a sell limit above the market at its limit", async () => {
    const fake = new FakeAlpaca();
    const r = await adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 10, type: "limit", limit_price: "200.00" });
    expect(r.args).toMatchObject({ notional_usd: 2000 });
  });

  it("refuses a sell that would open or extend a short", async () => {
    const fake = new FakeAlpaca();
    // no BRK.B position
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "BRK.B", side: "sell", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /hold no BRK.B.*shorting is refused/));
    // more than held
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 11, type: "market" })).rejects.toEqual(err("resolve_failed", /10 AAPL available to sell; this order sells 11/));
    // a short position
    fake.positions = [{ symbol: "AAPL", qty: "-5", qty_available: "-5", side: "short" }];
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 1, type: "limit", limit_price: "190.00" })).rejects.toEqual(err("resolve_failed", /not a long position/));
    expect(fake.writes()).toEqual([]);
  });

  it("counts shares already held for other open orders: qty_available, not qty", async () => {
    const fake = new FakeAlpaca();
    fake.positions = [{ symbol: "AAPL", qty: "10", qty_available: "4", side: "long" }];
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 5, type: "market" })).rejects.toEqual(err("resolve_failed", /4 AAPL available/));
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "sell", qty: 4, type: "market" })).resolves.toBeDefined();
  });

  it("refuses a market order while the market is closed; a limit order is still taken", async () => {
    const fake = new FakeAlpaca();
    fake.isOpen = false;
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /market is closed/));
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "180.00" })).resolves.toBeDefined();
  });

  it("refuses a market order valued from a stale or undated trade", async () => {
    const fake = new FakeAlpaca();
    fake.tradeTime = () => new Date(Date.now() - 20 * 60_000).toISOString();
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /20 minutes old/));
    fake.tradeTime = () => undefined;
    await expect(adapter.resolve(resolveCtx(fake), "place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "market" })).rejects.toEqual(err("resolve_failed", /didn't say when/));
  });
});

describe("the read-only client and a malformed stored key (security review 2026-11-23)", () => {
  it("refuses a key with a line break or a space before it goes into a header, and never quotes it", async () => {
    const fake = new FakeAlpaca();
    for (const bad of [{ ...KEY, secret_key: "part-one\npart-two" }, { ...KEY, key_id: "PK KEY" }, { ...KEY, secret_key: "x\u0000y" }]) {
      const client = createReadOnlyClient({ key: () => bad, fetch: fake.fetch });
      const e = await client.get("trading", "/v2/account").catch((x: unknown) => x as Error);
      expect(e).toEqual(err("resolve_failed", /characters a key can't have/));
      expect(JSON.stringify(e) + String(e)).not.toMatch(/part-one|part-two|PK KEY/);
    }
    expect(fake.calls).toEqual([]);
  });

  it("a fetch error that quotes the request's headers is reported by its class name only", async () => {
    const leaky: typeof fetch = async (_url, init) => {
      const h = (init?.headers ?? {}) as Record<string, string>;
      throw new TypeError(`Headers.append: "${h["apca-api-secret-key"]}" is an invalid header value.`);
    };
    const client = createReadOnlyClient({ key: () => KEY, fetch: leaky });
    const e = await client.get("trading", "/v2/account").catch((x: unknown) => x as Error);
    expect(e).toEqual(err("upstream_unreachable", /^Alpaca not reachable \(TypeError\)$/));
    expect(JSON.stringify(e) + String(e)).not.toContain(KEY.secret_key);
  });
});
