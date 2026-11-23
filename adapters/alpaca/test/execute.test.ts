import { describe, expect, it } from "vitest";
import type { Adapter, Credential } from "@signeto/adapter-sdk";
import { createAlpacaAdapter } from "../src/index.js";
import { FakeAlpaca, KEY, credentialCtx, executeCtx, frozen, recordingLogger, resolveCtx } from "./helpers.js";

const err = (code: string, message?: RegExp) => expect.objectContaining({ code, ...(message ? { message: expect.stringMatching(message) } : {}) });

/** An adapter whose fill wait advances a fake clock instead of sleeping. */
function fastAdapter(opts: { settleMs?: number; maxDriftPct?: number } = {}): Adapter {
  let t = 0;
  return createAlpacaAdapter({ now: () => t, sleep: async (ms) => void (t += ms), ...opts });
}

async function approved(adapter: Adapter, fake: FakeAlpaca, tool: string, input: Record<string, unknown>) {
  const r = await adapter.resolve(resolveCtx(fake), tool, input);
  const action = frozen(tool, r.args);
  const credential = await adapter.custody!(credentialCtx(fake), action);
  fake.calls = [];
  return { action, credential };
}

const MARKET = { symbol: "AAPL", side: "buy", qty: 10, type: "market" };
const LIMIT = { symbol: "AAPL", side: "buy", qty: 2, type: "limit", limit_price: "150.00", time_in_force: "gtc" };

describe("custody", () => {
  it("hands over the key pair for one request, scoped to the action, expiring with it", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    expect(credential.scope).toBe(`custody: alpaca paper key …ABCD, one place_order request for ${action.id}`);
    expect(credential.scope).not.toContain(KEY.secret_key);
    const expires = (JSON.parse(new TextDecoder().decode(action.canonicalBytes)) as { expires_at: string }).expires_at;
    expect(credential.expiresAt.toISOString().slice(0, 19)).toBe(expires.slice(0, 19));
    expect(credential.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(3600_000);
  });

  it("refuses without both secrets", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const action = frozen("read_positions", { account: "paper" });
    await expect(adapter.custody!(credentialCtx(fake, { key_id: KEY.key_id }), action)).rejects.toEqual(err("credential_failed", /secret_key/));
  });

  it("revoke drops the key: execute with a revoked credential refuses", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    await credential.revoke!();
    expect(JSON.stringify(credential.material)).not.toContain(KEY.secret_key);
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("credential_failed"));
    expect(fake.calls).toEqual([]);
  });
});

describe("execute place_order", () => {
  it("re-prices, sends exactly one order with the action id as client_order_id, and reports the fill", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.writes()).toHaveLength(1);
    expect(fake.writes()[0]).toMatchObject({
      method: "POST",
      host: "paper-api.alpaca.markets",
      path: "/v2/orders",
      body: { symbol: "AAPL", qty: "10", side: "buy", type: "market", time_in_force: "day", client_order_id: action.id },
    });
    expect(fake.calls[0]).toMatchObject({ method: "GET", host: "data.alpaca.markets" });
    expect(r.content).toMatchObject({ symbol: "AAPL", status: "filled", filled_qty: "10", filled_avg_price: "189.5", client_order_id: action.id });
    expect(r.evidence).toMatchObject({ client_order_id: action.id, status: "filled" });
  });

  it("sends a limit order with its signed limit price and no re-pricing", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", LIMIT);
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.calls.some((c) => c.host === "data.alpaca.markets")).toBe(false);
    expect(fake.writes()[0]!.body).toMatchObject({ type: "limit", limit_price: "150.00", time_in_force: "gtc" });
    // a resting limit order is read back until settleMs, then reported as it is
    expect(r.content).toMatchObject({ status: "accepted", filled_qty: "0" });
  });

  it("refuses a market order whose price moved past the drift limit, sending nothing", async () => {
    const adapter = fastAdapter({ maxDriftPct: 5 });
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.prices.set("AAPL", 199.5); // +5.28%
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("precondition_failed", /moved 5\.2\d% since approval/));
    expect(fake.writes()).toEqual([]);
  });

  it("allows drift within the limit", async () => {
    const adapter = fastAdapter({ maxDriftPct: 5 });
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.prices.set("AAPL", 180.1); // -4.96%
    await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.writes()).toHaveLength(1);
  });

  it("one request per credential: a second execute with the same credential is refused", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    await adapter.execute(executeCtx(fake), action, credential);
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("credential_failed", /already sent its one request/));
    expect(fake.writes()).toHaveLength(1);
    expect(fake.orders).toHaveLength(1);
  });

  it("a replayed approval with a fresh credential gets Alpaca's duplicate refusal and reports the existing order", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    await adapter.execute(executeCtx(fake), action, credential);
    const again: Credential = await adapter.custody!(credentialCtx(fake), action);
    const r = await adapter.execute(executeCtx(fake), action, again);
    expect(fake.orders).toHaveLength(1);
    expect(r.content).toMatchObject({ id: fake.orders[0]!.id, client_order_id: action.id });
    expect(fake.calls.some((c) => c.path.startsWith("/v2/orders:by_client_order_id"))).toBe(true);
  });

  it("a dropped connection after Alpaca took the order: looks it up by client id, never resends", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.dropOrder = "after";
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.writes()).toHaveLength(1);
    expect(fake.orders).toHaveLength(1);
    expect(r.content).toMatchObject({ client_order_id: action.id });
  });

  it("a dropped connection before Alpaca took the order: fails without retrying", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.dropOrder = "before";
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(expect.objectContaining({ code: "upstream_unreachable", retryable: false }));
    expect(fake.writes()).toHaveLength(1);
    expect(fake.orders).toHaveLength(0);
  });

  it("an answer lost after Alpaca took the order (503, garbage, no answer): looks it up, never resends", async () => {
    for (const answer of ["503", "garbage", "hang"] as const) {
      const adapter = createAlpacaAdapter({ now: () => 0, sleep: async () => {}, orderTimeoutMs: 50 });
      const fake = new FakeAlpaca();
      const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
      fake.orderAnswer = answer;
      const r = await adapter.execute(executeCtx(fake), action, credential);
      expect(fake.writes(), answer).toHaveLength(1);
      expect(r.content).toMatchObject({ client_order_id: action.id });
    }
  });

  it("an order that takes a moment to show up is found on the second look", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.dropOrder = "after";
    fake.lookupLag = 1;
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(r.content).toMatchObject({ client_order_id: action.id });
    expect(fake.writes()).toHaveLength(1);
  });

  it("when the lookup fails too, the outcome is unknown: not 'no order', not retryable", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    fake.dropOrder = "after";
    fake.lookupFailures = 1;
    const e = await adapter.execute(executeCtx(fake), action, credential).catch((x: unknown) => x as { code: string; message: string; retryable: boolean; detail?: unknown });
    expect(e).toEqual(expect.objectContaining({ code: "upstream_unreachable", retryable: false, message: expect.stringMatching(/is unknown/) }));
    expect(e.detail).toEqual({ client_order_id: action.id, outcome: "unknown" });
    // the order does exist; nothing was sent twice
    expect(fake.orders).toHaveLength(1);
    expect(fake.writes()).toHaveLength(1);
  });

  it("refuses to start with too little time left to send and look up the order", async () => {
    const adapter = createAlpacaAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", LIMIT);
    await expect(adapter.execute({ ...executeCtx(fake), deadline: new Date(Date.now() + 5_000) }, action, credential)).rejects.toEqual(err("precondition_failed", /too little time.*nothing was sent/));
    expect(fake.writes()).toEqual([]);
  });

  it("re-values a sell limit below the market and refuses it if the market moved past the drift limit", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", { symbol: "AAPL", side: "sell", qty: 10, type: "limit", limit_price: "0.01" });
    expect(action.args["notional_usd"]).toBe(1895);
    fake.prices.set("AAPL", 210);
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("precondition_failed", /moved .*nothing was sent/));
    expect(fake.writes()).toEqual([]);
  });

  it("a fetch error quoting the key never reaches the error", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", LIMIT);
    const leaky: typeof fetch = async (url, init) => {
      if ((init?.method ?? "GET") === "POST") throw new TypeError(`Headers.append: "${(init!.headers as Record<string, string>)["apca-api-secret-key"]}" is an invalid header value.`);
      return fake.fetch(url, init);
    };
    const e = await adapter.execute({ ...executeCtx(fake), fetch: leaky }, action, credential).catch((x: unknown) => x);
    expect(JSON.stringify(e) + String(e)).not.toContain(KEY.secret_key);
    expect(e).toEqual(err("upstream_unreachable", /probably not placed/));
  });

  it("custody refuses a malformed stored key with a message that doesn't quote it", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const action = frozen("read_positions", { account: "paper" });
    const e = await adapter.custody!(credentialCtx(fake, { key_id: KEY.key_id, secret_key: "line-one\nline-two" }), action).catch((x: unknown) => x);
    expect(e).toEqual(err("credential_failed", /characters a key can't have/));
    expect(String(e) + JSON.stringify(e)).not.toMatch(/line-one|line-two/);
  });

  it("refuses when Alpaca's order differs from the signed one", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", LIMIT);
    const f = fake.fetch;
    fake.fetch = async (u, i) => {
      const res = await f(u, i);
      if (i?.method === "POST") {
        const o = (await res.json()) as Record<string, unknown>;
        return new Response(JSON.stringify({ ...o, qty: "20" }), { status: 200 });
      }
      return res;
    };
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("upstream_rejected", /does not match the signed one/));
  });

  it("passes Alpaca's refusal through (e.g. buying power)", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "place_order", LIMIT);
    fake.fetch = async () => new Response(JSON.stringify({ code: 40310000, message: "insufficient buying power" }), { status: 403 });
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("upstream_rejected", /insufficient buying power/));
  });

  it("only talks to the manifest's hosts, and refuses redirects", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const inits: RequestInit[] = [];
    const f = fake.fetch;
    fake.fetch = (u, i) => (inits.push(i ?? {}), f(u, i));
    const { action, credential } = await approved(adapter, fake, "place_order", MARKET);
    await adapter.execute(executeCtx(fake), action, credential);
    for (const c of fake.calls) expect(["paper-api.alpaca.markets", "data.alpaca.markets"]).toContain(c.host);
    for (const i of inits) expect(i.redirect).toBe("error");
  });
});

describe("execute cancel_order", () => {
  const ID = "11111111-2222-3333-4444-555555555555";

  it("sends one DELETE for the signed order", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    fake.open({ id: ID });
    const { action, credential } = await approved(adapter, fake, "cancel_order", { order_id: ID });
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.writes()).toEqual([expect.objectContaining({ method: "DELETE", path: `/v2/orders/${ID}` })]);
    expect(r.content).toEqual({ order_id: ID, cancel_requested: true });
    expect(fake.orders[0]!.status).toBe("canceled");
  });

  it("reports an order that filled between approval and cancel", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    fake.open({ id: ID });
    const { action, credential } = await approved(adapter, fake, "cancel_order", { order_id: ID });
    fake.orders[0]!.status = "filled";
    await expect(adapter.execute(executeCtx(fake), action, credential)).rejects.toEqual(err("upstream_rejected", /can no longer be cancelled/));
  });
});

describe("execute reads", () => {
  it("read_positions returns the picked fields only", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const { action, credential } = await approved(adapter, fake, "read_positions", {});
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(r.content).toEqual({ account: "paper", positions: [{ symbol: "AAPL", qty: "10", side: "long", avg_entry_price: "180.00", market_value: "1895.00", unrealized_pl: "95.00", current_price: "189.50" }] });
    expect(fake.writes()).toEqual([]);
  });

  it("read_orders asks for the signed status and limit", async () => {
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    fake.open({ id: "11111111-2222-3333-4444-555555555555" });
    const { action, credential } = await approved(adapter, fake, "read_orders", { status: "all", limit: 5 });
    const r = await adapter.execute(executeCtx(fake), action, credential);
    expect(fake.calls[0]!.path).toBe("/v2/orders?status=all&limit=5&direction=desc");
    expect(r.evidence).toEqual({ count: 1 });
  });
});

describe("the key stays secret", () => {
  it("never appears in args, facts, results, evidence, scope or logs", async () => {
    const { logger, lines } = recordingLogger();
    const adapter = fastAdapter();
    const fake = new FakeAlpaca();
    const out: unknown[] = [];
    for (const [tool, input] of [
      ["place_order", MARKET],
      ["place_order", LIMIT],
      ["read_positions", {}],
      ["read_orders", {}],
    ] as const) {
      const r = await adapter.resolve({ ...resolveCtx(fake), logger }, tool, input);
      const action = frozen(tool, r.args);
      const c = await adapter.custody!(credentialCtx(fake, KEY, logger), action);
      const res = await adapter.execute({ ...executeCtx(fake), logger }, action, c);
      await c.revoke!();
      out.push(r, new TextDecoder().decode(action.canonicalBytes), c.scope, res);
    }
    // and on failure
    const r = await adapter.resolve({ ...resolveCtx(fake), logger }, "place_order", MARKET);
    const action = frozen("place_order", r.args);
    const c = await adapter.custody!(credentialCtx(fake, KEY, logger), action);
    fake.prices.set("AAPL", 400);
    await adapter.execute({ ...executeCtx(fake), logger }, action, c).catch((e: unknown) => out.push(String(e), JSON.stringify(e)));
    const all = JSON.stringify(out) + lines.join("\n");
    expect(all).not.toContain(KEY.secret_key);
    expect(all).not.toContain(KEY.key_id);
  });
});
