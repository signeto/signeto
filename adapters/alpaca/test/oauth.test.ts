// Signeto Cloud's credential: an OAuth access token held by its custody service. The same resolve and execute
// code runs with it; only the Authorization header differs.
import { describe, expect, it } from "vitest";
import type { Adapter } from "@signeto/adapter-sdk";
import { READ_PATHS, createAlpacaAdapter, createReadOnlyClient, isAllowedRead, isWellFormedCredential, oauthCredential } from "../src/index.js";
import { FakeAlpaca, KEY, TOKEN, executeCtx, frozen, future, recordingLogger, resolveCtx } from "./helpers.js";

const err = (code: string, message?: RegExp) => expect.objectContaining({ code, ...(message ? { message: expect.stringMatching(message) } : {}) });
const LIMIT = { symbol: "AAPL", side: "buy", qty: 2, type: "limit", limit_price: "150.00", time_in_force: "gtc" };
const MARKET = { symbol: "AAPL", side: "buy", qty: 10, type: "market" };

function fastAdapter(): Adapter {
  let t = 0;
  return createAlpacaAdapter({ now: () => t, sleep: async (ms) => void (t += ms) });
}

function tokenOnly(): FakeAlpaca {
  const fake = new FakeAlpaca();
  fake.oauthToken = TOKEN;
  return fake;
}

const viaToken = (fake: FakeAlpaca) => fake.calls.every((c) => c.headers["authorization"] === `Bearer ${TOKEN}` && c.headers["apca-api-key-id"] === undefined && c.headers["apca-api-secret-key"] === undefined);

describe("OAuth token (Signeto Cloud)", () => {
  it("resolve reads with a Bearer header and no key headers", async () => {
    const fake = tokenOnly();
    const r = await fastAdapter().resolve(resolveCtx(fake, undefined, { access_token: TOKEN }), "place_order", LIMIT);
    expect(r.args).toMatchObject({ symbol: "AAPL", qty: 2 });
    expect(fake.calls.length).toBeGreaterThan(0);
    expect(viaToken(fake)).toBe(true);
  });

  it("a token Alpaca doesn't accept (revoked, or another app's) fails resolve; nothing is retried with anything else", async () => {
    const fake = tokenOnly();
    fake.oauthToken = "some-other-token-value";
    await expect(fastAdapter().resolve(resolveCtx(fake, undefined, { access_token: TOKEN }), "place_order", LIMIT)).rejects.toBeDefined();
    expect(fake.calls).toHaveLength(1);
    expect(viaToken(fake)).toBe(true);
  });

  it("oauthCredential wraps the token for one action: scope names no secret, expiry follows the action", async () => {
    const action = frozen("place_order", { symbol: "AAPL", side: "buy", qty: 1, type: "limit", limit_price: "150.00", time_in_force: "gtc", terms: "limit 150.00, good till canceled", notional_usd: 150, last_price: "189.50", last_trade_at: new Date().toISOString(), account: "paper" });
    const c = oauthCredential(TOKEN, action, future());
    expect(c.scope).toBe(`hosted: alpaca paper OAuth token, one place_order request for ${action.id}`);
    expect(c.scope).not.toContain(TOKEN);
    const expires = (JSON.parse(new TextDecoder().decode(action.canonicalBytes)) as { expires_at: string }).expires_at;
    expect(c.expiresAt.toISOString().slice(0, 19)).toBe(expires.slice(0, 19));
  });

  it("execute places exactly one order with the token, and a second execute with the same credential is refused", async () => {
    const adapter = fastAdapter();
    const fake = tokenOnly();
    const r = await adapter.resolve(resolveCtx(fake, undefined, { access_token: TOKEN }), "place_order", LIMIT);
    const action = frozen("place_order", r.args);
    const c = oauthCredential(TOKEN, action, future());
    fake.calls = [];
    const res = await adapter.execute(executeCtx(fake), action, c);
    expect(res).toBeDefined();
    expect(fake.calls.filter((x) => x.method === "POST")).toHaveLength(1);
    expect(fake.calls.find((x) => x.method === "POST")?.body).toMatchObject({ client_order_id: action.id, limit_price: "150.00" });
    expect(viaToken(fake)).toBe(true);
    await expect(adapter.execute(executeCtx(fake), action, c)).rejects.toEqual(err("credential_failed", /already sent its one request/));
  });

  it("cancel and reads work with the token", async () => {
    const adapter = fastAdapter();
    const fake = tokenOnly();
    for (const [tool, input] of [["read_positions", {}], ["read_orders", {}]] as const) {
      const r = await adapter.resolve(resolveCtx(fake, undefined, { access_token: TOKEN }), tool, input);
      const action = frozen(tool, r.args);
      await adapter.execute(executeCtx(fake), action, oauthCredential(TOKEN, action, future()));
    }
    expect(viaToken(fake)).toBe(true);
  });

  it("revoke drops the token: execute refuses and sends nothing", async () => {
    const adapter = fastAdapter();
    const fake = tokenOnly();
    const r = await adapter.resolve(resolveCtx(fake, undefined, { access_token: TOKEN }), "place_order", MARKET);
    const action = frozen("place_order", r.args);
    const c = oauthCredential(TOKEN, action, future());
    await c.revoke!();
    fake.calls = [];
    expect(JSON.stringify(c.material)).not.toContain(TOKEN);
    await expect(adapter.execute(executeCtx(fake), action, c)).rejects.toEqual(err("credential_failed"));
    expect(fake.calls).toEqual([]);
  });

  it("a malformed token is refused without being quoted, in oauthCredential and in resolve", async () => {
    const bad = "line-one\nline-two-token";
    const action = frozen("read_positions", { account: "paper" });
    const e1 = (() => {
      try {
        oauthCredential(bad, action, future());
      } catch (x) {
        return x;
      }
    })();
    expect(e1).toEqual(err("credential_failed", /connect the Alpaca account again/));
    const fake = tokenOnly();
    const e2 = await fastAdapter().resolve(resolveCtx(fake, undefined, { access_token: bad }), "place_order", LIMIT).catch((x: unknown) => x);
    expect(e2).toEqual(err("resolve_failed", /connect the Alpaca account again/));
    expect(String(e1) + JSON.stringify(e1) + String(e2) + JSON.stringify(e2)).not.toMatch(/line-one|line-two/);
    expect(fake.calls).toEqual([]);
  });

  it("a credential carrying both a key and a token is refused", () => {
    expect(isWellFormedCredential({ access_token: TOKEN, ...KEY })).toBe(false);
    expect(isWellFormedCredential({ access_token: TOKEN })).toBe(true);
    expect(isWellFormedCredential(KEY)).toBe(true);
  });

  it("the token never appears in args, facts, results, scope or logs, on success or failure", async () => {
    const { logger, lines } = recordingLogger();
    const adapter = fastAdapter();
    const fake = tokenOnly();
    const out: unknown[] = [];
    for (const [tool, input] of [["place_order", MARKET], ["place_order", LIMIT], ["read_positions", {}], ["read_orders", {}]] as const) {
      const r = await adapter.resolve(resolveCtx(fake, logger, { access_token: TOKEN }), tool, input);
      const action = frozen(tool, r.args);
      const c = oauthCredential(TOKEN, action, future());
      out.push(r, new TextDecoder().decode(action.canonicalBytes), c.scope, await adapter.execute({ ...executeCtx(fake), logger }, action, c));
    }
    const r = await adapter.resolve(resolveCtx(fake, logger, { access_token: TOKEN }), "place_order", MARKET);
    const action = frozen("place_order", r.args);
    fake.prices.set("AAPL", 400);
    await adapter.execute({ ...executeCtx(fake), logger }, action, oauthCredential(TOKEN, action, future())).catch((e: unknown) => out.push(String(e), JSON.stringify(e)));
    expect(JSON.stringify(out) + lines.join("\n")).not.toContain(TOKEN);
  });
});

describe("the read allowlist Signeto Cloud shares", () => {
  it("allows exactly resolve's reads", () => {
    expect(isAllowedRead("trading", "/v2/account")).toBe(true);
    expect(isAllowedRead("trading", "/v2/clock")).toBe(true);
    expect(isAllowedRead("data", "/v2/stocks/AAPL/trades/latest?feed=iex")).toBe(true);
    expect(isAllowedRead("trading", "/v2/orders")).toBe(false);
    expect(isAllowedRead("trading", "/v2/account/configurations")).toBe(false);
    expect(isAllowedRead("data", "/v2/account")).toBe(false);
    expect(isAllowedRead("live", "/v2/account")).toBe(false);
    expect(isAllowedRead("trading", 42)).toBe(false);
    expect(Object.keys(READ_PATHS).sort()).toEqual(["data", "trading"]);
  });

  it("the read-only client refuses anything else, with a token too", async () => {
    const fake = tokenOnly();
    const client = createReadOnlyClient({ key: () => ({ access_token: TOKEN }), fetch: fake.fetch });
    await expect(client.get("trading", "/v2/orders")).rejects.toEqual(err("resolve_failed", /refuses/));
    expect(fake.calls).toEqual([]);
  });
});
