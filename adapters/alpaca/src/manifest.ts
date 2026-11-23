// The signed surface of the Alpaca adapter: resolved schemas and display templates (docs/adapters.md §2, §6).
// `alpaca.place_order` v2 must stay byte-identical to the builtin registry in @signeto/protocol (the apps render it
// from there); `alpaca.cancel_order` v1 is bundled there too, from the app builds after 2026-11-23.
//
// Custody mode (docs/adapters.md §3.3): Alpaca has no scoped or short-lived keys, so the gateway keeps the account's
// key pair in its encrypted store and unlocks it for one approved request. Paper trading only: the only trading host
// is paper-api.alpaca.markets. A live account is a later, explicit opt-in, not a setting of this adapter.
import type { AdapterManifest, ToolSpec } from "@signeto/adapter-sdk";
import { decimalInput, enm, int, nullableDecimal, num, obj, str } from "./schema.js";

/** Alpaca's paper trading API: the only trading host this adapter talks to. */
export const ALPACA_PAPER_HOST = "paper-api.alpaca.markets";
/** Alpaca's market data API (latest trade prices for a market order's notional value). */
export const ALPACA_DATA_HOST = "data.alpaca.markets";
/** What the card says the account is. Paper only, so always "paper". */
export const ACCOUNT_LABEL = "paper";

export const SECRET_KEY_ID = "key_id";
export const SECRET_SECRET_KEY = "secret_key";

/**
 * US equity symbols as Alpaca lists them: capitals and digits, one dot for a share class (BRK.B). No slash and no
 * second dot, so a symbol can never be a path segment like `..` in the URLs it is put into.
 */
export const SYMBOL_BODY = "[A-Z][A-Z0-9]{0,5}(?:\\.[A-Z0-9]{1,3})?";
export const SYMBOL_PATTERN = `^${SYMBOL_BODY}$`;
export const SYMBOL_INPUT_PATTERN = "^[A-Za-z][A-Za-z0-9]{0,5}(?:\\.[A-Za-z0-9]{1,3})?$";
/** A price as signed: digits, a point, 2 to 4 decimals (Alpaca: 2 at $1 and above, up to 4 below $1). */
export const PRICE_PATTERN = "^(0|[1-9][0-9]{0,6})\\.[0-9]{2,4}$";
/** The largest notional value: MAX_QTY shares at the largest price ($9,999,999.99), inside safe integers in cents. */
export const MAX_NOTIONAL_USD = 1_000_000_000_000;
export const ORDER_ID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

export const SIDES = ["buy", "sell"] as const;
export const ORDER_TYPES = ["market", "limit"] as const;
export const TIMES_IN_FORCE = ["day", "gtc"] as const;
/** Whole shares per order; Alpaca's own limits apply below this. */
export const MAX_QTY = 100_000;

export const placeOrder: ToolSpec = {
  name: "place_order",
  description:
    "Place a stock order on the Alpaca paper account (whole shares; market or limit; day or gtc). The approver signs the exact order: side, quantity, symbol, type, limit price, time in force and the estimated value. Returns Alpaca's order id and status, and the fill if it comes within a few seconds.",
  effect: "write",
  classification: "internal",
  input: obj(
    {
      symbol: str(SYMBOL_INPUT_PATTERN, 10),
      side: enm(...SIDES),
      qty: int(1, MAX_QTY),
      type: enm(...ORDER_TYPES),
      limit_price: decimalInput(),
      time_in_force: enm(...TIMES_IN_FORCE),
    },
    ["symbol", "side", "qty", "type"],
  ),
  resolved: obj(
    {
      account: enm(ACCOUNT_LABEL),
      side: enm(...SIDES),
      qty: int(1, MAX_QTY),
      symbol: str(SYMBOL_PATTERN, 10),
      type: enm(...ORDER_TYPES),
      limit_price: nullableDecimal(PRICE_PATTERN),
      time_in_force: enm(...TIMES_IN_FORCE),
      // A number, not a string, so policy can set thresholds on it (`when: { notional_usd: { gt: 500 } }`).
      notional_usd: num(0, MAX_NOTIONAL_USD),
    },
    ["account", "side", "qty", "symbol", "type", "limit_price", "time_in_force", "notional_usd"],
  ),
  template: {
    id: "alpaca.place_order",
    // v2 (SIG-92 N9): every argument in the sentence; v1 elided limit_price and time_in_force.
    version: 2,
    text: "Place order: {side} {qty} {symbol} {type}, limit price {limit_price}, time in force {time_in_force}, on {account} (notional {notional_usd} USD)",
  },
};

export const cancelOrder: ToolSpec = {
  name: "cancel_order",
  description: "Cancel an open order on the Alpaca paper account by its order id. The approver (when policy asks for one) signs the order being cancelled.",
  effect: "write",
  classification: "internal",
  input: obj({ order_id: str(ORDER_ID_PATTERN, 36) }, ["order_id"]),
  resolved: obj(
    {
      account: enm(ACCOUNT_LABEL),
      order_id: str(ORDER_ID_PATTERN, 36),
      side: enm(...SIDES),
      qty: int(1, MAX_QTY),
      symbol: str(SYMBOL_PATTERN, 10),
      type: enm(...ORDER_TYPES),
    },
    ["account", "order_id", "side", "qty", "symbol", "type"],
  ),
  template: {
    id: "alpaca.cancel_order",
    version: 1,
    text: "Cancel order {order_id}: {side} {qty} {symbol} {type} on {account}",
  },
};

export const readPositions: ToolSpec = {
  name: "read_positions",
  description: "List the open positions on the Alpaca paper account: symbol, quantity, market value, unrealised profit or loss.",
  effect: "read",
  classification: "internal",
  input: obj({}, []),
  resolved: obj({ account: enm(ACCOUNT_LABEL) }, ["account"]),
  template: { id: "alpaca.read_positions", version: 1, text: "Read positions on {account}" },
};

export const ORDER_STATUSES = ["open", "closed", "all"] as const;

export const readOrders: ToolSpec = {
  name: "read_orders",
  description: "List orders on the Alpaca paper account: open (default), closed or all, newest first, at most 50.",
  effect: "read",
  classification: "internal",
  input: obj({ status: enm(...ORDER_STATUSES), limit: int(1, 50) }, []),
  resolved: obj({ account: enm(ACCOUNT_LABEL), status: enm(...ORDER_STATUSES), limit: int(1, 50) }, ["account", "status", "limit"]),
  template: { id: "alpaca.read_orders", version: 1, text: "Read {status} orders on {account} (at most {limit})" },
};

export const manifest: AdapterManifest = {
  name: "alpaca",
  version: "0.1.0",
  mode: "custody",
  egress: [ALPACA_PAPER_HOST, ALPACA_DATA_HOST],
  secrets: [
    { name: SECRET_KEY_ID, description: "Alpaca paper trading API key id (APCA-API-KEY-ID)" },
    { name: SECRET_SECRET_KEY, description: "Alpaca paper trading API secret key (APCA-API-SECRET-KEY)" },
  ],
  tools: [placeOrder, cancelOrder, readPositions, readOrders],
};
