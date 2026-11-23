// The signed surface of the Alpaca adapter: resolved schemas and display templates (docs/adapters.md §2, §6).
// Every template here must stay byte-identical to the builtin registry in @signeto/protocol (the apps render them from
// there). `alpaca.place_order` v3 and `alpaca.cancel_order` v2 are bundled in the app builds from iOS 1.1.1 (16) and
// Android 1.1.1 (8): release a gateway that sends them only once those builds are out, or older apps show the card
// as "unverified template".
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

/**
 * How the order trades, in words, as the card says it: `at market` or `limit 349.50`, then `, good till canceled` for
 * gtc and, for a limit order, `, today only` for day (a market order fills now, so day goes unsaid).
 */
export const TERMS_PATTERN = "^(at market|limit (0|[1-9][0-9]{0,6})\\.[0-9]{2,4})(, today only|, good till canceled)?$";
/** When the last trade happened, to the minute: `2026-11-23 20:06 UTC`. */
export const TRADE_TIME_PATTERN = "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC$";

/** `terms` for an order's type, limit price (formatted, or null) and time in force. */
export function termsOf(type: string, limitPrice: string | null, timeInForce: string): string {
  const how = type === "market" ? "at market" : `limit ${limitPrice}`;
  if (timeInForce === "gtc") return `${how}, good till canceled`;
  return type === "market" ? how : `${how}, today only`;
}

export const placeOrder: ToolSpec = {
  name: "place_order",
  description:
    "Place a stock order on the Alpaca paper account (whole shares; market or limit; day or gtc). The approver signs the exact order: side, quantity, symbol, type, limit price, time in force and the estimated value, with the last trade for reference. Returns Alpaca's order id and status, and the fill if it comes within a few seconds.",
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
      // type, limit_price and time_in_force in words (termsOf); execute refuses an order whose terms don't match them.
      terms: str(TERMS_PATTERN, 60),
      // The last trade when the order was priced, for the approver to compare a limit with the market. Shown, not used
      // to value a buy limit order.
      last_price: str(PRICE_PATTERN, 12),
      last_trade_at: str(TRADE_TIME_PATTERN, 20),
    },
    ["account", "side", "qty", "symbol", "type", "limit_price", "time_in_force", "notional_usd", "terms", "last_price", "last_trade_at"],
  ),
  template: {
    id: "alpaca.place_order",
    // v3: the order's terms in words (no "limit price null"), and the last trade on the note line. type, limit_price
    // and time_in_force stay signed (policy can test them) and are listed under the card's hidden fields.
    version: 3,
    text: "Place order on {account}: {side} {qty} {symbol} {terms} (value {notional_usd} USD)",
    elide: ["type", "limit_price", "time_in_force", "last_price", "last_trade_at"],
    note: "Last trade {last_price} USD at {last_trade_at}.",
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
      limit_price: nullableDecimal(PRICE_PATTERN),
      time_in_force: enm(...TIMES_IN_FORCE),
      terms: str(TERMS_PATTERN, 60),
    },
    ["account", "order_id", "side", "qty", "symbol", "type", "limit_price", "time_in_force", "terms"],
  ),
  template: {
    id: "alpaca.cancel_order",
    // v2: the order's terms in words, as on the order card; the order id on the note line.
    version: 2,
    text: "Cancel order on {account}: {side} {qty} {symbol} {terms}",
    elide: ["order_id", "type", "limit_price", "time_in_force"],
    note: "Order {order_id}.",
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
