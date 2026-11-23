// Prices and notional values are signed as decimal strings, so they are computed here in exact integer arithmetic
// (ten-thousandths of a dollar), never in floating point: the card must show the number that is sent.
import { AdapterError } from "@signeto/adapter-sdk";

const SCALE = 10_000n;

/** A price in ten-thousandths of a dollar, from the agent's string or number. Throws `resolve_failed` on anything else. */
export function parsePrice(x: unknown, what = "limit_price"): bigint {
  const s = typeof x === "number" ? (Number.isFinite(x) ? String(x) : "") : typeof x === "string" ? x.trim() : "";
  const m = /^([0-9]{1,7})(?:\.([0-9]{1,4}))?$/.exec(s);
  if (!m) throw new AdapterError("resolve_failed", `${what} must be a positive price below $10,000,000 with at most 4 decimals`);
  const whole = BigInt(m[1] as string);
  const frac = BigInt(((m[2] ?? "") + "0000").slice(0, 4));
  const v = whole * SCALE + frac;
  if (v <= 0n) throw new AdapterError("resolve_failed", `${what} must be above zero`);
  // Alpaca takes whole cents at $1 and above, up to 4 decimals below $1: an order Alpaca would refuse isn't signed.
  if (v >= SCALE && v % 100n !== 0n) throw new AdapterError("resolve_failed", `${what} at $1 or more takes at most 2 decimals (whole cents)`);
  return v;
}

/** A price as signed: 2 decimals, or up to 4 below $1 (trailing zeros past the second dropped). */
export function formatPrice(v: bigint): string {
  const whole = v / SCALE;
  let frac = (v % SCALE).toString().padStart(4, "0");
  while (frac.length > 2 && frac.endsWith("0")) frac = frac.slice(0, -1);
  return `${whole}.${frac}`;
}

/** qty × price in whole cents, half up. */
export function notionalCents(qty: number, price: bigint): bigint {
  return (BigInt(qty) * price + 50n) / 100n;
}

/**
 * Whole cents as the USD number that is signed (`notional_usd`): a number so policy can test it (`gt: 500`).
 * Dividing exact integers gives the double nearest the decimal, so it serialises as that decimal (1895.37, 1895.3, 1895).
 */
export function usd(cents: bigint): number {
  return Number(cents) / 100;
}

/** qty × price as the signed USD number. */
export function notional(qty: number, price: bigint): number {
  return usd(notionalCents(qty, price));
}

/** A signed USD number back to whole cents, for the execute-time drift check. */
export function centsOf(n: number): bigint {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) throw new AdapterError("precondition_failed", "the signed notional value is not an amount");
  return BigInt(Math.round(n * 100));
}
