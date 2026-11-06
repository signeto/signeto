// docs/protocol.md §2.5. RFC 3339 UTC, exactly three fractional digits, Z designator.

export const TIMESTAMP_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/** Clock-skew tolerance for receipt signed_at and device-side checks. */
export const CLOCK_SKEW_MS = 60_000;
/** Default expires_at - issued_at. */
export const DEFAULT_EXPIRY_MS = 3 * 60_000;
/** Hard maximum expires_at - issued_at; longer policies are rejected at load. */
export const MAX_EXPIRY_MS = 5 * 60_000;

export function formatTimestamp(t: Date | number): string {
  const d = typeof t === "number" ? new Date(t) : t;
  if (Number.isNaN(d.getTime())) throw new Error("invalid date");
  return d.toISOString(); // always YYYY-MM-DDTHH:mm:ss.sssZ
}

/** Parse a protocol timestamp to epoch ms, or return undefined if it is not in the exact format. */
export function parseTimestamp(s: string): number | undefined {
  if (!TIMESTAMP_RE.test(s)) return undefined;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return undefined;
  // Round-trip guard: rejects 2026-13-45T... which Date.parse may normalise.
  if (new Date(ms).toISOString() !== s) return undefined;
  return ms;
}
