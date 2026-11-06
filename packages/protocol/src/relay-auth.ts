// docs/protocol.md §7.1: request authentication to a relay with the gateway or device key.
//
//   Authorization: Signeto-Gateway <gateway_id>.<ts>.<sig>
//   Authorization: Signeto-Device  <device_id>.<ts>.<sig>
//
// `sig` is base64url (no padding) of the key's signature over the UTF-8 JCS of
// `{body_sha256, method, path, ts}`:
//   - `method`: the HTTP method in upper case.
//   - `path`: the request-target exactly as sent on the request line (origin-form): absolute path,
//     plus `?` and the query string when present, percent-encoding untouched; no scheme, host or
//     fragment.
//   - `ts`: §2.5 timestamp (RFC 3339 UTC, three fractional digits, `Z`). Accepted within ±60 s.
//   - `body_sha256`: lowercase hex SHA-256 of the exact request body bytes as sent, or of the empty
//     string when there is no body.
// `ts` itself contains a `.`, so a header is split at its first and last `.`; neither ids nor
// base64url contain one.
import { canonicalize } from "./jcs.js";
import { base64url, sha256hex, utf8 } from "./encoding.js";
import { DEVICE_ID_RE, GATEWAY_ID_RE, deviceIdFromJwk, gatewayIdFromJwk, type PrivateJwk, type PublicJwk } from "./ids.js";
import { signWithJwk, verifyWithJwk } from "./signing.js";
import { CLOCK_SKEW_MS, formatTimestamp, parseTimestamp } from "./timestamps.js";

export type RelayAuthScheme = "Signeto-Gateway" | "Signeto-Device";
export const RELAY_AUTH_SCHEMES: readonly RelayAuthScheme[] = ["Signeto-Gateway", "Signeto-Device"];

/** Tolerance between `ts` and the relay's clock, either direction, inclusive. */
export const RELAY_AUTH_WINDOW_MS = CLOCK_SKEW_MS;
/** How long a relay remembers `(key_id, sig)` to refuse replays; at least twice the window. */
export const RELAY_AUTH_REPLAY_TTL_MS = 2 * RELAY_AUTH_WINDOW_MS;

/** SHA-256 of the empty string: `body_sha256` for a request without a body. */
export const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const METHOD_RE = /^[A-Z]+$/;
// origin-form request-target: starts with "/", no whitespace, no fragment.
const PATH_RE = /^\/[^\s#]*$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;

export interface RelayAuthFields {
  method: string;
  path: string;
  ts: string;
  body_sha256: string;
}

/** Hex SHA-256 of the raw body; `undefined`, `null` and an empty body all hash the empty string. */
export function relayBodySha256(body?: string | Uint8Array | null): string {
  if (body === undefined || body === null) return EMPTY_BODY_SHA256;
  return sha256hex(typeof body === "string" ? utf8.encode(body) : body);
}

/** The signing input: JCS of `{body_sha256, method, path, ts}`. Throws on a malformed field. */
export function relayAuthSigningInput(f: RelayAuthFields): string {
  if (!METHOD_RE.test(f.method)) throw new RangeError("method must be an upper-case HTTP method");
  if (!PATH_RE.test(f.path)) throw new RangeError("path must be the origin-form request-target (starts with '/', no host, no fragment)");
  if (parseTimestamp(f.ts) === undefined) throw new RangeError("ts must be an RFC 3339 UTC timestamp with three fractional digits");
  if (!/^[0-9a-f]{64}$/.test(f.body_sha256)) throw new RangeError("body_sha256 must be lowercase hex SHA-256");
  return canonicalize({ body_sha256: f.body_sha256, method: f.method, path: f.path, ts: f.ts });
}

export function keyIdForScheme(scheme: RelayAuthScheme, jwk: PublicJwk | PrivateJwk): string {
  return scheme === "Signeto-Gateway" ? gatewayIdFromJwk(jwk) : deviceIdFromJwk(jwk);
}

export interface SignRelayRequestInput {
  scheme: RelayAuthScheme;
  method: string;
  path: string;
  /** Raw body bytes exactly as they will be sent. Omit for no body. */
  body?: string | Uint8Array | null;
  /** §2.5 timestamp. Default: `formatTimestamp(now ?? Date.now())`. */
  ts?: string;
  now?: number;
}

/** Build the `Authorization` header value for one request. */
export function signRelayRequest(input: SignRelayRequestInput, privateJwk: PrivateJwk): string {
  const ts = input.ts ?? formatTimestamp(input.now ?? Date.now());
  const si = relayAuthSigningInput({ method: input.method, path: input.path, ts, body_sha256: relayBodySha256(input.body) });
  const { signature } = signWithJwk(utf8.encode(si), privateJwk);
  return `${input.scheme} ${keyIdForScheme(input.scheme, privateJwk)}.${ts}.${base64url.encode(signature)}`;
}

export interface ParsedRelayAuth {
  scheme: RelayAuthScheme;
  key_id: string;
  ts: string;
  signature: string;
}

export type ParseRelayAuthResult = ({ ok: true } & ParsedRelayAuth) | { ok: false; code: "auth_malformed"; detail: string };

/**
 * Parse an `Authorization` header value. The scheme name is matched case-insensitively (RFC 9110
 * §11.1) and returned in its canonical spelling; everything after it is case-sensitive.
 */
export function parseRelayAuthHeader(value: string | undefined | null): ParseRelayAuthResult {
  const bad = (detail: string): ParseRelayAuthResult => ({ ok: false, code: "auth_malformed", detail });
  if (typeof value !== "string") return bad("missing header");
  const m = /^([A-Za-z-]+) +([^\s]+)$/.exec(value);
  if (!m) return bad("expected '<scheme> <key_id>.<ts>.<sig>'");
  const scheme = RELAY_AUTH_SCHEMES.find((s) => s.toLowerCase() === (m[1] as string).toLowerCase());
  if (!scheme) return bad("unknown scheme");
  const cred = m[2] as string;
  const first = cred.indexOf(".");
  const last = cred.lastIndexOf(".");
  if (first <= 0 || last === first) return bad("expected '<key_id>.<ts>.<sig>'");
  const key_id = cred.slice(0, first);
  const ts = cred.slice(first + 1, last);
  const signature = cred.slice(last + 1);
  const idRe = scheme === "Signeto-Gateway" ? GATEWAY_ID_RE : DEVICE_ID_RE;
  if (!idRe.test(key_id)) return bad(scheme === "Signeto-Gateway" ? "key id is not a gateway_id" : "key id is not a device_id");
  if (parseTimestamp(ts) === undefined) return bad("ts is not an RFC 3339 UTC timestamp with three fractional digits");
  if (!SIG_RE.test(signature)) return bad("signature is not 64 bytes of base64url");
  return { ok: true, scheme, key_id, ts, signature };
}

export type RelayAuthErrorCode = "auth_malformed" | "scheme_not_allowed" | "key_mismatch" | "clock_skew" | "invalid_signature";

export interface VerifyRelayRequestInput {
  /** The `Authorization` header value as received. */
  header: string | undefined | null;
  method: string;
  /** Request-target exactly as received on the request line. */
  path: string;
  /** Raw body bytes exactly as received; omit or `null` for none. */
  body?: string | Uint8Array | null;
  /** The registered public key for the header's key id. */
  public_key: PublicJwk;
  /** Epoch ms; default `Date.now()`. */
  now?: number;
  window_ms?: number;
  /** Schemes the caller accepts for this request. Default both. */
  schemes?: readonly RelayAuthScheme[];
}

export type VerifyRelayRequestResult = ({ ok: true } & ParsedRelayAuth) | { ok: false; code: RelayAuthErrorCode; detail?: string };

/**
 * Relay side. Checks, in order: header shape, scheme, that the key id is the thumbprint of
 * `public_key`, the ±60 s window, then the signature. Replay detection (`(key_id, sig)` within
 * `RELAY_AUTH_REPLAY_TTL_MS`) is the relay's job: it needs state.
 */
export function verifyRelayRequest(input: VerifyRelayRequestInput): VerifyRelayRequestResult {
  const p = parseRelayAuthHeader(input.header);
  if (!p.ok) return p;
  if (input.schemes && !input.schemes.includes(p.scheme)) return { ok: false, code: "scheme_not_allowed" };
  let expectedId: string;
  try {
    expectedId = keyIdForScheme(p.scheme, input.public_key);
  } catch {
    return { ok: false, code: "key_mismatch", detail: "public key type unsupported" };
  }
  if (expectedId !== p.key_id) return { ok: false, code: "key_mismatch" };
  const ts = parseTimestamp(p.ts) as number;
  const now = input.now ?? Date.now();
  if (Math.abs(now - ts) > (input.window_ms ?? RELAY_AUTH_WINDOW_MS)) return { ok: false, code: "clock_skew" };
  let si: string;
  try {
    si = relayAuthSigningInput({ method: input.method, path: input.path, ts: p.ts, body_sha256: relayBodySha256(input.body) });
  } catch (e) {
    return { ok: false, code: "auth_malformed", detail: e instanceof Error ? e.message : String(e) };
  }
  let good = false;
  try {
    good = verifyWithJwk(utf8.encode(si), base64url.decode(p.signature), input.public_key);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, code: "invalid_signature" };
  return { ok: true, scheme: p.scheme, key_id: p.key_id, ts: p.ts, signature: p.signature };
}
