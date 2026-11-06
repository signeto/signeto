import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as P from "../src/index.js";

const key = (t: "ed25519" | "es256"): P.PrivateJwk =>
  (t === "es256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("ed25519")).privateKey.export({ format: "jwk" }) as P.PrivateJwk;
const pub = (j: P.PrivateJwk): P.PublicJwk => {
  const { d: _d, ...rest } = j;
  return rest as P.PublicJwk;
};
const now = Date.parse("2026-11-05T18:04:10.000Z");

describe("relay auth (§7.1)", () => {
  it("round-trips for both algorithms and both schemes, with and without a body", () => {
    for (const t of ["ed25519", "es256"] as const) {
      const k = key(t);
      for (const scheme of P.RELAY_AUTH_SCHEMES) {
        for (const body of [undefined, "", '{"a":1}', new Uint8Array([0xff, 0x00, 0x7b])]) {
          const header = P.signRelayRequest({ scheme, method: "POST", path: "/v1/x?y=1", body, now }, k);
          const r = P.verifyRelayRequest({ header, method: "POST", path: "/v1/x?y=1", body, public_key: pub(k), now });
          expect(r).toMatchObject({ ok: true, scheme, key_id: P.keyIdForScheme(scheme, k), ts: P.formatTimestamp(now) });
        }
      }
    }
  });

  it("an empty body and no body hash the same", () => {
    expect(P.relayBodySha256("")).toBe(P.EMPTY_BODY_SHA256);
    expect(P.relayBodySha256(null)).toBe(P.EMPTY_BODY_SHA256);
    expect(P.relayBodySha256(new Uint8Array(0))).toBe(P.EMPTY_BODY_SHA256);
    expect(P.sha256hex("")).toBe(P.EMPTY_BODY_SHA256);
  });

  it("hashes the exact bytes, so re-serialised JSON does not verify", () => {
    const k = key("ed25519");
    const body = '{ "b": 1, "a": 2 }';
    const header = P.signRelayRequest({ scheme: "Signeto-Gateway", method: "POST", path: "/v1/p", body, now }, k);
    const reserialised = JSON.stringify(JSON.parse(body));
    expect(P.verifyRelayRequest({ header, method: "POST", path: "/v1/p", body: reserialised, public_key: pub(k), now })).toMatchObject({ ok: false, code: "invalid_signature" });
  });

  it("parses the header at the first and last dot (ts contains one)", () => {
    const k = key("ed25519");
    const header = P.signRelayRequest({ scheme: "Signeto-Device", method: "GET", path: "/v1/approvals", now }, k);
    const p = P.parseRelayAuthHeader(header);
    expect(p).toMatchObject({ ok: true, scheme: "Signeto-Device", key_id: P.deviceIdFromJwk(k), ts: "2026-11-05T18:04:10.000Z" });
    // Scheme name is case-insensitive; the rest is not.
    expect(P.parseRelayAuthHeader(header.replace("Signeto-Device", "signeto-device"))).toMatchObject({ ok: true, scheme: "Signeto-Device" });
  });

  it("rejects malformed headers", () => {
    const k = key("ed25519");
    const good = P.signRelayRequest({ scheme: "Signeto-Gateway", method: "GET", path: "/v1/a", now }, k);
    const id = P.gatewayIdFromJwk(k);
    const [, cred] = good.split(" ") as [string, string];
    const sig = cred.slice(cred.lastIndexOf(".") + 1);
    for (const h of [
      undefined,
      "",
      "Bearer abc",
      `Signeto-Gateway ${id}`,
      `Signeto-Gateway ${id}.2026-11-05T18:04:10Z.${sig}`, // ts without millis
      `Signeto-Gateway ${id}.2026-11-05T18:04:10.000Z.${sig.slice(1)}`, // short signature
      `Signeto-Gateway ${id}.2026-11-05T18:04:10.000Z.${sig}=`, // padding
      `Signeto-Device ${id}.2026-11-05T18:04:10.000Z.${sig}`, // gw_ id under the device scheme
      `Signeto-Other ${id}.2026-11-05T18:04:10.000Z.${sig}`,
    ]) {
      expect(P.parseRelayAuthHeader(h)).toMatchObject({ ok: false, code: "auth_malformed" });
    }
  });

  it("enforces the window inclusively at ±60 s", () => {
    const k = key("es256");
    const header = P.signRelayRequest({ scheme: "Signeto-Gateway", method: "GET", path: "/v1/a", now }, k);
    const v = (n: number) => P.verifyRelayRequest({ header, method: "GET", path: "/v1/a", public_key: pub(k), now: n });
    expect(v(now + 60_000).ok).toBe(true);
    expect(v(now - 60_000).ok).toBe(true);
    expect(v(now + 60_001)).toMatchObject({ ok: false, code: "clock_skew" });
    expect(v(now - 60_001)).toMatchObject({ ok: false, code: "clock_skew" });
  });

  it("restricts schemes when asked", () => {
    const k = key("ed25519");
    const header = P.signRelayRequest({ scheme: "Signeto-Device", method: "GET", path: "/v1/a", now }, k);
    expect(P.verifyRelayRequest({ header, method: "GET", path: "/v1/a", public_key: pub(k), now, schemes: ["Signeto-Gateway"] })).toMatchObject({ ok: false, code: "scheme_not_allowed" });
  });

  it("refuses to sign a malformed request", () => {
    const k = key("ed25519");
    expect(() => P.signRelayRequest({ scheme: "Signeto-Gateway", method: "get", path: "/v1/a", now }, k)).toThrow(/method/);
    expect(() => P.signRelayRequest({ scheme: "Signeto-Gateway", method: "GET", path: "https://relay/v1/a", now }, k)).toThrow(/path/);
    expect(() => P.signRelayRequest({ scheme: "Signeto-Gateway", method: "GET", path: "/v1/a#frag", now }, k)).toThrow(/path/);
  });
});
