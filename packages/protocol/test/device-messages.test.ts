import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import * as P from "../src/index.js";

const key = (t: "ed25519" | "es256"): P.PrivateJwk =>
  (t === "es256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("ed25519")).privateKey.export({ format: "jwk" }) as P.PrivateJwk;
const pub = (j: P.PrivateJwk): P.PublicJwk => {
  const { d: _d, ...rest } = j;
  return rest as P.PublicJwk;
};
const vector = JSON.parse(readFileSync(new URL("../vectors/gateway-revoke/ed25519.json", import.meta.url), "utf8")) as {
  inputs: { device_public_key: P.PublicJwk; device_id: string; gateway_id: string; signed_at: string };
  expected: { signing_input: string; body: P.GatewayRevokeObject };
};
const now = Date.parse("2026-11-14T12:00:00.000Z");
const GW = vector.inputs.gateway_id;

describe("gateway revocation by a device (§7.2)", () => {
  it("matches the vector: signing input, deterministic Ed25519 signature, verification", () => {
    const dev = JSON.parse(readFileSync(new URL("../vectors/keys/device-ed25519.json", import.meta.url), "utf8")) as P.PrivateJwk;
    expect(P.deviceIdFromJwk(vector.inputs.device_public_key)).toBe(vector.inputs.device_id);
    expect(P.gatewayRevokeSigningInput(vector.inputs)).toBe(vector.expected.signing_input);
    expect(P.signGatewayRevoke(vector.inputs, dev)).toEqual(vector.expected.body);
    expect(P.verifyGatewayRevoke(vector.expected.body, { gateway_id: GW, public_key: vector.inputs.device_public_key, now })).toEqual({ ok: true, signed_at_ms: now });
  });

  it("round-trips with ES256 and Ed25519 device keys", () => {
    for (const t of ["es256", "ed25519"] as const) {
      const k = key(t);
      const o = P.signGatewayRevoke({ gateway_id: GW, signed_at: P.formatTimestamp(now) }, k);
      expect(P.verifyGatewayRevoke(o, { gateway_id: GW, public_key: pub(k), now: now + 59_000 }).ok).toBe(true);
    }
  });

  it("refuses another key, another gateway, a stale or future signed_at, and malformed objects", () => {
    const k = key("es256");
    const o = P.signGatewayRevoke({ gateway_id: GW, signed_at: P.formatTimestamp(now) }, k);
    expect(P.verifyGatewayRevoke(o, { gateway_id: GW, public_key: pub(key("es256")), now })).toEqual({ ok: false, code: "signature_invalid" });
    const other = "gw_" + "A".repeat(43);
    expect(P.verifyGatewayRevoke(o, { gateway_id: other, public_key: pub(k), now })).toEqual({ ok: false, code: "request_malformed" });
    expect(P.verifyGatewayRevoke({ ...o, gateway_id: other }, { gateway_id: other, public_key: pub(k), now })).toEqual({ ok: false, code: "signature_invalid" });
    expect(P.verifyGatewayRevoke(o, { gateway_id: GW, public_key: pub(k), now: now + 60_001 })).toEqual({ ok: false, code: "clock_skew" });
    expect(P.verifyGatewayRevoke(o, { gateway_id: GW, public_key: pub(k), now: now - 60_001 })).toEqual({ ok: false, code: "clock_skew" });
    expect(P.verifyGatewayRevoke({ ...o, signed_at: "2026-11-14T12:00:00Z" }, { gateway_id: GW, public_key: pub(k), now })).toEqual({ ok: false, code: "request_malformed" });
    expect(P.verifyGatewayRevoke({ ...o, signature: "x" }, { gateway_id: GW, public_key: pub(k), now })).toEqual({ ok: false, code: "request_malformed" });
  });

  it("a freeze or receipt signature never verifies as a revocation (distinct members)", () => {
    const k = key("ed25519");
    const signed_at = P.formatTimestamp(now);
    const freezeSig = P.base64url.encode(P.signWithJwk(P.utf8.encode(P.canonicalize({ frozen: true, signed_at })), k).signature);
    expect(P.verifyGatewayRevoke({ gateway_id: GW, signed_at, signature: freezeSig }, { gateway_id: GW, public_key: pub(k), now })).toEqual({ ok: false, code: "signature_invalid" });
  });
});
