import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import {
  buildCanonicalAction,
  canonicalize,
  JcsError,
  deviceIdFromJwk,
  formatTimestamp,
  gatewayIdFromJwk,
  isCanonical,
  newNonce,
  parseTimestamp,
  signReceipt,
  ulid,
  verifyReceipt,
} from "../src/index.js";

describe("JCS (RFC 8785)", () => {
  it("matches the RFC 8785 section 3.2.3 sample", () => {
    // Input string: euro, $, U+000F, LF, A, ', B, ", \, \, ", /
    const sample = "€$" + "\u000f" + "\n" + "A'B" + '"' + "\\\\" + '"' + "/";
    const input = {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
      string: sample,
      literals: [null, true, false],
    };
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
    expect(canonicalize(input)).toBe(expected);
  });
  it("sorts keys by UTF-16 code units", () => {
    const out = canonicalize({ "\u{1F600}": 1, "ﬁ": 2, a: 3, A: 4, "é": 5 });
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FB01 by UTF-16 code units.
    expect(out).toBe('{"A":4,"a":3,"é":5,"\u{1F600}":1,"ﬁ":2}');
  });
  it("drops undefined members and rejects non-finite numbers", () => {
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(() => canonicalize({ a: NaN })).toThrow();
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(1e21)).toBe("1e+21");
  });
  it("isCanonical", () => {
    expect(isCanonical('{"a":1,"b":[1,2]}')).toBe(true);
    expect(isCanonical('{"b":[1,2],"a":1}')).toBe(false);
    expect(isCanonical('{"a": 1}')).toBe(false);
    expect(isCanonical("not json")).toBe(false);
  });
});

describe("ids and timestamps", () => {
  it("nonce is 22 base64url chars", () => expect(newNonce()).toMatch(/^[A-Za-z0-9_-]{22}$/));
  it("ulid is 26 crockford chars and time-ordered", () => {
    const a = ulid(1_000_000);
    const b = ulid(2_000_000);
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(a < b).toBe(true);
  });
  it("timestamps round-trip in the fixed format", () => {
    const s = formatTimestamp(1_762_365_849_123);
    expect(s).toBe("2025-11-05T18:04:09.123Z");
    expect(parseTimestamp(s)).toBe(1_762_365_849_123);
    expect(parseTimestamp("2025-11-05T18:04:09Z")).toBeUndefined();
    expect(parseTimestamp("2025-13-05T18:04:09.123Z")).toBeUndefined();
  });
});

describe("end to end: build, sign, verify", () => {
  const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as any;
  const dev = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }) as any;
  const requester = { agent: "claude-code", session_id: "s1", host: "h", gateway_id: gatewayIdFromJwk(gw) };
  it("ES256 approve verifies; expiry over 5 minutes is refused at build", () => {
    const now = Date.parse("2026-11-05T18:04:09.123Z");
    const enc = buildCanonicalAction(
      { tool: "github.merge_pull_request", template_version: 1, args_resolved: { pr: 1 }, requester, origin_hash: "0".repeat(64), tier: 3, mode: "enforce" },
      { now },
    );
    expect(enc.action.expires_at).toBe("2026-11-05T18:07:09.123Z");
    const receipt = signReceipt(
      {
        action_id: "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C",
        canonical_bytes_sha256: enc.canonical_bytes_sha256,
        decision: "approve",
        approver_id: "jason",
        device_id: deviceIdFromJwk(dev),
        signed_at: formatTimestamp(now + 30_000),
      },
      dev,
    );
    expect(receipt.alg).toBe("ES256");
    const { d: _d, ...pub } = dev;
    expect(
      verifyReceipt({ receipt, canonical_bytes: enc.canonical_bytes, issued_at: enc.action.issued_at, expires_at: enc.action.expires_at, device_public_key: pub }),
    ).toMatchObject({ ok: true });
    expect(() =>
      buildCanonicalAction(
        { tool: "a.b", template_version: 1, args_resolved: {}, requester, origin_hash: "0".repeat(64), tier: 1, mode: "enforce", expiry_ms: 6 * 60_000 },
        { now },
      ),
    ).toThrow(RangeError);
  });
});

describe("lone surrogates (RFC 8785, SIG-109)", () => {
  it("rejects a lone high or low surrogate in a value or a key, accepts a proper pair", () => {
    expect(() => canonicalize({ a: "x\uD800" })).toThrow(JcsError);
    expect(() => canonicalize({ a: "\uDC00y" })).toThrow(JcsError);
    expect(() => canonicalize({ ["k\uD83D"]: 1 })).toThrow(JcsError);
    expect(canonicalize({ a: "😀" })).toBe('{"a":"😀"}');
  });
});
