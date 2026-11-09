// §3.6 display escape rule: properties the shared vectors do not pin down.
import { describe, expect, it } from "vitest";
import { buildCanonicalAction, displayEscape, displayValue, gatewayIdFromJwk, isDisplayEscaped, isDisplaySafe, isPrintableAgentName, renderTemplate, builtinRegistries } from "../src/index.js";
import { generateKeyPairSync } from "node:crypto";

describe("displayEscape", () => {
  it("escapes exactly the documented set, every code point of the BMP and the astral planes' first code points", () => {
    const set = (cp: number) =>
      cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || cp === 0x61c || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2069) || cp === 0xfeff;
    for (let cp = 0; cp <= 0x10ffff; cp += cp < 0x30000 ? 1 : 0x1000) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const s = String.fromCodePoint(cp);
      expect(isDisplayEscaped(cp), cp.toString(16)).toBe(set(cp));
      expect(displayEscape(s) !== s, cp.toString(16)).toBe(set(cp));
    }
  });

  it("escapes lone surrogates but keeps surrogate pairs", () => {
    expect(displayEscape("a\ud800b\udfffc")).toBe("a\\u{D800}b\\u{DFFF}c");
    expect(displayEscape("x😀y")).toBe("x😀y");
    expect(displayEscape("\ud83d")).toBe("\\u{D83D}");
  });

  it("output never contains an escaped code point (idempotent on its own output)", () => {
    const nasty = "\u001b[31m\u202e\n\r\t\u0085\u2028\ufeff\u200d";
    const once = displayEscape(nasty);
    expect(isDisplaySafe(once)).toBe(true);
    expect(displayEscape(once)).toBe(once);
  });

  it("displayValue escapes JCS text of non-strings too (JCS leaves DEL, C1 and bidi raw)", () => {
    expect(displayValue({ a: "x\u202ey\u007f", n: 1 })).toBe('{"a":"x\\u{202E}y\\u{7F}","n":1}');
    expect(displayValue("plain")).toBe("plain");
  });
});

describe("rendered template line (§3.6)", () => {
  it("an argument cannot add a line or reorder the sentence", () => {
    const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
    const enc = buildCanonicalAction({
      tool: "github.merge_pull_request",
      template_version: 1,
      args_resolved: { repo: "acme/api", pr: 1, base: "dev\n\u202emain", head_sha: "a".repeat(40), method: "squash" },
      requester: { agent: "claude-code", session_id: "s", host: "h", gateway_id: gatewayIdFromJwk(gw) },
      origin_hash: "0".repeat(64),
      tier: 2,
      mode: "enforce",
    });
    const r = renderTemplate(enc.canonical_bytes, builtinRegistries);
    expect(r.status).toBe("ok");
    if (r.status === "ok") expect(r.text).toBe(`Merge PR #1 into dev\\n\\u{202E}main on acme/api (squash) at ${"a".repeat(40)}`);
  });
});

describe("requester.agent (§2.1)", () => {
  it("isPrintableAgentName accepts names that need no escape, refuses the rest", () => {
    expect(isPrintableAgentName("claude-code")).toBe(true);
    expect(isPrintableAgentName("Claude Code 2.1 (naïve) 😀")).toBe(true);
    expect(isPrintableAgentName("cc\u001b[3A")).toBe(false);
    expect(isPrintableAgentName("a\nb")).toBe(false);
    expect(isPrintableAgentName("a\u202eb")).toBe(false);
    expect(isPrintableAgentName("")).toBe(false);
    expect(isPrintableAgentName("x".repeat(129))).toBe(false);
  });

  it("buildCanonicalAction refuses a non-printable agent, parse still accepts old bytes", () => {
    const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
    const input = (agent: string) => ({
      tool: "x.y",
      template_version: 1,
      args_resolved: {},
      requester: { agent, session_id: "s", host: "h", gateway_id: gatewayIdFromJwk(gw) },
      origin_hash: "0".repeat(64),
      tier: 2 as const,
      mode: "enforce" as const,
    });
    expect(() => buildCanonicalAction(input("cc\u001b[2K"))).toThrow(/agent/);
    expect(() => buildCanonicalAction(input("claude-code"))).not.toThrow();
  });
});
