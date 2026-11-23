import { describe, expect, it } from "vitest";
import { registryFromManifest, validateAdapter } from "@signeto/adapter-sdk";
import { alpacaRegistry, findTemplate, templateSha256 } from "@signeto/protocol";
import { alpacaAdapter, manifest } from "../src/index.js";
import { TERMS_PATTERN, termsOf } from "../src/manifest.js";

describe("manifest", () => {
  it("passes validateAdapter with no errors", () => {
    expect(validateAdapter(alpacaAdapter)).toEqual([]);
  });

  it("is a custody adapter that implements custody and not mint", () => {
    expect(manifest.mode).toBe("custody");
    expect(typeof alpacaAdapter.custody).toBe("function");
    expect(alpacaAdapter.mint).toBeUndefined();
  });

  it("only egresses to Alpaca's paper trading and market data hosts", () => {
    expect(manifest.egress).toEqual(["paper-api.alpaca.markets", "data.alpaca.markets"]);
    expect(manifest.egress).not.toContain("api.alpaca.markets");
  });

  it("declares the key pair as its secrets", () => {
    expect(manifest.secrets.map((s) => s.name).sort()).toEqual(["key_id", "secret_key"]);
  });

  it.each([
    ["alpaca.place_order", 3],
    ["alpaca.cancel_order", 2],
    ["alpaca.read_positions", 1],
    ["alpaca.read_orders", 1],
  ])("%s v%i matches the builtin protocol registry byte for byte", (id, version) => {
    const ours = findTemplate([registryFromManifest(manifest)], id, version);
    const builtin = findTemplate([alpacaRegistry], id, version);
    expect(builtin).toBeDefined();
    expect(ours).toEqual(builtin);
    expect(ours!.sha256).toBe(templateSha256(builtin!));
  });

  it("closes every input and resolved schema", () => {
    for (const t of manifest.tools) {
      expect(t.input.additionalProperties).toBe(false);
      expect(t.resolved.additionalProperties).toBe(false);
    }
  });

  it("shows every signed value of a write on its card: in the sentence, on the note line, or stated by terms", () => {
    // SIG-92 N9: nothing signed for a write may be hidden from the approver. v3 hides type, limit_price and
    // time_in_force only because `terms` says them in words, and execute refuses an order whose terms don't match.
    const byTerms = ["type", "limit_price", "time_in_force"];
    for (const name of ["place_order", "cancel_order"]) {
      const t = manifest.tools.find((x) => x.name === name)!;
      const tpl = t.template as { text: string; note?: string; elide?: string[] };
      expect(tpl.text).toContain("{terms}");
      for (const k of Object.keys((t.resolved as { properties: object }).properties)) {
        const shown = tpl.text.includes(`{${k}}`) || (tpl.note ?? "").includes(`{${k}}`) || byTerms.includes(k);
        expect(shown, `${name}.${k}`).toBe(true);
      }
      for (const k of tpl.elide ?? []) expect((tpl.note ?? "").includes(`{${k}}`) || byTerms.includes(k), `${name} elides ${k}`).toBe(true);
    }
  });

  it("terms say the order's type, limit price and time in force", () => {
    expect(termsOf("market", null, "day")).toBe("at market");
    expect(termsOf("market", null, "gtc")).toBe("at market, good till canceled");
    expect(termsOf("limit", "349.50", "day")).toBe("limit 349.50, today only");
    expect(termsOf("limit", "0.1234", "gtc")).toBe("limit 0.1234, good till canceled");
    const re = new RegExp(TERMS_PATTERN);
    for (const x of ["at market", "at market, good till canceled", "limit 349.50, today only", "limit 0.1234, good till canceled"]) expect(re.test(x)).toBe(true);
    for (const x of ["limit null", "at market ", "limit 349.5, today only", "limit 1e3"]) expect(re.test(x)).toBe(false);
  });
});
