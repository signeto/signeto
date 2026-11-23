import { describe, expect, it } from "vitest";
import { registryFromManifest, validateAdapter } from "@signeto/adapter-sdk";
import { alpacaRegistry, findTemplate, templateSha256 } from "@signeto/protocol";
import { alpacaAdapter, manifest } from "../src/index.js";

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
    ["alpaca.place_order", 2],
    ["alpaca.cancel_order", 1],
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

  it("shows every signed value of a write on its card (no elided arg)", () => {
    for (const name of ["place_order", "cancel_order"]) {
      const t = manifest.tools.find((x) => x.name === name)!;
      expect((t.template as { elide?: string[] }).elide ?? []).toEqual([]);
      for (const k of Object.keys((t.resolved as { properties: object }).properties)) expect(t.template.text).toContain(`{${k}}`);
    }
  });
});
