// SIG-185: github.dispatch_workflow v4, the sentence without "with inputs {}" for a run with no inputs. The inputs are
// never elided: a v4 request that carries any `inputs` (even `{}`) has an argument the sentence does not mention, so it
// renders "unverified template" (§3.4) instead of hiding them. v3 is unchanged, so older receipts still verify.
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildCanonicalAction, builtinRegistries, findTemplate, gatewayIdFromJwk, renderTemplate } from "../src/index.js";

const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
const SHA = "c622de2" + "0".repeat(33);
const render = (template_version: number, args: Record<string, unknown>) =>
  renderTemplate(
    buildCanonicalAction({
      tool: "github.dispatch_workflow",
      template_version,
      args_resolved: args,
      requester: { agent: "claude-code", session_id: "s", host: "h", gateway_id: gatewayIdFromJwk(gw) },
      origin_hash: "0".repeat(64),
      tier: 3,
      mode: "enforce",
    }).canonical_bytes,
    builtinRegistries,
  );
const base = { repo: "signeto/deploy-to-prod-example", workflow: "deploy.yml", ref: "main", ref_sha: SHA };

describe("github.dispatch_workflow v4 (SIG-185)", () => {
  it("is bundled next to v3, with the same review links and no elide", () => {
    const v3 = findTemplate(builtinRegistries, "github.dispatch_workflow", 3)!;
    const v4 = findTemplate(builtinRegistries, "github.dispatch_workflow", 4)!;
    expect(v4.text).toBe("Run {workflow} on {ref} ({ref_sha}) in {repo}");
    expect(v4.elide).toBeUndefined();
    expect([v4.links, v4.link_hosts]).toEqual([v3.links, v3.link_hosts]);
    expect(v4.sha256).toBe("d04c5744e1e526632f696316ce57f96fb7e33bee8a4c7802b501dbf1e7e75261");
  });

  it("renders a run with no inputs without the {} tail", () => {
    const r = render(4, base);
    expect(r.status).toBe("ok");
    if (r.status === "ok") {
      expect(r.text).toBe(`Run deploy.yml on main (${SHA}) in signeto/deploy-to-prod-example`);
      expect(r.hidden).toEqual([]);
      expect(r.links.map((l) => l.label)).toEqual(["Workflow file at approved commit", "Actions"]);
    }
  });

  it("can't hide inputs: v4 with inputs, even empty, is an unverified template", () => {
    for (const inputs of [{ environment: "production" }, {}]) {
      const r = render(4, { ...base, inputs });
      expect(r.status).toBe("unverified");
      if (r.status === "unverified") expect([r.reason, r.detail]).toEqual(["unreferenced_key", inputs && Object.keys(inputs).length ? "inputs.environment" : "inputs"]);
    }
  });

  it("v3 still renders as before (older receipts verify)", () => {
    const r = render(3, { ...base, inputs: {} });
    expect(r.status).toBe("ok");
    if (r.status === "ok") expect(r.text).toBe(`Run deploy.yml on main (${SHA}) in signeto/deploy-to-prod-example with inputs {}`);
  });
});
