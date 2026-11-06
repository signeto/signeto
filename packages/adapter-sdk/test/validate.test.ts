import { describe, expect, it } from "vitest";
import { renderTemplate, buildCanonicalAction, gatewayIdFromJwk } from "@signeto/protocol";
import { generateKeyPairSync } from "node:crypto";
import { AdapterError, registryFromManifest, validateAdapter, type Adapter } from "../src/index.js";

const ok: Adapter = {
  manifest: {
    name: "demo", version: "0.1.0", mode: "mint", egress: ["api.example.com"], secrets: [],
    tools: [
      { name: "close_ticket", description: "Close a ticket", effect: "write", classification: "internal",
        input: { type: "object", additionalProperties: false, required: ["id"], properties: { id: { type: "string" } } },
        resolved: { type: "object", additionalProperties: false, required: ["id", "title"], properties: { id: { type: "string" }, title: { type: "string" } } },
        template: { id: "demo.close_ticket", version: 1, text: "Close ticket {id}: {title}" } },
    ],
  },
  async resolve(_c, _t, a) { return { args: { id: (a as { id: string }).id, title: "Login page 500s" } }; },
  async mint() { return { material: "t", expiresAt: new Date(Date.now() + 60_000), scope: "tickets:write" }; },
  async execute() { return { content: "closed", evidence: {} }; },
};

describe("validateAdapter", () => {
  it("accepts a well-formed mint adapter", () => expect(validateAdapter(ok)).toEqual([]));
  it("rejects a mint adapter that also implements custody", () => {
    const bad = { ...ok, custody: ok.mint } as Adapter;
    expect(validateAdapter(bad).map((e) => e.message)).toContain("mint adapter must implement mint and not custody");
  });
  it("rejects an open input schema and a template id that does not match the tool", () => {
    const t = ok.manifest.tools[0]!;
    const bad: Adapter = { ...ok, manifest: { ...ok.manifest, tools: [{ ...t, input: { type: "object" }, template: { ...t.template, id: "other.id" } }] } };
    const msgs = validateAdapter(bad).map((e) => e.message);
    expect(msgs).toContain("input schema must set additionalProperties: false");
    expect(msgs.some((m) => m.startsWith("template id must equal"))).toBe(true);
  });
  it("rejects a resolved property the template neither shows nor elides", () => {
    const t = ok.manifest.tools[0]!;
    const resolved = { ...t.resolved, properties: { ...(t.resolved.properties as object), priority: { type: "string" } } };
    const bad: Adapter = { ...ok, manifest: { ...ok.manifest, tools: [{ ...t, resolved }] } };
    expect(validateAdapter(bad).map((e) => e.message)).toContain('resolved property "priority" is neither referenced by the template nor listed in elide');
  });
});

describe("registryFromManifest", () => {
  it("renders the same line every approver will show", () => {
    const gw = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" }) as never;
    const enc = buildCanonicalAction({
      tool: "demo.close_ticket", template_version: 1, args_resolved: { id: "T-42", title: "Login page 500s" },
      requester: { agent: "claude-code", session_id: "s1", host: "h", gateway_id: gatewayIdFromJwk(gw) },
      origin_hash: "0".repeat(64), tier: 2, mode: "enforce",
    });
    const r = renderTemplate(enc.canonical_bytes, [registryFromManifest(ok.manifest)]);
    expect(r).toMatchObject({ status: "ok", text: "Close ticket T-42: Login page 500s" });
  });
});

describe("AdapterError", () => {
  it("carries a code and retryable flag", () => {
    const e = new AdapterError("upstream_unreachable", "down", true);
    expect([e.code, e.retryable, e.name]).toEqual(["upstream_unreachable", true, "AdapterError"]);
  });
});
