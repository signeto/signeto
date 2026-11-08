import { describe, expect, it } from "vitest";
import { renderTemplate, buildCanonicalAction, gatewayIdFromJwk, templateSha256 } from "@signeto/protocol";
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

describe("validateAdapter: notes and review links (protocol.md §3.5)", () => {
  const t = ok.manifest.tools[0]!;
  const withTemplate = (template: Record<string, unknown>): Adapter => ({ ...ok, manifest: { ...ok.manifest, tools: [{ ...t, template: { ...t.template, ...template } }] } });
  it("accepts a note with :short and links to an allowlisted host", () => {
    expect(validateAdapter(withTemplate({ note: "Ticket {id:short}", links: [{ label: "Open ticket", url: "https://tickets.example.com/t/{id}" }], link_hosts: ["tickets.example.com"] }))).toEqual([]);
  });
  it("refuses a link to a host outside link_hosts, http, and a placeholder in the host", () => {
    for (const [url, code] of [["https://evil.example/t/{id}", "host_not_allowed"], ["http://tickets.example.com/t/{id}", "url_not_https"], ["https://{id}.example.com/", "host_not_literal"]]) {
      const msgs = validateAdapter(withTemplate({ links: [{ label: "x", url }], link_hosts: ["tickets.example.com"] })).map((e) => e.message);
      expect(msgs).toContain(`template links are invalid (protocol.md §3.5): ${code}`);
    }
  });
  it("refuses more than 4 links and a link placeholder that is not a resolved property", () => {
    const five = [1, 2, 3, 4, 5].map((i) => ({ label: `l${i}`, url: `https://tickets.example.com/${i}` }));
    expect(validateAdapter(withTemplate({ links: five, link_hosts: ["tickets.example.com"] })).map((e) => e.message)).toContain("template links are invalid (protocol.md §3.5): too_many_links");
    expect(validateAdapter(withTemplate({ links: [{ label: "x", url: "https://tickets.example.com/{nope}" }], link_hosts: ["tickets.example.com"] })).map((e) => e.message)).toContain('template link "x" placeholder {nope} is not a resolved property');
  });
  it("refuses a note formatter other than :short, and a placeholder only the note mentions is still unreferenced", () => {
    expect(validateAdapter(withTemplate({ note: "{id:path}" })).map((e) => e.message)).toContain("template note has a stray brace, an invalid placeholder or a formatter other than :short");
    const resolved = { ...t.resolved, properties: { ...(t.resolved.properties as object), priority: { type: "string" } }, required: ["id", "title", "priority"] };
    const bad: Adapter = { ...ok, manifest: { ...ok.manifest, tools: [{ ...t, resolved, template: { ...t.template, note: "{priority}" } }] } };
    expect(validateAdapter(bad).map((e) => e.message)).toContain('resolved property "priority" is neither referenced by the template nor listed in elide');
  });
  it("registryFromManifest carries note, links and link_hosts, hashed together", () => {
    const reg = registryFromManifest(withTemplate({ note: "n", links: [{ label: "Open", url: "https://tickets.example.com/t/{id}" }], link_hosts: ["tickets.example.com"] }).manifest);
    const e = reg.templates[0]!;
    expect(e).toMatchObject({ note: "n", links: [{ label: "Open", url: "https://tickets.example.com/t/{id}" }], link_hosts: ["tickets.example.com"] });
    expect(e.sha256).toBe(templateSha256(e));
    expect(e.sha256).not.toBe(templateSha256(e.text));
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
