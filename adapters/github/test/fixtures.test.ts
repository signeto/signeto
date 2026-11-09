// (agentArgs, upstreamState) → resolved args + rendered template, rendered with the same protocol code every approver uses.
import { describe, expect, it } from "vitest";
import { renderTemplate } from "@signeto/protocol";
import { registryFromManifest } from "@signeto/adapter-sdk";
import { githubAdapter, manifest } from "../src/index.js";
import { HEAD_SHA, REF_SHA, canonicalFor, pullRequest, readOnlyClient, resolveCtx, workflow, type Route } from "./helpers.js";

interface Fixture {
  name: string;
  tool: string;
  agentArgs: Record<string, unknown>;
  upstreamState: Route[];
  resolved: Record<string, unknown>;
  rendered: string;
  hidden?: string[];
  /** The note line, when the template has one. */
  note?: string;
  /** Review links built from the resolved args (protocol.md §3.5). */
  links: { label: string; url: string }[];
}

const prLinks = (repo: string, pr: number) => [
  { label: "View pull request", url: `https://github.com/${repo}/pull/${pr}` },
  { label: "Files changed", url: `https://github.com/${repo}/pull/${pr}/files` },
  { label: "Code at approved commit", url: `https://github.com/${repo}/tree/${HEAD_SHA}` },
];
const mergeNote = `Approving commit ${HEAD_SHA.slice(0, 7)}. If the PR changes, this approval will not merge it.`;
const dispatchLinks = (repo: string, file: string) => [
  { label: "Workflow file at approved commit", url: `https://github.com/${repo}/blob/${REF_SHA}/.github/workflows/${file}` },
  { label: "Actions", url: `https://github.com/${repo}/actions` },
];

const fixtures: Fixture[] = [
  {
    name: "merge with default method",
    tool: "merge_pull_request",
    agentArgs: { repo: "acme/api", pr: 42 },
    upstreamState: [{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest() }],
    resolved: { repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" },
    rendered: `Merge PR #42 into main on acme/api (squash) at ${HEAD_SHA}`,
    note: mergeNote,
    links: prLinks("acme/api", 42),
  },
  {
    name: "merge with mixed-case input and explicit rebase",
    tool: "merge_pull_request",
    agentArgs: { repo: "Acme/API", pr: 42, method: "REBASE" },
    upstreamState: [{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest({ base: { ref: "release/2026.11", repo: { full_name: "Acme/API" } } }) }],
    resolved: { repo: "acme/api", pr: 42, base: "release/2026.11", head_sha: HEAD_SHA, method: "rebase" },
    rendered: `Merge PR #42 into release/2026.11 on acme/api (rebase) at ${HEAD_SHA}`,
    note: mergeNote,
    links: prLinks("acme/api", 42),
  },
  {
    name: "dispatch by file name with inputs (inputs in the sentence, template v3)",
    tool: "dispatch_workflow",
    agentArgs: { repo: "acme/api", workflow: "deploy.yml", ref: "main", inputs: { environment: "production", dry_run: "false" } },
    upstreamState: [
      { method: "GET", path: "/repos/acme/api/actions/workflows/deploy.yml", body: workflow() },
      { method: "GET", path: "/repos/acme/api/commits/main", body: { sha: REF_SHA } },
    ],
    resolved: { repo: "acme/api", workflow: "deploy.yml", ref: "main", ref_sha: REF_SHA, inputs: { dry_run: "false", environment: "production" } },
    rendered: `Run deploy.yml on main (${REF_SHA}) in acme/api with inputs {"dry_run":"false","environment":"production"}`,
    links: dispatchLinks("acme/api", "deploy.yml"),
  },
  {
    name: "dispatch by numeric workflow id on a tag",
    tool: "dispatch_workflow",
    agentArgs: { repo: "acme/api", workflow: "161335", ref: "v1.2.0" },
    upstreamState: [
      { method: "GET", path: "/repos/acme/api/actions/workflows/161335", body: workflow() },
      { method: "GET", path: "/repos/acme/api/commits/v1.2.0", body: { sha: REF_SHA } },
    ],
    resolved: { repo: "acme/api", workflow: "deploy.yml", ref: "v1.2.0", ref_sha: REF_SHA, inputs: {} },
    rendered: `Run deploy.yml on v1.2.0 (${REF_SHA}) in acme/api with inputs {}`,
    links: dispatchLinks("acme/api", "deploy.yml"),
  },
  {
    name: "read a closed PR",
    tool: "read_pull_request",
    agentArgs: { repo: "ACME/api", pr: 7 },
    upstreamState: [{ method: "GET", path: "/repos/acme/api/pulls/7", body: pullRequest({ number: 7, state: "closed" }) }],
    resolved: { repo: "acme/api", pr: 7 },
    rendered: "Read PR #7 on acme/api",
    links: [{ label: "View pull request", url: "https://github.com/acme/api/pull/7" }],
  },
];

const registries = [registryFromManifest(manifest)];

describe("fixtures: (agentArgs, upstreamState) → resolved args → rendered template", () => {
  for (const f of fixtures) {
    it(f.name, async () => {
      const { client } = readOnlyClient(f.upstreamState);
      const r = await githubAdapter.resolve(resolveCtx(client), f.tool, f.agentArgs);
      expect(r.args).toEqual(f.resolved);

      const spec = manifest.tools.find((t) => t.name === f.tool)!;
      const enc = canonicalFor(`github.${f.tool}`, spec.template.version, r.args);
      const rendered = renderTemplate(enc.canonical_bytes, registries);
      expect(rendered.status).toBe("ok");
      if (rendered.status !== "ok") return;
      expect(rendered.text).toBe(f.rendered);
      expect(rendered.hidden).toEqual(f.hidden ?? []);
      expect(rendered.template.template_id).toBe(`github.${f.tool}`);
      expect(rendered.note).toBe(f.note);
      expect(rendered.links).toEqual(f.links);
      expect(rendered.links_error).toBeUndefined();

      // Determinism: a second resolve against the same state yields the same canonical bytes.
      const again = await githubAdapter.resolve(resolveCtx(client), f.tool, f.agentArgs);
      expect(canonicalFor(`github.${f.tool}`, spec.template.version, again.args).canonical_bytes).toBe(enc.canonical_bytes);
    });
  }

  it("a resolved object with a key the template neither shows nor elides is refused by the renderer", () => {
    const enc = canonicalFor("github.merge_pull_request", 2, { repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash", title: "sneaky" });
    const rendered = renderTemplate(enc.canonical_bytes, registries);
    expect(rendered).toMatchObject({ status: "unverified", reason: "unreferenced_key", detail: "title" });
  });
});
