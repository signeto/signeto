import { describe, expect, it } from "vitest";
import { registryFromManifest, validateAdapter } from "@signeto/adapter-sdk";
import { findTemplate, githubRegistry, renderTemplate, templateLinksError, templateSha256, type Template } from "@signeto/protocol";
import { githubAdapter, manifest, MINT_PERMISSIONS } from "../src/index.js";
import { HEAD_SHA, canonicalFor } from "./helpers.js";

describe("manifest", () => {
  it("passes validateAdapter with no errors", () => {
    expect(validateAdapter(githubAdapter)).toEqual([]);
  });

  it("is a mint adapter that implements mint and not custody", () => {
    expect(manifest.mode).toBe("mint");
    expect(typeof githubAdapter.mint).toBe("function");
    expect(githubAdapter.custody).toBeUndefined();
  });

  it("only egresses to api.github.com", () => {
    expect(manifest.egress).toEqual(["api.github.com"]);
  });

  it("declares the two mandatory secrets", () => {
    expect(manifest.secrets.map((s) => s.name).sort()).toEqual(["app_id", "private_key"]);
  });

  it("merge_pull_request v2 matches the builtin protocol registry byte for byte, links and note included", () => {
    const ours = findTemplate([registryFromManifest(manifest)], "github.merge_pull_request", 2);
    const builtin = findTemplate([githubRegistry], "github.merge_pull_request", 2);
    expect(ours).toBeDefined();
    expect(builtin).toBeDefined();
    expect(ours).toEqual(builtin);
    expect(ours!.sha256).toBe(templateSha256(builtin!));
    // the links are hashed: a different URL is a different template
    const altered: Template = { ...ours!, links: [{ label: "View pull request", url: "https://github.com/{repo:path}/pulls" }] };
    expect(templateSha256(altered)).not.toBe(ours!.sha256);
    // v1 stays in the builtin registry for older gateways, unchanged
    expect(findTemplate([githubRegistry], "github.merge_pull_request", 1)!.sha256).toBe(templateSha256("Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}"));
  });

  it("has the expected templates", () => {
    const reg = registryFromManifest(manifest);
    expect(reg.templates.map((t) => [t.template_id, t.template_version, t.text, t.elide ?? null])).toEqual([
      ["github.merge_pull_request", 2, "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}", null],
      ["github.dispatch_workflow", 2, "Run {workflow} on {ref} ({ref_sha}) in {repo}", ["inputs"]],
      ["github.read_pull_request", 2, "Read PR #{pr} on {repo}", null],
    ]);
    expect(reg.templates.map((t) => t.note ?? null)).toEqual(["Approving commit {head_sha:short}. If the PR changes, this approval will not merge it.", null, null]);
    expect(reg.templates.map((t) => (t.links ?? []).map((l) => [l.label, l.url]))).toEqual([
      [
        ["View pull request", "https://github.com/{repo:path}/pull/{pr}"],
        ["Files changed", "https://github.com/{repo:path}/pull/{pr}/files"],
        ["Code at approved commit", "https://github.com/{repo:path}/tree/{head_sha}"],
      ],
      [
        ["Workflow file at approved commit", "https://github.com/{repo:path}/blob/{ref_sha}/.github/workflows/{workflow}"],
        ["Actions", "https://github.com/{repo:path}/actions"],
      ],
      [["View pull request", "https://github.com/{repo:path}/pull/{pr}"]],
    ]);
    for (const t of reg.templates) {
      expect(t.link_hosts).toEqual(["github.com"]);
      expect(templateLinksError(t)).toBeNull();
      expect(t.sha256).toBe(templateSha256(t));
    }
  });

  it("review links stay on github.com whatever the signed values contain", () => {
    const reg = [registryFromManifest(manifest)];
    const render = (args: Record<string, unknown>) => renderTemplate(canonicalFor("github.merge_pull_request", 2, args).canonical_bytes, reg);
    const base = { pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" };
    // repo is written {repo:path}: owner/name keeps its slash, each segment is percent-encoded
    const ok = render({ ...base, repo: "acme/api" });
    expect(ok).toMatchObject({ status: "ok", links: [{ url: "https://github.com/acme/api/pull/42" }, {}, {}] });
    for (const repo of ["evil.com@acme/api", "acme/api?x=1#y", "acme/../../evil", "acme//api", "naïve org/api"]) {
      const r = render({ ...base, repo });
      expect(r.status).toBe("ok");
      if (r.status !== "ok") continue;
      for (const l of r.links) {
        const u = new URL(l.url);
        expect([u.protocol, u.hostname, u.port, u.username, u.search, u.hash]).toEqual(["https:", "github.com", "", "", "", ""]);
        expect(u.pathname.split("/")).not.toContain("..");
      }
    }
    // a head_sha with a slash cannot add path segments: the plain placeholder encodes it
    const r = render({ ...base, repo: "acme/api", head_sha: "x/../../../evil" });
    expect(r).toMatchObject({ status: "ok" });
    if (r.status === "ok") expect(r.links[2]!.url).toBe("https://github.com/acme/api/tree/x%2F..%2F..%2F..%2Fevil");
  });

  it("closes every input and resolved schema", () => {
    for (const t of manifest.tools) {
      expect(t.input.additionalProperties).toBe(false);
      expect(t.resolved.additionalProperties).toBe(false);
    }
  });

  it("has a mint permission set for every tool", () => {
    for (const t of manifest.tools) expect(MINT_PERMISSIONS[t.name as keyof typeof MINT_PERMISSIONS]).toBeDefined();
  });
});
