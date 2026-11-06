import { describe, expect, it } from "vitest";
import { registryFromManifest, validateAdapter } from "@signeto/adapter-sdk";
import { findTemplate, githubRegistry, templateSha256 } from "@signeto/protocol";
import { githubAdapter, manifest, MINT_PERMISSIONS } from "../src/index.js";

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

  it("merge_pull_request v1 matches the builtin protocol registry byte for byte", () => {
    const ours = findTemplate([registryFromManifest(manifest)], "github.merge_pull_request", 1);
    const builtin = findTemplate([githubRegistry], "github.merge_pull_request", 1);
    expect(ours).toBeDefined();
    expect(builtin).toBeDefined();
    expect(ours!.text).toBe(builtin!.text);
    expect(ours!.sha256).toBe(builtin!.sha256);
    expect(ours!.sha256).toBe(templateSha256("Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}"));
  });

  it("has the expected templates", () => {
    const reg = registryFromManifest(manifest);
    expect(reg.templates.map((t) => [t.template_id, t.template_version, t.text, t.elide ?? null])).toEqual([
      ["github.merge_pull_request", 1, "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}", null],
      ["github.dispatch_workflow", 1, "Run {workflow} on {ref} ({ref_sha}) in {repo}", ["inputs"]],
      ["github.read_pull_request", 1, "Read PR #{pr} on {repo}", null],
    ]);
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
