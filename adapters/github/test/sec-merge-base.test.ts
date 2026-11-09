// Regression for SIG-92 M5 / SIG-98 (threat-model 4.7): the signed `base` of github.merge_pull_request is enforced at
// execute. The approver signs "Merge PR #42 into dev ...". Between approval and execution the PR is retargeted to
// `main` (the PR author or anyone with write access can edit the base; the head sha does not change). GitHub's merge
// endpoint pins only `sha`, so the adapter re-reads the PR and refuses unless base, base repo and head all match.
import { describe, expect, it } from "vitest";
import { AdapterError, type Credential } from "@signeto/adapter-sdk";
import { githubAdapter } from "../src/index.js";
import { HEAD_SHA, MERGE_SHA, executeCtx, frozen, mockFetch, pullRequest } from "./helpers.js";

const credential: Credential = { material: "ghs_token", expiresAt: new Date(Date.now() + 3_600_000), scope: "test" };
const signed = frozen("github.merge_pull_request", { repo: "acme/api", pr: 42, base: "dev", head_sha: HEAD_SHA, method: "squash" }, 2);
const mergeRoute = { method: "PUT", path: "/repos/acme/api/pulls/42/merge", body: { sha: MERGE_SHA, merged: true, message: "merged" } };

async function refused(upstreamPr: Record<string, unknown>) {
  const m = mockFetch([{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest(upstreamPr) }, mergeRoute]);
  const err = await githubAdapter.execute(executeCtx(m.fetch), signed, credential).then(() => undefined, (e: unknown) => e);
  expect(err).toBeInstanceOf(AdapterError);
  expect((err as AdapterError).code).toBe("precondition_failed");
  expect((err as AdapterError).retryable).toBe(false);
  // Nothing mutating was sent: no merge, no check run.
  expect(m.calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /repos/acme/api/pulls/42"]);
  return err as AdapterError;
}

describe("SEC: merge base binding (SIG-98)", () => {
  it("refuses a PR whose base moved from the signed `dev` to `main` after approval", async () => {
    const e = await refused({ base: { ref: "main", repo: { full_name: "acme/api" } } });
    expect(e.message).toContain("now targets main, not the approved dev");
    expect(e.detail).toMatchObject({ base: "dev", current_base: "main" });
  });

  it("refuses a PR whose base repository is not the signed repository", async () => {
    const e = await refused({ base: { ref: "dev", repo: { full_name: "evil/api" } } });
    expect(e.detail).toMatchObject({ repo: "acme/api", current_repo: "evil/api" });
  });

  it("refuses a PR whose head moved, and one whose base cannot be read", async () => {
    await refused({ base: { ref: "dev", repo: { full_name: "acme/api" } }, head: { ref: "x", sha: "f".repeat(40) } });
    await refused({ base: { ref: "dev" } });
    await refused({ base: null });
  });

  it("merges when base, base repo (case-insensitive) and head are the signed values, still pinning `sha`", async () => {
    const m = mockFetch([{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest({ base: { ref: "dev", repo: { full_name: "Acme/API" } } }) }, mergeRoute]);
    const r = await githubAdapter.execute(executeCtx(m.fetch), signed, credential);
    expect(m.calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /repos/acme/api/pulls/42", "PUT /repos/acme/api/pulls/42/merge"]);
    expect(m.calls[1]!.body).toEqual({ sha: HEAD_SHA, merge_method: "squash" });
    expect(r.evidence).toMatchObject({ base: "dev", merge_sha: MERGE_SHA });
  });

  it("a frozen merge without a signed base is refused before any request", async () => {
    const noBase = { ...signed, args: { repo: "acme/api", pr: 42, head_sha: HEAD_SHA, method: "squash" } };
    const m = mockFetch([mergeRoute]);
    await expect(githubAdapter.execute(executeCtx(m.fetch), noBase, credential)).rejects.toMatchObject({ code: "upstream_rejected" });
    expect(m.calls).toHaveLength(0);
  });
});
