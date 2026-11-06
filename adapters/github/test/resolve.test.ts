import { describe, expect, it } from "vitest";
import { canonicalize } from "@signeto/protocol";
import { AdapterError } from "@signeto/adapter-sdk";
import { githubAdapter } from "../src/index.js";
import { HEAD_SHA, REF_SHA, pullRequest, readOnlyClient, resolveCtx, workflow } from "./helpers.js";

const prRoutes = (over: Record<string, unknown> = {}) => [{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest(over) }];

async function expectCode(p: Promise<unknown>, code: AdapterError["code"]) {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AdapterError);
  expect((err as AdapterError).code).toBe(code);
  return err as AdapterError;
}

describe("resolve merge_pull_request", () => {
  it("looks the PR up over the read-only client and pins base + head sha", async () => {
    const { client, calls } = readOnlyClient(prRoutes());
    const r = await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 });
    expect(r.args).toEqual({ repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: "GET", path: "/repos/acme/api/pulls/42" });
    expect(calls[0]!.headers.authorization).toBe("Bearer read-only-token");
  });

  it("is deterministic: the same agent args and upstream state give byte-identical canonical args", async () => {
    const { client } = readOnlyClient(prRoutes());
    const a = await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42, method: "rebase" });
    const b = await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42, method: "rebase" });
    expect(canonicalize(a.args)).toBe(canonicalize(b.args));
  });

  it("normalises repo case and method case so two spellings produce the same bytes", async () => {
    const { client } = readOnlyClient([{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest() }]);
    const a = await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "Acme/API", pr: 42, method: "Squash" });
    const b = await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 });
    expect(canonicalize(a.args)).toBe(canonicalize(b.args));
  });

  it("rejects a closed PR with resolve_failed", async () => {
    const { client } = readOnlyClient(prRoutes({ state: "closed" }));
    const e = await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
    expect(e.message).toMatch(/closed/);
  });

  it("rejects a merged PR with resolve_failed", async () => {
    const { client } = readOnlyClient(prRoutes({ state: "closed", merged: true }));
    await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });

  it("rejects a draft PR with resolve_failed", async () => {
    const { client } = readOnlyClient(prRoutes({ draft: true }));
    await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });

  it("rejects a missing PR (404) with resolve_failed", async () => {
    const { client } = readOnlyClient([]);
    await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });

  it("rejects a PR whose repository moved with resolve_failed", async () => {
    const { client } = readOnlyClient(prRoutes({ base: { ref: "main", repo: { full_name: "acme/api-v2" } } }));
    await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });

  it("rejects an unknown merge method", async () => {
    const { client } = readOnlyClient(prRoutes());
    await expectCode(githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42, method: "fast-forward" }), "resolve_failed");
  });

  it("maps upstream 5xx to upstream_rejected (retryable) and network failure to upstream_unreachable", async () => {
    const a = readOnlyClient([{ method: "GET", path: "/repos/acme/api/pulls/42", status: 502, body: { message: "bad gateway" } }]);
    const e1 = await expectCode(githubAdapter.resolve(resolveCtx(a.client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "upstream_rejected");
    expect(e1.retryable).toBe(true);
    const b = readOnlyClient([{ method: "GET", path: "/repos/acme/api/pulls/42", throws: new TypeError("fetch failed") }]);
    await expectCode(githubAdapter.resolve(resolveCtx(b.client), "merge_pull_request", { repo: "acme/api", pr: 42 }), "upstream_unreachable");
  });

  it("refuses an upstream that is not a GithubReadOnlyClient", async () => {
    await expectCode(githubAdapter.resolve(resolveCtx({ put: () => {} }), "merge_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });

  it("throws timeout when the deadline has already passed", async () => {
    const { client } = readOnlyClient(prRoutes());
    const ctx = { ...resolveCtx(client), deadline: new Date(Date.now() - 1) };
    await expectCode(githubAdapter.resolve(ctx, "merge_pull_request", { repo: "acme/api", pr: 42 }), "timeout");
  });

  it("only ever issues GET requests", async () => {
    const { client, calls } = readOnlyClient([
      ...prRoutes(),
      { method: "GET", path: "/repos/acme/api/actions/workflows/deploy.yml", body: workflow() },
      { method: "GET", path: "/repos/acme/api/commits/main", body: { sha: REF_SHA } },
    ]);
    await githubAdapter.resolve(resolveCtx(client), "merge_pull_request", { repo: "acme/api", pr: 42 });
    await githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main" });
    await githubAdapter.resolve(resolveCtx(client), "read_pull_request", { repo: "acme/api", pr: 42 });
    expect(calls.every((c) => c.method === "GET")).toBe(true);
    expect(calls.length).toBe(4);
  });
});

describe("resolve dispatch_workflow", () => {
  const routes = [
    { method: "GET", path: "/repos/acme/api/actions/workflows/deploy.yml", body: workflow() },
    { method: "GET", path: "/repos/acme/api/actions/workflows/161335", body: workflow() },
    { method: "GET", path: "/repos/acme/api/commits/main", body: { sha: REF_SHA } },
    { method: "GET", path: "/repos/acme/api/commits/v1.2.0", body: { sha: REF_SHA } },
  ];

  it("pins the ref sha, normalises the workflow to its file name, and defaults inputs to {}", async () => {
    const { client } = readOnlyClient(routes);
    const r = await githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "Acme/Api", workflow: "deploy.yml", ref: "main" });
    expect(r.args).toEqual({ repo: "acme/api", workflow: "deploy.yml", ref: "main", ref_sha: REF_SHA, inputs: {} });
  });

  it("a workflow id and its file name resolve to the same bytes", async () => {
    const { client } = readOnlyClient(routes);
    const a = await githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "acme/api", workflow: "161335", ref: "main", inputs: { env: "prod" } });
    const b = await githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main", inputs: { env: "prod" } });
    expect(canonicalize(a.args)).toBe(canonicalize(b.args));
    expect(a.args.inputs).toEqual({ env: "prod" });
  });

  it("accepts tags", async () => {
    const { client } = readOnlyClient(routes);
    const r = await githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "v1.2.0" });
    expect(r.args.ref).toBe("v1.2.0");
  });

  it("rejects a disabled workflow, an unknown workflow, an unknown ref and a bare sha", async () => {
    const disabled = readOnlyClient([{ method: "GET", path: "/repos/acme/api/actions/workflows/deploy.yml", body: workflow({ state: "disabled_manually" }) }]);
    await expectCode(githubAdapter.resolve(resolveCtx(disabled.client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main" }), "resolve_failed");
    const missing = readOnlyClient([]);
    await expectCode(githubAdapter.resolve(resolveCtx(missing.client), "dispatch_workflow", { repo: "acme/api", workflow: "nope.yml", ref: "main" }), "resolve_failed");
    const noRef = readOnlyClient([routes[0]!]);
    await expectCode(githubAdapter.resolve(resolveCtx(noRef.client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "gone" }), "resolve_failed");
    const sha = readOnlyClient(routes);
    await expectCode(githubAdapter.resolve(resolveCtx(sha.client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: REF_SHA }), "resolve_failed");
  });

  it("rejects non-string inputs", async () => {
    const { client } = readOnlyClient(routes);
    await expectCode(githubAdapter.resolve(resolveCtx(client), "dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main", inputs: { n: 1 } }), "resolve_failed");
  });
});

describe("resolve read_pull_request", () => {
  it("verifies the PR exists and returns only repo + pr", async () => {
    const { client } = readOnlyClient(prRoutes({ state: "closed" }));
    const r = await githubAdapter.resolve(resolveCtx(client), "read_pull_request", { repo: "ACME/api", pr: 42 });
    expect(r.args).toEqual({ repo: "acme/api", pr: 42 });
  });

  it("fails on a missing PR", async () => {
    const { client } = readOnlyClient([]);
    await expectCode(githubAdapter.resolve(resolveCtx(client), "read_pull_request", { repo: "acme/api", pr: 42 }), "resolve_failed");
  });
});

describe("resolve unknown tool", () => {
  it("throws resolve_failed", async () => {
    const { client } = readOnlyClient([]);
    await expectCode(githubAdapter.resolve(resolveCtx(client), "delete_repo", { repo: "acme/api" }), "resolve_failed");
  });
});
