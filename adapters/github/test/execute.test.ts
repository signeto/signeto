import { describe, expect, it } from "vitest";
import { AdapterError } from "@signeto/adapter-sdk";
import type { ApprovalInfo, Credential } from "@signeto/adapter-sdk";
import { CHECK_RUN_NAME, checkRunOutput, createGithubAdapter, escapeMarkdown, githubAdapter, type GithubCredential } from "../src/index.js";
import { HEAD_SHA, MERGE_SHA, REF_SHA, executeCtx, frozen, mockFetch, pullRequest, recordingLogger, type Route } from "./helpers.js";

const TOKEN = "ghs_mintedInstallationToken123";
const credential: Credential = { material: TOKEN, expiresAt: new Date(Date.now() + 3_600_000), scope: "test" };
const mergeAction = frozen("github.merge_pull_request", { repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" });
const dispatchAction = frozen("github.dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main", ref_sha: REF_SHA, inputs: { env: "prod" } });
const readAction = frozen("github.read_pull_request", { repo: "acme/api", pr: 42 });

async function expectCode(p: Promise<unknown>, code: AdapterError["code"]) {
  const err = await p.then(() => undefined, (e: unknown) => e);
  expect(err).toBeInstanceOf(AdapterError);
  expect((err as AdapterError).code).toBe(code);
  return err as AdapterError;
}

const mergeOk: Route = { method: "PUT", path: "/repos/acme/api/pulls/42/merge", body: { sha: MERGE_SHA, merged: true, message: "Pull Request successfully merged" } };

describe("execute merge_pull_request", () => {
  it("PUTs the frozen head sha and merge method with the minted token, and returns the merge sha as evidence", async () => {
    const m = mockFetch([mergeOk]);
    const r = await githubAdapter.execute(executeCtx(m.fetch), mergeAction, credential);
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]).toMatchObject({ method: "PUT", path: "/repos/acme/api/pulls/42/merge", body: { sha: HEAD_SHA, merge_method: "squash" } });
    expect(m.calls[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(m.calls[0]!.headers["x-github-api-version"]).toBe("2022-11-28");
    expect(r.content).toEqual({ merged: true, sha: MERGE_SHA, message: "Pull Request successfully merged" });
    expect(r.evidence).toEqual({ merge_sha: MERGE_SHA, repo: "acme/api", pr: 42, head_sha: HEAD_SHA, base: "main", method: "squash" });
    expect(JSON.stringify(r)).not.toContain(TOKEN);
  });

  describe("Signeto check run", () => {
    const approval: ApprovalInfo = {
      action_id: "act_01M6X0RJX3ARAWA7Q0CE4EPD9W",
      approver_id: "jason",
      device_id: "dev_AXRbxuCypBsG",
      device_name: "iPhone | <b>",
      signed_at: "2026-11-08T07:26:11.877Z",
      receipt_sha256: "3554f62e87bfc3a389b5484df3eac117de194f49201ec1c4b95c40ab41755b9a",
      approvals: 1,
    };
    const withChecks: GithubCredential = { ...credential, permissions: { contents: "write", pull_requests: "write", checks: "write" } };
    const checkOk: Route = { method: "POST", path: "/repos/acme/api/check-runs", status: 201, body: { id: 4242 } };

    it("posts a completed success check on the approved head sha before merging, and records its id", async () => {
      const m = mockFetch([checkOk, mergeOk]);
      const r = await githubAdapter.execute({ ...executeCtx(m.fetch), approval }, mergeAction, withChecks);
      expect(m.calls.map((c) => [c.method, c.path])).toEqual([
        ["POST", "/repos/acme/api/check-runs"],
        ["PUT", "/repos/acme/api/pulls/42/merge"],
      ]);
      expect(m.calls[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
      const body = m.calls[0]!.body as { name: string; head_sha: string; status: string; conclusion: string; external_id: string; output: { title: string; summary: string } };
      expect(body).toMatchObject({ name: CHECK_RUN_NAME, head_sha: HEAD_SHA, status: "completed", conclusion: "success", external_id: approval.action_id, completed_at: approval.signed_at });
      expect(body.output.title).toBe("Approved by jason on iPhone | <b>");
      expect(body.output.summary).toContain("| Device | iPhone \\| \\<b\\> (`dev_AXRbxuCypBsG`) |");
      expect(body.output.summary).toContain(`| Approved commit | \`${HEAD_SHA}\` |`);
      expect(body.output.summary).toContain(`signeto ledger --action ${approval.action_id}`);
      expect(body.output.summary).not.toContain("Approvals");
      expect(r.evidence).toMatchObject({ merge_sha: MERGE_SHA, check_run_id: 4242 });
    });

    it("a refused or unreachable check run is a warning; the approved merge still happens", async () => {
      for (const route of [{ ...checkOk, status: 403, body: { message: "Resource not accessible by integration" } }, { ...checkOk, throws: new TypeError("fetch failed") }]) {
        const { logger, warnings } = recordingLogger();
        const m = mockFetch([route, mergeOk]);
        const r = await githubAdapter.execute({ ...executeCtx(m.fetch), logger, approval }, mergeAction, withChecks);
        expect(r.evidence).toMatchObject({ merge_sha: MERGE_SHA, check_run_id: null });
        expect(warnings.map((w) => w.msg)).toContain("github: check run not created");
      }
    });

    it("no check run without checks:write on the token, or without an approval (tier 1)", async () => {
      const a = mockFetch([checkOk, mergeOk]);
      const r = await githubAdapter.execute({ ...executeCtx(a.fetch), approval }, mergeAction, credential);
      expect(a.calls.map((c) => c.method)).toEqual(["PUT"]);
      expect(r.evidence).not.toHaveProperty("check_run_id");
      const b = mockFetch([checkOk, mergeOk]);
      await githubAdapter.execute(executeCtx(b.fetch), mergeAction, withChecks);
      expect(b.calls.map((c) => c.method)).toEqual(["PUT"]);
    });

    it("summary lists the approval count for a quorum and escapes markdown in names", () => {
      const { summary, title } = checkRunOutput({ ...approval, approver_id: "*ops*", device_name: undefined, approvals: 2 } as ApprovalInfo, HEAD_SHA);
      expect(title).toBe("Approved by *ops* on dev_AXRbxuCypBsG");
      expect(summary).toContain("| Approver | \\*ops\\* |");
      expect(summary).toContain("| Approvals | 2 |");
      expect(escapeMarkdown("a\nb [x](y)")).toBe("a b \\[x\\]\\(y\\)");
    });
  });

  it("uses the frozen args, never anything else", async () => {
    const m = mockFetch([{ method: "PUT", path: "/repos/other/repo/pulls/7/merge", body: { sha: MERGE_SHA, merged: true } }]);
    const other = frozen("github.merge_pull_request", { repo: "other/repo", pr: 7, base: "main", head_sha: REF_SHA, method: "rebase" });
    await githubAdapter.execute(executeCtx(m.fetch), other, credential);
    expect(m.calls[0]!.body).toEqual({ sha: REF_SHA, merge_method: "rebase" });
  });

  it("maps 405 (not mergeable) and 409 (sha moved) to precondition_failed", async () => {
    for (const status of [405, 409]) {
      const m = mockFetch([{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status, body: { message: "Head branch was modified" } }]);
      const e = await expectCode(githubAdapter.execute(executeCtx(m.fetch), mergeAction, credential), "precondition_failed");
      expect(e.retryable).toBe(false);
      expect(e.detail).toEqual({ repo: "acme/api", pr: 42, head_sha: HEAD_SHA });
    }
  });

  it("fails closed on other statuses, malformed bodies, unconfirmed merges and network errors", async () => {
    const cases: Array<[Route, AdapterError["code"]]> = [
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 403, body: {} }, "upstream_rejected"],
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 404, body: {} }, "upstream_rejected"],
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 502, body: {} }, "upstream_rejected"],
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 200, text: "<html>" }, "upstream_rejected"],
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 200, body: { merged: false } }, "upstream_rejected"],
      [{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", throws: new TypeError("fetch failed") }, "upstream_unreachable"],
    ];
    for (const [route, code] of cases) {
      const m = mockFetch([route]);
      const e = await expectCode(githubAdapter.execute(executeCtx(m.fetch), mergeAction, credential), code);
      expect(e.message).not.toContain(TOKEN);
      expect(JSON.stringify(e.detail ?? {})).not.toContain(TOKEN);
    }
    const srv = mockFetch([{ method: "PUT", path: "/repos/acme/api/pulls/42/merge", status: 502, body: {} }]);
    const e = await expectCode(githubAdapter.execute(executeCtx(srv.fetch), mergeAction, credential), "upstream_rejected");
    expect(e.retryable).toBe(true);
  });

  it("refuses a credential whose material is not a token", async () => {
    const m = mockFetch([mergeOk]);
    await expectCode(githubAdapter.execute(executeCtx(m.fetch), mergeAction, { ...credential, material: { nope: true } }), "credential_failed");
    expect(m.calls).toHaveLength(0);
  });

  it("throws timeout when the deadline has already passed", async () => {
    const m = mockFetch([mergeOk]);
    await expectCode(githubAdapter.execute({ ...executeCtx(m.fetch), deadline: new Date(Date.now() - 1) }, mergeAction, credential), "timeout");
    expect(m.calls).toHaveLength(0);
  });
});

describe("execute dispatch_workflow", () => {
  const head = (sha: string): Route => ({ method: "GET", path: "/repos/acme/api/commits/main", body: { sha } });
  const dispatch: Route = { method: "POST", path: "/repos/acme/api/actions/workflows/deploy.yml/dispatches", status: 204 };
  const NOW = 1_700_000_000_000;
  const runs: Route = {
    method: "GET",
    path: `/repos/acme/api/actions/workflows/deploy.yml/runs?event=workflow_dispatch&head_sha=${REF_SHA}&per_page=1`,
    body: { workflow_runs: [{ id: 5551, html_url: "https://github.com/acme/api/actions/runs/5551", created_at: new Date(NOW + 500).toISOString() }] },
  };

  it("checks the ref still points at the signed sha, then POSTs the frozen ref and inputs, then looks the run up", async () => {
    const m = mockFetch([head(REF_SHA), dispatch, runs]);
    const r = await createGithubAdapter({ now: () => NOW }).execute(executeCtx(m.fetch), dispatchAction, credential);
    expect(m.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", "/repos/acme/api/commits/main"],
      ["POST", "/repos/acme/api/actions/workflows/deploy.yml/dispatches"],
      ["GET", runs.path],
    ]);
    expect(m.calls[1]!.body).toEqual({ ref: "main", inputs: { env: "prod" } });
    expect(m.calls.every((c) => c.headers.authorization === `Bearer ${TOKEN}`)).toBe(true);
    expect(r.content).toEqual({ dispatched: true, run_id: 5551, run_url: "https://github.com/acme/api/actions/runs/5551" });
    expect(r.evidence).toEqual({ dispatched: true, status: 204, repo: "acme/api", workflow: "deploy.yml", ref: "main", ref_sha: REF_SHA, run_id: 5551, run_url: "https://github.com/acme/api/actions/runs/5551" });
  });

  it("throws precondition_failed and does not dispatch when the ref moved after approval", async () => {
    const moved = "1111111111111111111111111111111111111111";
    const m = mockFetch([head(moved), dispatch, runs]);
    const e = await expectCode(githubAdapter.execute(executeCtx(m.fetch), dispatchAction, credential), "precondition_failed");
    expect(e.detail).toEqual({ repo: "acme/api", ref: "main", ref_sha: REF_SHA, current_sha: moved });
    expect(m.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("a failed run lookup is a warning, not a failure; an old run is not attributed", async () => {
    const { logger, warnings } = recordingLogger();
    const a = mockFetch([head(REF_SHA), dispatch, { ...runs, throws: new TypeError("fetch failed") }]);
    const r1 = await createGithubAdapter({ now: () => NOW }).execute({ ...executeCtx(a.fetch), logger }, dispatchAction, credential);
    expect(r1.content).toEqual({ dispatched: true });
    expect(r1.evidence).toMatchObject({ dispatched: true, run_id: null, run_url: null });
    expect(warnings).toHaveLength(1);

    const stale = { ...runs, body: { workflow_runs: [{ id: 1, html_url: "x", created_at: new Date(NOW - 600_000).toISOString() }] } };
    const b = mockFetch([head(REF_SHA), dispatch, stale]);
    const r2 = await createGithubAdapter({ now: () => NOW }).execute(executeCtx(b.fetch), dispatchAction, credential);
    expect(r2.content).toEqual({ dispatched: true });
  });

  it("fails closed when the dispatch is rejected or the ref check fails", async () => {
    const rejected = mockFetch([head(REF_SHA), { ...dispatch, status: 422, body: { message: "Required input missing" } }]);
    await expectCode(githubAdapter.execute(executeCtx(rejected.fetch), dispatchAction, credential), "upstream_rejected");
    const noRef = mockFetch([dispatch]);
    await expectCode(githubAdapter.execute(executeCtx(noRef.fetch), dispatchAction, credential), "upstream_rejected");
    expect(noRef.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });
});

describe("execute read_pull_request", () => {
  it("GETs the PR and returns a compact view plus state evidence", async () => {
    const m = mockFetch([{ method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest() }]);
    const r = await githubAdapter.execute(executeCtx(m.fetch), readAction, credential);
    expect(m.calls).toEqual([expect.objectContaining({ method: "GET", path: "/repos/acme/api/pulls/42" })]);
    expect(r.content).toEqual({
      repo: "acme/api",
      pr: 42,
      title: "Ship it",
      state: "open",
      draft: false,
      merged: false,
      mergeable: true,
      mergeable_state: "clean",
      head: { ref: "feature/x", sha: HEAD_SHA },
      base: { ref: "main" },
      author: "octocat",
      html_url: "https://github.com/acme/api/pull/42",
    });
    expect(r.evidence).toEqual({ repo: "acme/api", pr: 42, state: "open", head_sha: HEAD_SHA });
  });

  it("fails closed on 404", async () => {
    const m = mockFetch([]);
    await expectCode(githubAdapter.execute(executeCtx(m.fetch), readAction, credential), "upstream_rejected");
  });
});

describe("execute unknown tool", () => {
  it("throws", async () => {
    const m = mockFetch([]);
    await expectCode(githubAdapter.execute(executeCtx(m.fetch), frozen("github.delete_repo", { repo: "acme/api" }), credential), "upstream_rejected");
    expect(m.calls).toHaveLength(0);
  });
});
