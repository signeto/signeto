import { describe, expect, it } from "vitest";
import { verify } from "node:crypto";
import { AdapterError } from "@signeto/adapter-sdk";
import { GithubApiError, READ_ONLY_PERMISSIONS, readPermissionsFor, READ_TOKEN_REFRESH_MS, createAppReadOnlyClient, createGithubAdapter } from "../src/index.js";
import { HEAD_SHA, TEST_APP_ID, TEST_PRIVATE_KEY_PEM, TEST_PUBLIC_KEY, mockFetch, pullRequest, resolveCtx, type Route } from "./helpers.js";

const T0 = 1_700_000_000_000;
const HOUR = 3_600_000;

function tokenBody(token: string, expiresAt: number, over: Record<string, unknown> = {}) {
  return { token, expires_at: new Date(expiresAt).toISOString(), permissions: { contents: "read", pull_requests: "read", metadata: "read" }, repositories: [{ full_name: "acme/api" }], ...over };
}

const TOKEN_PATH = /^\/app\/installations\/\d+\/access_tokens$/;

/** Static routes for acme/api and acme/web; token mints are answered from a queue (see `sequenced`). */
function routes(prStatus = 200): Route[] {
  return [
    { method: "GET", path: "/repos/acme/api/installation", body: { id: 99 } },
    { method: "GET", path: "/repos/acme/web/installation", body: { id: 99 } },
    { method: "POST", path: TOKEN_PATH, status: 500 },
    { method: "GET", path: "/repos/acme/api/pulls/42", status: prStatus, body: pullRequest() },
    { method: "GET", path: "/repos/acme/web/pulls/7", body: pullRequest({ number: 7, base: { ref: "main", repo: { full_name: "acme/web" } } }) },
  ];
}

/** mockFetch, except each token POST is answered by the next entry of `tokens` (recorded like any other call). */
function sequenced(r: Route[], tokens: Array<{ status?: number; body: unknown }>) {
  const m = mockFetch(r);
  const queue = [...tokens];
  const fetchFn: typeof fetch = async (input, init) => {
    const res = await m.fetch(input, init);
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if ((init?.method ?? "GET").toUpperCase() === "POST" && TOKEN_PATH.test(new URL(url).pathname)) {
      const next = queue.shift();
      if (!next) return new Response(JSON.stringify({ message: "no more tokens" }), { status: 500 });
      return new Response(JSON.stringify(next.body), { status: next.status ?? 201 });
    }
    return res;
  };
  return { fetch: fetchFn, calls: m.calls };
}

function client(tokens: Array<{ status?: number; body: unknown }>, clock: { t: number }, prStatus = 200) {
  const m = sequenced(routes(prStatus), tokens);
  return { c: createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: TEST_PRIVATE_KEY_PEM, fetch: m.fetch, clock: () => clock.t }), calls: m.calls };
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => {
      throw new Error("expected a rejection");
    },
    (e: unknown) => e,
  );
}

describe("createAppReadOnlyClient", () => {
  it("mints an installation token with read-only permissions scoped to the one repository, then GETs with it", async () => {
    const clock = { t: T0 };
    const { c, calls } = client([{ body: tokenBody("ghs_read1", T0 + HOUR) }], clock);
    const pr = await c.get("/repos/acme/api/pulls/42");
    expect(pr).toMatchObject({ number: 42, head: { sha: HEAD_SHA } });

    expect(calls.map((x) => [x.method, x.path])).toEqual([
      ["GET", "/repos/acme/api/installation"],
      ["POST", "/app/installations/99/access_tokens"],
      ["GET", "/repos/acme/api/pulls/42"],
    ]);
    const mintCall = calls[1]!;
    expect(mintCall.body).toEqual({ repositories: ["api"], permissions: { contents: "read", pull_requests: "read" } });
    expect(Object.values(READ_ONLY_PERMISSIONS).every((v) => v === "read")).toBe(true);
    // App calls carry a JWT signed by the App key; the GET carries the minted installation token.
    for (const x of calls.slice(0, 2)) {
      const [h, p, s] = x.headers.authorization!.slice(7).split(".") as [string, string, string];
      expect(verify("sha256", Buffer.from(`${h}.${p}`), TEST_PUBLIC_KEY, Buffer.from(s, "base64url"))).toBe(true);
    }
    expect(calls[2]!.headers.authorization).toBe("Bearer ghs_read1");
  });

  it("caches the token per repository and mints separately for another repository", async () => {
    const clock = { t: T0 };
    const { c, calls } = client([{ body: tokenBody("ghs_api", T0 + HOUR) }, { body: tokenBody("ghs_web", T0 + HOUR, { repositories: [{ full_name: "acme/web" }] }) }], clock);
    await c.get("/repos/acme/api/pulls/42");
    clock.t += 30 * 60_000;
    await c.get("/repos/acme/api/pulls/42");
    await c.get("/repos/acme/api/pulls/42");
    expect(calls.filter((x) => x.method === "POST")).toHaveLength(1);
    expect(calls.filter((x) => x.path === "/repos/acme/api/installation")).toHaveLength(1);

    await c.get("/repos/acme/web/pulls/7");
    const posts = calls.filter((x) => x.method === "POST");
    expect(posts).toHaveLength(2);
    expect(posts[1]!.body).toEqual({ repositories: ["web"], permissions: { contents: "read", pull_requests: "read" } });
    expect(calls.at(-1)!.headers.authorization).toBe("Bearer ghs_web");
  });

  it("shares one mint between concurrent GETs for the same repository", async () => {
    const clock = { t: T0 };
    const { c, calls } = client([{ body: tokenBody("ghs_once", T0 + HOUR) }], clock);
    await Promise.all([c.get("/repos/acme/api/pulls/42"), c.get("/repos/acme/api/pulls/42"), c.get("/repos/acme/api/pulls/42")]);
    expect(calls.filter((x) => x.method === "POST")).toHaveLength(1);
  });

  it("re-mints about five minutes before expires_at", async () => {
    const clock = { t: T0 };
    const { c, calls } = client([{ body: tokenBody("ghs_first", T0 + HOUR) }, { body: tokenBody("ghs_second", T0 + 2 * HOUR - READ_TOKEN_REFRESH_MS) }], clock);
    await c.get("/repos/acme/api/pulls/42");
    clock.t = T0 + HOUR - READ_TOKEN_REFRESH_MS - 1;
    await c.get("/repos/acme/api/pulls/42");
    expect(calls.filter((x) => x.method === "POST")).toHaveLength(1);
    expect(calls.at(-1)!.headers.authorization).toBe("Bearer ghs_first");

    clock.t = T0 + HOUR - READ_TOKEN_REFRESH_MS;
    await c.get("/repos/acme/api/pulls/42");
    expect(calls.filter((x) => x.method === "POST")).toHaveLength(2);
    expect(calls.at(-1)!.headers.authorization).toBe("Bearer ghs_second");
    // the installation id is cached across mints
    expect(calls.filter((x) => x.path === "/repos/acme/api/installation")).toHaveLength(1);
  });

  it("uses the installation_id secret instead of looking the installation up", async () => {
    const clock = { t: T0 };
    const m = mockFetch([
      { method: "POST", path: "/app/installations/777/access_tokens", status: 201, body: tokenBody("ghs_777", T0 + HOUR) },
      { method: "GET", path: "/repos/acme/api/pulls/42", body: pullRequest() },
    ]);
    const c = createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: TEST_PRIVATE_KEY_PEM, installationId: "777", fetch: m.fetch, clock: () => clock.t });
    await c.get("/repos/acme/api/pulls/42");
    expect(m.calls.map((x) => x.path)).toEqual(["/app/installations/777/access_tokens", "/repos/acme/api/pulls/42"]);
  });

  it("rejects paths outside /repos/{owner}/{repo}/ as GithubApiError without calling GitHub", async () => {
    const clock = { t: T0 };
    const { c, calls } = client([{ body: tokenBody("ghs_x", T0 + HOUR) }], clock);
    for (const p of [
      "/user",
      "/orgs/acme/repos",
      "/app/installations",
      "/installation/repositories",
      "/repos/acme",
      "/repos/acme/api",
      "/repos/acme/../orgs/acme/x",
      "/repos/acme/api/../../other/repo/pulls/1",
      "/repos/acme/api/%2e%2e/%2e%2e/other/repo/pulls/1",
      "/repos/acme/../../user/x",
      "/repos/acme%2fother/api/pulls/1",
      "repos/acme/api/pulls/1",
      "//evil.example/repos/acme/api/pulls/1",
      "/repos/acme/api/pulls/1#frag",
    ]) {
      const e = await rejection(c.get(p));
      expect(e, p).toBeInstanceOf(GithubApiError);
    }
    expect(calls).toHaveLength(0);
  });

  it("refuses a token broader than requested (write level, extra permission, extra repository)", async () => {
    const cases = [
      tokenBody("ghs_w", T0 + HOUR, { permissions: { contents: "write", pull_requests: "read", metadata: "read" } }),
      tokenBody("ghs_admin", T0 + HOUR, { permissions: { contents: "read", administration: "read" } }),
      tokenBody("ghs_meta_w", T0 + HOUR, { permissions: { metadata: "write" } }),
      tokenBody("ghs_repos", T0 + HOUR, { repositories: [{ full_name: "acme/api" }, { full_name: "acme/web" }] }),
    ];
    for (const body of cases) {
      const clock = { t: T0 };
      const { c, calls } = client([{ body }], clock);
      const e = await rejection(c.get("/repos/acme/api/pulls/42"));
      expect(e).toBeInstanceOf(AdapterError);
      expect((e as AdapterError).code).toBe("resolve_failed");
      expect((e as AdapterError).message).toMatch(/beyond/);
      // the broader token is never used
      expect(calls.some((x) => x.path === "/repos/acme/api/pulls/42")).toBe(false);
    }
  });

  it("fails closed on API errors and never leaks the key or JWT", async () => {
    const clock = { t: T0 };
    const installation404: Route[] = [{ method: "GET", path: "/repos/acme/api/installation", status: 404 }];
    const installation500: Route[] = [{ method: "GET", path: "/repos/acme/api/installation", status: 500 }];
    const unreachable: Route[] = [{ method: "GET", path: "/repos/acme/api/installation", throws: new TypeError("fetch failed") }];
    const mintFailures: Array<[Route[], Array<{ status?: number; body: unknown }>, AdapterError["code"]]> = [
      [installation404, [], "resolve_failed"],
      [installation500, [], "resolve_failed"],
      [unreachable, [], "upstream_unreachable"],
      [routes(), [{ status: 403, body: { message: "Resource not accessible by integration" } }], "resolve_failed"],
      [routes(), [{ body: { token: "ghs_noexpiry" } }], "resolve_failed"],
      [routes(), [{ body: tokenBody("ghs_long", T0 + 3 * HOUR) }], "resolve_failed"],
      [routes(), [{ body: tokenBody("ghs_old", T0 - 1) }], "resolve_failed"],
    ];
    for (const [r, tokens, code] of mintFailures) {
      const m = sequenced(r, tokens);
      const c = createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: TEST_PRIVATE_KEY_PEM, fetch: m.fetch, clock: () => clock.t });
      const e = await rejection(c.get("/repos/acme/api/pulls/42"));
      expect(e).toBeInstanceOf(AdapterError);
      expect((e as AdapterError).code).toBe(code);
      expect((e as Error).message).not.toContain("BEGIN");
      expect((e as Error).message).not.toContain("eyJ");
      expect(m.calls.some((x) => x.path === "/repos/acme/api/pulls/42")).toBe(false);
    }

    // a non-2xx GET is a GithubApiError carrying the status; a 401 drops the cached token
    const { c, calls } = client([{ body: tokenBody("ghs_a", T0 + HOUR) }, { body: tokenBody("ghs_b", T0 + HOUR) }], clock, 401);
    const e = await rejection(c.get("/repos/acme/api/pulls/42"));
    expect(e).toBeInstanceOf(GithubApiError);
    expect((e as GithubApiError).status).toBe(401);
    await rejection(c.get("/repos/acme/api/pulls/42"));
    expect(calls.filter((x) => x.method === "POST")).toHaveLength(2);
  });

  it("refuses a bad app id or key at construction, without echoing the key", () => {
    expect(() => createAppReadOnlyClient({ appId: "acme-app", privateKey: TEST_PRIVATE_KEY_PEM })).toThrow(/numeric/);
    let msg = "";
    try {
      createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: "-----BEGIN PRIVATE KEY-----\nsecretish\n-----END PRIVATE KEY-----" });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/private key/);
    expect(msg).not.toContain("secretish");
    expect(() => createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: TEST_PRIVATE_KEY_PEM, installationId: "abc" })).toThrow(/numeric/);
  });

  it("plugs into resolve: merge_pull_request resolves through the App client; a mint failure fails resolve closed", async () => {
    const clock = { t: T0 };
    const { c } = client([{ body: tokenBody("ghs_r", T0 + HOUR) }], clock);
    const adapter = createGithubAdapter();
    const r = await adapter.resolve(resolveCtx(c), "github.merge_pull_request", { repo: "Acme/API", pr: 42 });
    expect(r.args).toEqual({ repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" });

    const bad = createAppReadOnlyClient({ appId: TEST_APP_ID, privateKey: TEST_PRIVATE_KEY_PEM, fetch: mockFetch([{ method: "GET", path: "/repos/acme/api/installation", status: 404 }]).fetch, clock: () => clock.t });
    const e = await rejection(adapter.resolve(resolveCtx(bad), "github.merge_pull_request", { repo: "acme/api", pr: 42 }));
    expect(e).toBeInstanceOf(AdapterError);
    expect((e as AdapterError).code).toBe("resolve_failed");
    expect((e as AdapterError).message).toMatch(/not installed/);
  });

  it("asks for Actions read only on workflow paths, so an App without Actions access still resolves pull requests", () => {
    expect(readPermissionsFor("/repos/acme/api/pulls/1")).toEqual({ contents: "read", pull_requests: "read" });
    expect(readPermissionsFor("/repos/acme/api/actions/workflows/deploy.yml")).toEqual({ contents: "read", actions: "read" });
    expect(readPermissionsFor("/repos/acme/api/git/ref/heads/main")).toEqual({ contents: "read", pull_requests: "read" });
  });
});
