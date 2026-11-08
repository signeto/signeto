import { describe, expect, it } from "vitest";
import { verify } from "node:crypto";
import { AdapterError } from "@signeto/adapter-sdk";
import { buildAppJwt, createGithubAdapter, MINT_PERMISSIONS, type GithubCredential } from "../src/index.js";
import { HEAD_SHA, REF_SHA, TEST_APP_ID, TEST_PRIVATE_KEY_PEM, TEST_PUBLIC_KEY, credentialCtx, frozen, mockFetch, recordingLogger, type Route } from "./helpers.js";

const NOW = 1_700_000_000_000;
const TOKEN = "ghs_mintedInstallationToken123";
const expiresIn = (ms: number) => new Date(NOW + ms).toISOString();

const secrets = { app_id: TEST_APP_ID, private_key: TEST_PRIVATE_KEY_PEM };
const mergeAction = frozen("github.merge_pull_request", { repo: "acme/api", pr: 42, base: "main", head_sha: HEAD_SHA, method: "squash" });
const dispatchAction = frozen("github.dispatch_workflow", { repo: "acme/api", workflow: "deploy.yml", ref: "main", ref_sha: REF_SHA, inputs: {} });
const readAction = frozen("github.read_pull_request", { repo: "acme/api", pr: 42 });

function tokenRoutes(over: Partial<Route> = {}, installationBody: unknown = { id: 99 }): Route[] {
  return [
    { method: "GET", path: "/repos/acme/api/installation", body: installationBody },
    { method: "POST", path: "/app/installations/99/access_tokens", status: 201, body: { token: TOKEN, expires_at: expiresIn(3_600_000), permissions: { contents: "write", pull_requests: "write" }, repositories: [{ full_name: "acme/api" }] }, ...over },
    { method: "DELETE", path: "/installation/token", status: 204 },
  ];
}

function decodeJwt(jwt: string) {
  const [h, p, s] = jwt.split(".") as [string, string, string];
  return { header: JSON.parse(Buffer.from(h, "base64url").toString()), payload: JSON.parse(Buffer.from(p, "base64url").toString()), signingInput: `${h}.${p}`, signature: Buffer.from(s, "base64url") };
}

async function expectCode(p: Promise<unknown>, code: AdapterError["code"]) {
  const err = await p.then(() => undefined, (e: unknown) => e);
  expect(err).toBeInstanceOf(AdapterError);
  expect((err as AdapterError).code).toBe(code);
  return err as AdapterError;
}

describe("buildAppJwt", () => {
  it("produces an RS256 JWT that verifies with the App public key and carries iss/iat/exp", () => {
    const jwt = buildAppJwt(TEST_APP_ID, TEST_PRIVATE_KEY_PEM, { nowS: NOW / 1000 });
    const { header, payload, signingInput, signature } = decodeJwt(jwt);
    expect(header).toEqual({ alg: "RS256", typ: "JWT" });
    expect(payload).toEqual({ iss: TEST_APP_ID, iat: NOW / 1000 - 60, exp: NOW / 1000 + 600 });
    expect(verify("sha256", Buffer.from(signingInput), TEST_PUBLIC_KEY, signature)).toBe(true);
  });

  it("never exceeds GitHub's 10 minute maximum", () => {
    const { payload } = decodeJwt(buildAppJwt(TEST_APP_ID, TEST_PRIVATE_KEY_PEM, { nowS: 1000, ttlS: 86_400 }));
    expect(payload.exp - 1000).toBe(600);
  });

  it("rejects a non-numeric app id and a non-RSA key", () => {
    expect(() => buildAppJwt("acme-app", TEST_PRIVATE_KEY_PEM)).toThrow(/numeric/);
    expect(() => buildAppJwt(TEST_APP_ID, "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----")).toThrow();
  });
});

describe("mint", () => {
  it("builds a JWT, finds the installation for the repo, and requests a token scoped to the one repo with merge permissions", async () => {
    const m = mockFetch(tokenRoutes());
    const adapter = createGithubAdapter({ fetch: m.fetch, now: () => NOW });
    const cred = await adapter.mint!(credentialCtx(secrets), mergeAction);

    expect(cred.material).toBe(TOKEN);
    expect(cred.expiresAt.toISOString()).toBe(expiresIn(3_600_000));
    expect(cred.scope).toBe(`github installation token: repo=acme/api contents:write pull_requests:write installation=99 expires=${expiresIn(3_600_000)}`);

    expect(m.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", "/repos/acme/api/installation"],
      ["POST", "/app/installations/99/access_tokens"],
    ]);
    for (const c of m.calls) {
      const auth = c.headers.authorization!;
      expect(auth.startsWith("Bearer ")).toBe(true);
      const { payload, signingInput, signature } = decodeJwt(auth.slice(7));
      expect(payload.iss).toBe(TEST_APP_ID);
      expect(verify("sha256", Buffer.from(signingInput), TEST_PUBLIC_KEY, signature)).toBe(true);
    }
    expect(m.calls[1]!.body).toEqual({ repositories: ["api"], permissions: { contents: "write", pull_requests: "write" } });
  });

  it("requests actions:write (+ contents:read for the ref check) for dispatch and pull_requests:read for read", async () => {
    const d = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000) } }));
    await createGithubAdapter({ fetch: d.fetch, now: () => NOW }).mint!(credentialCtx(secrets), dispatchAction);
    expect(d.calls[1]!.body).toEqual({ repositories: ["api"], permissions: MINT_PERMISSIONS.dispatch_workflow });
    expect(MINT_PERMISSIONS.dispatch_workflow).toEqual({ actions: "write", contents: "read" });

    const r = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000) } }));
    await createGithubAdapter({ fetch: r.fetch, now: () => NOW }).mint!(credentialCtx(secrets), readAction);
    expect(r.calls[1]!.body).toEqual({ repositories: ["api"], permissions: { pull_requests: "read" } });
  });

  it("uses installation_id from secrets instead of looking it up (merge reads the installation's permissions; a failed read is not fatal)", async () => {
    const m = mockFetch([{ method: "POST", path: "/app/installations/777/access_tokens", status: 201, body: { token: TOKEN, expires_at: expiresIn(3_600_000) } }]);
    const cred = await createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx({ ...secrets, installation_id: "777" }), mergeAction);
    expect(m.calls.map((c) => c.path)).toEqual(["/app/installations/777", "/app/installations/777/access_tokens"]);
    expect(cred.scope).toContain("installation=777");
    expect(m.calls[1]!.body).toEqual({ repositories: ["api"], permissions: { contents: "write", pull_requests: "write" } });
    const r = mockFetch([{ method: "POST", path: "/app/installations/777/access_tokens", status: 201, body: { token: TOKEN, expires_at: expiresIn(3_600_000) } }]);
    await createGithubAdapter({ fetch: r.fetch, now: () => NOW }).mint!(credentialCtx({ ...secrets, installation_id: "777" }), readAction);
    expect(r.calls.map((c) => c.path)).toEqual(["/app/installations/777/access_tokens"]);
  });

  it("adds checks:write to the merge token only when the installation has accepted it", async () => {
    const granted = { token: TOKEN, expires_at: expiresIn(3_600_000), permissions: { contents: "write", pull_requests: "write", checks: "write", metadata: "read" }, repositories: [{ full_name: "acme/api" }] };
    const m = mockFetch(tokenRoutes({ body: granted }, { id: 99, permissions: { contents: "write", pull_requests: "write", checks: "write", metadata: "read" } }));
    const cred = (await createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction)) as GithubCredential;
    expect(m.calls[1]!.body).toEqual({ repositories: ["api"], permissions: { contents: "write", pull_requests: "write", checks: "write" } });
    expect(cred.permissions).toEqual({ contents: "write", pull_requests: "write", checks: "write" });
    expect(cred.scope).toContain("checks:write contents:write pull_requests:write");

    // With installation_id in secrets the permissions come from GET /app/installations/{id}.
    const s = mockFetch([
      { method: "GET", path: "/app/installations/777", body: { id: 777, permissions: { checks: "write" } } },
      { method: "POST", path: "/app/installations/777/access_tokens", status: 201, body: { token: TOKEN, expires_at: expiresIn(3_600_000) } },
    ]);
    await createGithubAdapter({ fetch: s.fetch, now: () => NOW }).mint!(credentialCtx({ ...secrets, installation_id: "777" }), mergeAction);
    expect(s.calls[1]!.body).toMatchObject({ permissions: { checks: "write" } });

    // Read-only checks access, or none, is not enough: the token is requested without checks.
    const ro = mockFetch(tokenRoutes({}, { id: 99, permissions: { checks: "read" } }));
    const plain = (await createGithubAdapter({ fetch: ro.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction)) as GithubCredential;
    expect(ro.calls[1]!.body).toEqual({ repositories: ["api"], permissions: { contents: "write", pull_requests: "write" } });
    expect(plain.permissions).toEqual({ contents: "write", pull_requests: "write" });

    // Dispatch never asks for checks.
    const d = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000) } }, { id: 99, permissions: { checks: "write" } }));
    await createGithubAdapter({ fetch: d.fetch, now: () => NOW }).mint!(credentialCtx(secrets), dispatchAction);
    expect(d.calls[1]!.body).toEqual({ repositories: ["api"], permissions: MINT_PERMISSIONS.dispatch_workflow });
  });

  it("revoke() calls DELETE /installation/token with the minted token", async () => {
    const m = mockFetch(tokenRoutes());
    const cred = await createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction);
    await cred.revoke!();
    const del = m.calls.at(-1)!;
    expect(del).toMatchObject({ method: "DELETE", path: "/installation/token" });
    expect(del.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("revoke() is best effort: a failing DELETE logs a warning and does not throw", async () => {
    const m = mockFetch([...tokenRoutes().slice(0, 2), { method: "DELETE", path: "/installation/token", throws: new TypeError("fetch failed") }]);
    const { logger, warnings } = recordingLogger();
    const cred = await createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!({ ...credentialCtx(secrets), logger }, mergeAction);
    await expect(cred.revoke!()).resolves.toBeUndefined();
    expect(warnings).toHaveLength(1);
  });

  it("rejects a token response without an expiry", async () => {
    const m = mockFetch(tokenRoutes({ body: { token: TOKEN } }));
    const e = await expectCode(createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
    expect(e.message).toMatch(/expires_at/);
    const bad = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: "soon" } }));
    await expectCode(createGithubAdapter({ fetch: bad.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
  });

  it("rejects a token that lives longer than one hour or is already expired", async () => {
    const long = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(2 * 3_600_000) } }));
    await expectCode(createGithubAdapter({ fetch: long.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
    const past = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(-1000) } }));
    await expectCode(createGithubAdapter({ fetch: past.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
  });

  it("rejects a token broader than requested (extra permission, higher level, extra repository)", async () => {
    const extraPerm = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000), permissions: { contents: "write", pull_requests: "write", administration: "write" } } }));
    await expectCode(createGithubAdapter({ fetch: extraPerm.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
    const higher = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000), permissions: { contents: "write" } } }));
    await expectCode(createGithubAdapter({ fetch: higher.fetch, now: () => NOW }).mint!(credentialCtx(secrets), readAction), "credential_failed");
    const extraRepo = mockFetch(tokenRoutes({ body: { token: TOKEN, expires_at: expiresIn(3_600_000), repositories: [{ full_name: "acme/api" }, { full_name: "acme/web" }] } }));
    await expectCode(createGithubAdapter({ fetch: extraRepo.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
  });

  it("fails closed on every upstream error path and never falls back to a stored PAT", async () => {
    const withPat = { ...secrets, github_token: "ghp_storedPersonalAccessToken" };
    const cases: Array<[Route[], AdapterError["code"]]> = [
      [tokenRoutes({ status: 500, body: { message: "boom" } }), "credential_failed"],
      [tokenRoutes({ status: 403, body: { message: "Resource not accessible by integration" } }), "credential_failed"],
      [tokenRoutes({ text: "<html>not json</html>", status: 201 }), "credential_failed"],
      [tokenRoutes({ body: { expires_at: expiresIn(3_600_000) } }), "credential_failed"],
      [[{ method: "GET", path: "/repos/acme/api/installation", status: 404 }], "credential_failed"],
      [[{ method: "GET", path: "/repos/acme/api/installation", body: { id: "nope" } }], "credential_failed"],
      [[{ method: "GET", path: "/repos/acme/api/installation", throws: new TypeError("fetch failed") }], "upstream_unreachable"],
    ];
    for (const [routes, code] of cases) {
      const m = mockFetch(routes);
      const e = await expectCode(createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx(withPat), mergeAction), code);
      expect(e.message).not.toContain("ghp_");
      for (const c of m.calls) expect(c.headers.authorization).not.toContain("ghp_");
    }
  });

  it("fails closed when secrets are missing or malformed", async () => {
    const m = mockFetch(tokenRoutes());
    const adapter = createGithubAdapter({ fetch: m.fetch, now: () => NOW });
    await expectCode(adapter.mint!(credentialCtx({ app_id: TEST_APP_ID }), mergeAction), "credential_failed");
    await expectCode(adapter.mint!(credentialCtx({ private_key: TEST_PRIVATE_KEY_PEM }), mergeAction), "credential_failed");
    const e = await expectCode(adapter.mint!(credentialCtx({ app_id: TEST_APP_ID, private_key: "not a pem" }), mergeAction), "credential_failed");
    expect(e.message).not.toContain("not a pem");
    await expectCode(adapter.mint!(credentialCtx({ ...secrets, installation_id: "abc" }), mergeAction), "credential_failed");
    expect(m.calls).toHaveLength(0);
  });

  it("throws timeout when the deadline has already passed, without calling GitHub", async () => {
    const m = mockFetch(tokenRoutes());
    const ctx = { ...credentialCtx(secrets), deadline: new Date(Date.now() - 1) };
    await expectCode(createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(ctx, mergeAction), "timeout");
    expect(m.calls).toHaveLength(0);
  });

  it("never puts the private key or JWT in the scope or an error", async () => {
    const m = mockFetch(tokenRoutes({ status: 500, body: {} }));
    const e = await expectCode(createGithubAdapter({ fetch: m.fetch, now: () => NOW }).mint!(credentialCtx(secrets), mergeAction), "credential_failed");
    expect(e.message).not.toContain("BEGIN");
    expect(e.message).not.toContain("eyJ");
  });
});
