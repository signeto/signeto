// GitHub App JWT (RS256) with node:crypto only. https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
import { createPrivateKey, sign, type KeyObject } from "node:crypto";

/** GitHub rejects a JWT whose `exp` is more than 10 minutes ahead of its own clock. */
export const APP_JWT_MAX_TTL_S = 600;
/** Backdate iat to absorb clock drift between the gateway and GitHub. */
export const APP_JWT_SKEW_S = 60;

export function base64url(input: Uint8Array | string): string {
  return Buffer.from(input).toString("base64url");
}

export interface AppJwtOptions {
  /** Unix seconds. Defaults to Date.now()/1000. */
  nowS?: number;
  /** Lifetime from `iat` (which is backdated by APP_JWT_SKEW_S), in seconds. Clamped to GitHub's 10-minute maximum. */
  ttlS?: number;
}

export function parsePrivateKey(pem: string): KeyObject {
  const key = createPrivateKey({ key: pem, format: "pem" });
  if (key.asymmetricKeyType !== "rsa") throw new Error(`GitHub App private key must be RSA, got ${key.asymmetricKeyType ?? "unknown"}`);
  return key;
}

/**
 * Build a signed RS256 JWT `{ iat, exp, iss }` for the App. Deterministic for a fixed `nowS` (RSASSA-PKCS1-v1_5 is deterministic).
 * `iat` is backdated by APP_JWT_SKEW_S and `exp` is at most 10 minutes after `iat`, so `exp` is at most 9 minutes after
 * `nowS`: a machine whose clock runs up to a minute ahead of GitHub's is still accepted. (With `exp` at `nowS` + 600, a
 * clock one second ahead of GitHub's got `401 'Expiration time' claim ('exp') is too far in the future`.)
 */
export function buildAppJwt(appId: string, privateKeyPem: string, opts: AppJwtOptions = {}): string {
  if (!/^\d+$/.test(appId)) throw new Error("GitHub App id must be numeric");
  const key = parsePrivateKey(privateKeyPem);
  const nowS = Math.floor(opts.nowS ?? Date.now() / 1000);
  const ttl = Math.min(opts.ttlS ?? APP_JWT_MAX_TTL_S, APP_JWT_MAX_TTL_S);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const iat = nowS - APP_JWT_SKEW_S;
  const payload = base64url(JSON.stringify({ iat, exp: iat + ttl, iss: appId }));
  const signingInput = `${header}.${payload}`;
  const signature = sign("sha256", Buffer.from(signingInput, "utf8"), key);
  return `${signingInput}.${base64url(signature)}`;
}
