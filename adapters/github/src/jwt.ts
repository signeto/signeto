// GitHub App JWT (RS256) with node:crypto only. https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
import { createPrivateKey, sign, type KeyObject } from "node:crypto";

/** GitHub rejects JWTs valid for more than 10 minutes. */
export const APP_JWT_MAX_TTL_S = 600;
/** Backdate iat to absorb clock drift between the gateway and GitHub. */
export const APP_JWT_SKEW_S = 60;

export function base64url(input: Uint8Array | string): string {
  return Buffer.from(input).toString("base64url");
}

export interface AppJwtOptions {
  /** Unix seconds. Defaults to Date.now()/1000. */
  nowS?: number;
  /** Lifetime after `nowS`, in seconds. Clamped to GitHub's 10-minute maximum. */
  ttlS?: number;
}

export function parsePrivateKey(pem: string): KeyObject {
  const key = createPrivateKey({ key: pem, format: "pem" });
  if (key.asymmetricKeyType !== "rsa") throw new Error(`GitHub App private key must be RSA, got ${key.asymmetricKeyType ?? "unknown"}`);
  return key;
}

/** Build a signed RS256 JWT `{ iat, exp, iss }` for the App. Deterministic for a fixed `nowS` (RSASSA-PKCS1-v1_5 is deterministic). */
export function buildAppJwt(appId: string, privateKeyPem: string, opts: AppJwtOptions = {}): string {
  if (!/^\d+$/.test(appId)) throw new Error("GitHub App id must be numeric");
  const key = parsePrivateKey(privateKeyPem);
  const nowS = Math.floor(opts.nowS ?? Date.now() / 1000);
  const ttl = Math.min(opts.ttlS ?? APP_JWT_MAX_TTL_S, APP_JWT_MAX_TTL_S);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: nowS - APP_JWT_SKEW_S, exp: nowS + ttl, iss: appId }));
  const signingInput = `${header}.${payload}`;
  const signature = sign("sha256", Buffer.from(signingInput, "utf8"), key);
  return `${signingInput}.${base64url(signature)}`;
}
