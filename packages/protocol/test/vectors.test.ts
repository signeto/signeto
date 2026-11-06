import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as P from "../src/index.js";

const root = join(__dirname, "..", "vectors");
const load = (dir: string): Array<{ name: string; v: any }> =>
  readdirSync(join(root, dir))
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, v: JSON.parse(readFileSync(join(root, dir, f), "utf8")) }));

describe("canonical/", () => {
  for (const { name, v } of load("canonical")) {
    it(name, () => {
      const enc = P.encodeAction(v.inputs.action);
      expect(enc.canonical_bytes).toBe(v.expected.canonical_bytes);
      expect(enc.canonical_bytes_sha256).toBe(v.expected.canonical_bytes_sha256);
      expect(P.idempotencyKey(v.inputs.action)).toBe(v.expected.idempotency_key);
      const back = P.parseCanonicalAction(v.expected.canonical_bytes);
      expect(back.ok).toBe(true);
      if (v.expected.rendered) {
        const r = P.renderTemplate(v.expected.canonical_bytes, P.builtinRegistries);
        expect(r.status).toBe("ok");
        if (r.status === "ok") expect(r.text).toBe(v.expected.rendered);
      }
    });
  }
});

describe("canonical-invalid/", () => {
  for (const { name, v } of load("canonical-invalid")) {
    it(name, () => {
      const r = P.parseCanonicalAction(v.inputs.canonical_bytes);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe(v.expected_error);
    });
  }
});

describe("templates/", () => {
  for (const { name, v } of load("templates")) {
    it(name, () => {
      const r = P.renderTemplate(v.inputs.canonical_bytes, v.inputs.registries);
      expect(r.status).toBe(v.expected.status);
      if (r.status === "ok") {
        expect(r.text).toBe(v.expected.text);
        expect(r.hidden).toEqual(v.expected.hidden);
      } else {
        expect(r.reason).toBe(v.expected.reason);
        if (v.expected.detail) expect(r.detail).toBe(v.expected.detail);
      }
    });
  }
});

describe("receipts/signing-input/", () => {
  for (const { name, v } of load("receipts/signing-input")) {
    it(name, () => {
      const si = P.receiptSigningInput(v.inputs);
      expect(si).toBe(v.expected.signing_input);
      expect(P.base64url.encode(P.webauthnChallenge(si))).toBe(v.expected.webauthn_challenge);
    });
  }
});

describe("receipts/", () => {
  for (const { name, v } of load("receipts")) {
    it(name, () => {
      const r = P.verifyReceipt({
        receipt: v.inputs.receipt,
        canonical_bytes: v.inputs.canonical_bytes,
        issued_at: v.inputs.issued_at,
        expires_at: v.inputs.expires_at,
        device_public_key: v.inputs.device_public_key,
        ...(v.inputs.webauthn_policy ? { webauthn: v.inputs.webauthn_policy } : {}),
      });
      if (v.expected.verify === "ok") {
        expect(r).toMatchObject({ ok: true });
        if (r.ok && v.expected.signing_input) expect(r.signing_input).toBe(v.expected.signing_input);
      } else {
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe(v.expected.code);
      }
    });
  }
});

describe("approval-request/", () => {
  for (const { name, v } of load("approval-request")) {
    it(name, () => {
      const r = P.verifyApprovalRequest(v.inputs.request, v.inputs.pinned);
      if (v.expected.verify === "ok") {
        expect(r.ok).toBe(true);
        const f = P.approvalRequestFields(v.inputs.request)!;
        expect(P.approvalRequestSigningInput(f)).toBe(v.expected.signing_input);
      } else {
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe(v.expected.code);
      }
    });
  }
});

describe("ids/", () => {
  for (const { name, v } of load("ids")) {
    it(name, () => {
      expect(P.gatewayIdFromJwk(v.inputs.gateway)).toBe(v.expected.gateway_id);
      expect(P.deviceIdFromJwk(v.inputs.device_es256)).toBe(v.expected.device_es256_id);
      expect(P.deviceIdFromJwk(v.inputs.device_ed25519)).toBe(v.expected.device_ed25519_id);
      expect(P.fingerprint(v.inputs.gateway)).toBe(v.expected.gateway_fingerprint);
      expect(P.fingerprint(v.inputs.device_es256)).toBe(v.expected.device_es256_fingerprint);
    });
  }
});
