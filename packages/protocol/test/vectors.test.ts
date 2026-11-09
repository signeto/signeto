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

for (const dir of ["templates", "links"]) {
  describe(`${dir}/`, () => {
    for (const { name, v } of load(dir)) {
      it(name, () => {
        const r = P.renderTemplate(v.inputs.canonical_bytes, v.inputs.registries);
        expect(r.status).toBe(v.expected.status);
        if (r.status === "ok") {
          expect(r.text).toBe(v.expected.text);
          expect(r.hidden).toEqual(v.expected.hidden);
          expect(r.note).toBe(v.expected.note);
          expect(r.links).toEqual(v.expected.links ?? []);
          expect(r.links_error).toBe(v.expected.links_error);
        } else {
          expect(r.reason).toBe(v.expected.reason);
          if (v.expected.detail) expect(r.detail).toBe(v.expected.detail);
        }
      });
    }
  });
}

describe("display-escape/", () => {
  for (const { name, v } of load("display-escape")) {
    it(name, () => {
      expect(P.displayEscape(v.inputs.value)).toBe(v.expected.escaped);
      expect(P.isDisplaySafe(v.expected.escaped)).toBe(true);
    });
  }
});

describe("template-sha256/", () => {
  for (const { name, v } of load("template-sha256")) {
    it(name, () => {
      expect(P.templateHashInput(v.inputs.template)).toBe(v.expected.hash_input);
      expect(P.templateSha256(v.inputs.template)).toBe(v.expected.sha256);
      expect(P.sha256hex(v.expected.hash_input)).toBe(v.expected.sha256);
    });
  }
});

describe("bundled registries", () => {
  it("every bundled template is valid and hashes to its sha256 (a bad link is a build error)", () => {
    for (const r of P.builtinRegistries)
      for (const t of r.templates) {
        expect(P.templateProblems(t), t.template_id).toEqual([]);
        expect(P.templateSha256(t), t.template_id).toBe(t.sha256);
      }
  });
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

describe("relay-auth/", () => {
  const privateKey = (name: string) => JSON.parse(readFileSync(join(root, "keys", name + ".json"), "utf8"));
  for (const { name, v } of load("relay-auth")) {
    it(name, () => {
      const i = v.inputs;
      if (v.expected.body_sha256) expect(P.relayBodySha256(i.body)).toBe(v.expected.body_sha256);
      if (v.expected.signing_input)
        expect(P.relayAuthSigningInput({ method: i.method, path: i.path, ts: i.ts, body_sha256: P.relayBodySha256(i.body) })).toBe(v.expected.signing_input);
      if (v.expected.header && i.private_key)
        expect(P.signRelayRequest({ scheme: i.scheme, method: i.method, path: i.path, ts: i.ts, body: i.body }, privateKey(i.private_key))).toBe(v.expected.header);
      const r = P.verifyRelayRequest({ header: i.header, method: i.method, path: i.path, body: i.body, public_key: i.public_key, now: i.now });
      if (v.expected.verify === "ok") {
        expect(r.ok).toBe(true);
        if (r.ok && v.expected.key_id) expect(r.key_id).toBe(v.expected.key_id);
      } else {
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe(v.expected.code);
      }
    });
  }
});
