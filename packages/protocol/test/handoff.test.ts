import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import * as P from "../src/index.js";

const json = (p: string) => JSON.parse(readFileSync(new URL(`../vectors/${p}`, import.meta.url), "utf8"));
const move = json("handoff/move.json");
const cases = json("handoff/device-cases.json").cases as Array<{ name: string; inputs: any; expected: { ok: boolean; error?: string; completed?: boolean; late?: boolean } }>;
const I = move.inputs;
const E = move.expected;
const g1 = I.predecessor_private_key as P.PrivateJwk;
const dev = I.device_private_key as P.PrivateJwk;
const pub = (j: P.PrivateJwk): P.PublicJwk => {
  const { d: _d, ...rest } = j;
  return rest as P.PublicJwk;
};
const key = (t: "ed25519" | "es256"): P.PrivateJwk => (t === "es256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("ed25519")).privateKey.export({ format: "jwk" }) as P.PrivateJwk;
const T0 = Date.parse(I.issued_at);

describe("handoff vector (§5.6, vectors/handoff/move.json)", () => {
  it("rebuilds the canonical action, G1's request signature, the receipt and the completion byte for byte", () => {
    const action = P.buildHandoffAction({ predecessor_gateway_id: P.gatewayIdFromJwk(g1), host: I.host, args: I.args, expiry_ms: I.expiry_ms }, { now: T0, nonce: I.nonce });
    expect(action.canonical_bytes).toBe(E.canonical_bytes);
    expect(action.canonical_bytes_sha256).toBe(E.canonical_bytes_sha256);
    const req = P.signApprovalRequest({ action_id: I.action_id, canonical_bytes: action.canonical_bytes, expires_at: action.action.expires_at }, g1);
    expect(req.gateway_signature).toBe(E.handoff.gateway_signature);
    expect(P.approvalRequestSigningInput(P.approvalRequestFields(req)!)).toBe(E.request_signing_input);
    const receipt = P.signReceipt({ action_id: I.action_id, canonical_bytes_sha256: action.canonical_bytes_sha256, decision: "approve", approver_id: I.pin.approver_id, device_id: P.deviceIdFromJwk(dev), signed_at: I.receipt_signed_at }, dev);
    expect(receipt).toEqual(E.receipt);
    expect(P.receiptSigningInput({ canonical_bytes_sha256: action.canonical_bytes_sha256, decision: "approve", signed_at: I.receipt_signed_at })).toBe(E.receipt_signing_input);
    const completion = P.signHandoffCompletion({ ...I.completion_fields, devices: [...I.devices].reverse(), receipts: [receipt] }, g1);
    expect(completion).toEqual(E.completion); // devices are sorted before signing
    expect(P.handoffCompletionSigningInput(completion)).toBe(E.completion_signing_input);
    expect(E.completion_signing_input).toContain(`"purpose":"${P.HANDOFF_COMPLETE_PURPOSE}"`);
  });

  it("renders the bundled template: the successor in the sentence, the ledger and policy in the note, the key hidden", () => {
    const r = P.renderTemplate(E.canonical_bytes, P.builtinRegistries);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect({ text: r.text, note: r.note, hidden: r.hidden }).toEqual(E.rendered);
    expect(r.text).toBe(`Move this gateway to Signeto Cloud (${I.args.successor_gateway_id})`);
    const t = P.findTemplate(P.builtinRegistries, P.HANDOFF_TOOL, 1)!;
    expect(P.templateProblems(t)).toEqual([]);
  });

  it("the device pins the successor with its own approver binding and template pins", () => {
    const r = P.verifyHandoffForDevice({ handoff: E.handoff, pin: I.pin, device_public_key: pub(dev), receipt: E.receipt, completion: E.completion });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.successor).toEqual(E.successor_pin);
    expect(r.completed).toBe(true);
    expect(r.late).toBe(false);
  });

  it("the successor verifies the whole record", () => {
    const rec = { ...E.handoff, predecessor_public_key: pub(g1), completion: E.completion };
    const r = P.verifyHandoffRecord(rec, { successor_gateway_id: I.args.successor_gateway_id });
    expect(r.ok).toBe(true);
    if (r.ok) expect([...r.devices.keys()]).toEqual(I.devices.map((d: P.HandoffDevice) => d.device_id).sort());
    expect(P.verifyHandoffRecord(rec, { successor_gateway_id: P.gatewayIdFromJwk(dev) })).toMatchObject({ ok: false, code: "successor_mismatch" });
  });
});

describe("device cases (vectors/handoff/device-cases.json)", () => {
  for (const c of cases) {
    it(c.name, () => {
      const r = P.verifyHandoffForDevice(c.inputs);
      if (c.expected.ok) {
        expect(r.ok).toBe(true);
        if (r.ok) expect({ completed: r.completed, late: r.late }).toEqual({ completed: c.expected.completed, late: c.expected.late });
      } else {
        expect(r.ok ? "ok" : r.code).toBe(c.expected.error);
      }
    });
  }
});

describe("record checks the successor runs (§5.6.6)", () => {
  const rec = () => ({ ...structuredClone(E.handoff), predecessor_public_key: pub(g1), completion: structuredClone(E.completion) });

  it("refuses a predecessor key that is not the one the handoff names", () => {
    expect(P.verifyHandoffRecord({ ...rec(), predecessor_public_key: pub(key("ed25519")) })).toMatchObject({ ok: false, code: "gateway_not_pinned" });
  });

  it("refuses a completion with a receipt from a device it does not list", () => {
    const other = key("es256");
    const r2 = P.signReceipt({ action_id: I.action_id, canonical_bytes_sha256: E.canonical_bytes_sha256, decision: "approve", approver_id: "jason", device_id: P.deviceIdFromJwk(other), signed_at: I.receipt_signed_at }, other);
    const c = P.signHandoffCompletion({ ...I.completion_fields, devices: I.devices, receipts: [r2] }, g1);
    expect(P.verifyHandoffRecord({ ...rec(), completion: c })).toMatchObject({ ok: false, code: "completion_invalid" });
  });

  it("refuses a denial, an approver mismatch and a receipt outside the window inside the completion", () => {
    for (const o of [{ decision: "deny" as const }, { approver_id: "mallory" }, { signed_at: P.formatTimestamp(T0 + 3_600_000) }]) {
      const r = P.signReceipt({ action_id: I.action_id, canonical_bytes_sha256: E.canonical_bytes_sha256, decision: "approve", approver_id: "jason", device_id: P.deviceIdFromJwk(dev), signed_at: I.receipt_signed_at, ...o }, dev);
      const c = P.signHandoffCompletion({ ...I.completion_fields, devices: I.devices, receipts: [r] }, g1);
      expect(P.verifyHandoffRecord({ ...rec(), completion: c }).ok).toBe(false);
    }
  });

  it("refuses unsorted or duplicate devices, a device whose id is not its key, and unknown members", () => {
    const sign = (fields: P.HandoffCompletionFields) => {
      const { signature } = P.signWithJwk(P.utf8.encode(P.handoffCompletionSigningInput(fields)), g1);
      return { ...fields, signature: P.base64url.encode(signature) };
    };
    const f = { ...I.completion_fields, devices: I.devices, receipts: [E.receipt] } as P.HandoffCompletionFields;
    expect(P.verifyHandoffRecord({ ...rec(), completion: sign({ ...f, devices: [...f.devices].reverse() }) }).ok).toBe(false);
    expect(P.verifyHandoffRecord({ ...rec(), completion: sign({ ...f, devices: [f.devices[0]!, f.devices[0]!] }) }).ok).toBe(false);
    expect(P.verifyHandoffRecord({ ...rec(), completion: sign({ ...f, devices: [{ ...f.devices[0]!, public_key: f.devices[1]!.public_key }] }) }).ok).toBe(false);
    expect(P.verifyHandoffRecord({ ...rec(), completion: { ...E.completion, extra: 1 } }).ok).toBe(false);
  });

  it("refuses a completion signed by the successor", () => {
    const g2 = key("ed25519");
    const c = P.signHandoffCompletion({ ...I.completion_fields, devices: I.devices, receipts: [E.receipt] }, g2);
    expect(P.verifyHandoffRecord({ ...rec(), completion: c })).toMatchObject({ ok: false, code: "completion_invalid" });
  });
});

describe("handoff arguments (§5.6.1)", () => {
  const args = I.args as P.HandoffArgs;
  it("accepts the vector's arguments and refuses each malformed variant", () => {
    expect(P.handoffArgsError(args)).toBeNull();
    const bad: unknown[] = [
      { ...args, extra: 1 },
      { ...args, successor_public_key: { ...args.successor_public_key, d: "x" } },
      { ...args, successor_public_key: { kty: "OKP", crv: "Ed25519", x: "A".repeat(43) } }, // small order / not a point
      { ...args, successor_name: "" },
      { ...args, successor_name: " padded" },
      { ...args, successor_name: "a‮b" },
      { ...args, successor_name: "x".repeat(65) },
      { ...args, ledger_seq: 0 },
      { ...args, ledger_seq: 1.5 },
      { ...args, ledger_head: "ABC" },
      { ...args, policy_hash: 7 },
      { ...args, successor_gateway_id: "gw_short" },
    ];
    for (const b of bad) expect(P.handoffArgsError(b)).not.toBeNull();
  });

  it("parseHandoffAction refuses another tool, another version, tier 2 and advisory mode", () => {
    expect(P.parseHandoffAction(E.canonical_bytes).ok).toBe(true);
    expect(P.parseHandoffAction("{}")).toMatchObject({ ok: false, code: "handoff_malformed" });
    const build = (over: Partial<P.BuildActionInput>) =>
      P.buildCanonicalAction({ tool: P.HANDOFF_TOOL, template_version: 1, args_resolved: args as unknown as Record<string, unknown>, requester: { agent: "a", session_id: "s", host: "h", gateway_id: P.gatewayIdFromJwk(g1) }, origin_hash: "0".repeat(64), tier: 3, mode: "enforce", ...over }).canonical_bytes;
    expect(P.parseHandoffAction(build({ tool: "signeto.test", template_id: "signeto.test" }))).toMatchObject({ code: "not_a_handoff" });
    expect(P.parseHandoffAction(build({ template_version: 2 }))).toMatchObject({ code: "handoff_unsupported" });
    expect(P.parseHandoffAction(build({ tier: 2 }))).toMatchObject({ code: "handoff_malformed" });
    expect(P.parseHandoffAction(build({ mode: "advisory" }))).toMatchObject({ code: "handoff_malformed" });
  });

  it("ES256 devices and gateways work the same way", () => {
    const G = key("es256");
    const S = key("es256");
    const D = key("es256");
    const a: P.HandoffArgs = { ...args, successor_gateway_id: P.gatewayIdFromJwk(S), successor_public_key: pub(S) };
    const action = P.buildHandoffAction({ predecessor_gateway_id: P.gatewayIdFromJwk(G), host: "h", args: a });
    const action_id = P.newActionId();
    const req = P.signApprovalRequest({ action_id, canonical_bytes: action.canonical_bytes, expires_at: action.action.expires_at }, G);
    const receipt = P.signReceipt({ action_id, canonical_bytes_sha256: action.canonical_bytes_sha256, decision: "approve", approver_id: "ops", device_id: P.deviceIdFromJwk(D), signed_at: P.formatTimestamp(Date.now()) }, D);
    const pin = { gateway_id: P.gatewayIdFromJwk(G), public_key: pub(G), approver_id: "ops" };
    const handoff = { action_id, canonical_bytes: action.canonical_bytes, gateway_signature: req.gateway_signature };
    const r = P.verifyHandoffForDevice({ handoff, pin, device_public_key: pub(D), receipt });
    expect(r.ok).toBe(true);
    const c = P.signHandoffCompletion(
      { action_id, canonical_bytes_sha256: action.canonical_bytes_sha256, predecessor_gateway_id: pin.gateway_id, successor_gateway_id: a.successor_gateway_id, final_seq: a.ledger_seq + 3, final_entry_hash: "1".repeat(64), completed_at: P.formatTimestamp(Date.now()), devices: [{ device_id: P.deviceIdFromJwk(D), public_key: pub(D), approver_id: "ops", attested: true, platform: "android", name: null, attestation_sha256: null }], receipts: [receipt] },
      G,
    );
    expect(P.verifyHandoffRecord({ ...handoff, predecessor_public_key: pub(G), completion: c }, { successor_gateway_id: a.successor_gateway_id }).ok).toBe(true);
  });
});
