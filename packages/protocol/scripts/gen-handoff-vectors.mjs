// Generates vectors/handoff/ (protocol.md §5.6, §9) from the built package:
//
//   pnpm --filter @signeto/protocol build
//   node public/packages/protocol/scripts/gen-handoff-vectors.mjs
//
// Ed25519 signatures are deterministic, so re-running reproduces move.json byte for byte. The ES256 signatures in
// device-cases.json (the second device) are randomised by ECDSA: re-running changes those bytes and they still verify.
// Test keys come from vectors/keys/ and MUST NOT be used elsewhere.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const P = await import(join(root, "dist", "index.js"));
const key = (name) => JSON.parse(readFileSync(join(root, "vectors", "keys", name + ".json"), "utf8"));
const pub = (jwk) => (jwk.kty === "EC" ? { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y } : { kty: "OKP", crv: jwk.crv, x: jwk.x });
const write = (name, obj) => writeFileSync(join(root, "vectors", "handoff", name), JSON.stringify(obj, null, 2) + "\n");

const g1 = key("gateway-ed25519");
const g2 = key("successor-ed25519");
const dev = key("device-ed25519");
const dev2 = key("device-es256");
const G1 = P.gatewayIdFromJwk(g1);
const G2 = P.gatewayIdFromJwk(g2);
const DEV = P.deviceIdFromJwk(dev);
const DEV2 = P.deviceIdFromJwk(dev2);
const T0 = Date.parse("2026-11-14T12:00:00.000Z");
const at = (ms) => P.formatTimestamp(T0 + ms);
const ACTION_ID = "act_01JCQ0HANDXFF5ZCCE55RS0000";
const NONCE = "SGFuZG9mZlZlY3Rvck5vbg";
const HOST = "jason-mbp";
const APPROVER = "jason";

const args = {
  successor_gateway_id: G2,
  successor_public_key: pub(g2),
  successor_name: "Signeto Cloud",
  ledger_seq: 41,
  ledger_head: P.sha256hex("vector ledger entry 41"),
  policy_hash: P.sha256hex("vector policy"),
};

/** A G1-signed §7.5 request for a canonical action (built with `build`), as a device receives it. */
const request = (action, action_id = ACTION_ID, key = g1) => {
  const r = P.signApprovalRequest({ action_id, canonical_bytes: action.canonical_bytes, expires_at: action.action.expires_at }, key);
  return { action_id, canonical_bytes: r.canonical_bytes, gateway_signature: r.gateway_signature };
};
const handoffAction = (a = args, extra = {}) => P.buildHandoffAction({ predecessor_gateway_id: G1, host: HOST, args: a, expiry_ms: 5 * 60_000, ...extra }, { now: T0, nonce: NONCE });
/** Same shape as buildHandoffAction, but without its checks, for malformed cases G1 still signs. */
const rawAction = (over) =>
  P.buildCanonicalAction(
    { tool: P.HANDOFF_TOOL, template_version: 1, args_resolved: args, requester: { agent: "signeto gateway", session_id: "handoff", host: HOST, gateway_id: G1 }, origin_hash: P.sha256hex(`handoff\n${G2}`), tier: 3, mode: "enforce", expiry_ms: 5 * 60_000, ...over },
    { now: T0, nonce: NONCE },
  );

const action = handoffAction();
const handoff = request(action);
const receiptFor = (k, o = {}) =>
  P.signReceipt(
    {
      action_id: o.action_id ?? ACTION_ID,
      canonical_bytes_sha256: o.hash ?? action.canonical_bytes_sha256,
      decision: o.decision ?? "approve",
      approver_id: o.approver_id ?? APPROVER,
      device_id: P.deviceIdFromJwk(k),
      signed_at: o.signed_at ?? at(60_000),
    },
    k,
  );
const receipt = receiptFor(dev);
const devices = [
  { device_id: DEV, public_key: pub(dev), approver_id: APPROVER, attested: true, platform: "ios", name: "iPhone 17", attestation_sha256: P.sha256hex("vector attestation") },
  { device_id: DEV2, public_key: pub(dev2), approver_id: APPROVER, attested: true, platform: "android", name: "Pixel 9", attestation_sha256: null },
];
const completionFields = {
  action_id: ACTION_ID,
  canonical_bytes_sha256: action.canonical_bytes_sha256,
  predecessor_gateway_id: G1,
  successor_gateway_id: G2,
  final_seq: 44,
  final_entry_hash: P.sha256hex("vector ledger entry 44"),
  completed_at: at(90_000),
  devices,
  receipts: [receipt],
};
const completion = P.signHandoffCompletion(completionFields, g1);
const pin = { gateway_id: G1, public_key: pub(g1), approver_id: APPROVER, templates_pinned: [{ template_id: "acme.deploy", template_version: 2, sha256: P.sha256hex("vector pinned template") }] };
const rendered = P.renderTemplate(action.canonical_bytes, P.builtinRegistries);
if (rendered.status !== "ok") throw new Error("handoff template does not render: " + JSON.stringify(rendered));
const record = { ...handoff, predecessor_public_key: pub(g1), completion };
const rec = P.verifyHandoffRecord(record, { successor_gateway_id: G2 });
if (!rec.ok) throw new Error("record does not verify: " + JSON.stringify(rec));

write("move.json", {
  description: "A gateway hands over to its successor (protocol.md §5.6): the handoff action, G1's request signature, the device's receipt, G1's completion, the rendered card and the successor pin",
  inputs: {
    predecessor_private_key: g1,
    successor_public_key: pub(g2),
    device_private_key: dev,
    action_id: ACTION_ID,
    host: HOST,
    nonce: NONCE,
    issued_at: at(0),
    expiry_ms: 5 * 60_000,
    args,
    pin,
    receipt_signed_at: receipt.signed_at,
    completion_fields: { ...completionFields, receipts: undefined, devices: undefined },
    devices,
  },
  expected: {
    canonical_bytes: action.canonical_bytes,
    canonical_bytes_sha256: action.canonical_bytes_sha256,
    request_signing_input: P.approvalRequestSigningInput(P.approvalRequestFields({ action_id: ACTION_ID, canonical_bytes: action.canonical_bytes, expires_at: action.action.expires_at })),
    handoff,
    rendered: { text: rendered.text, note: rendered.note, hidden: rendered.hidden },
    receipt_signing_input: P.receiptSigningInput({ canonical_bytes_sha256: action.canonical_bytes_sha256, decision: "approve", signed_at: receipt.signed_at }),
    receipt,
    completion_signing_input: P.handoffCompletionSigningInput(completion),
    completion,
    successor_pin: { gateway_id: G2, public_key: pub(g2), name: "Signeto Cloud", approver_id: APPROVER, templates_pinned: pin.templates_pinned, predecessor_gateway_id: G1 },
  },
});

// ---- device cases: verifyHandoffForDevice -----------------------------------------------------------------
const cases = [];
const add = (name, description, inputs, expected) => {
  const r = P.verifyHandoffForDevice(inputs);
  const got = r.ok ? { ok: true, completed: r.completed, late: r.late } : { ok: false, error: r.code };
  if (JSON.stringify(got) !== JSON.stringify(expected)) throw new Error(`${name}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)}`);
  cases.push({ name, description, inputs, expected });
};
const base = { handoff, pin, device_public_key: pub(dev), receipt };
const late = receiptFor(dev, { signed_at: at(3_600_000) });

add("approved-in-window", "own approving receipt inside the window, completion supplied", { ...base, completion }, { ok: true, completed: true, late: false });
add("approved-no-completion", "own approving receipt inside the window; the device pins the successor before the move completes", base, { ok: true, completed: false, late: false });
add("late-with-completion", "a phone that missed the window approves the completed move later; the completion names it", { ...base, receipt: late, completion }, { ok: true, completed: true, late: true });
add("late-without-completion", "a late receipt counts only with the completion", { ...base, receipt: late }, { ok: false, error: "clock_skew" });
{
  const r2 = receiptFor(dev2);
  const other = P.signHandoffCompletion({ ...completionFields, devices: [devices[1]], receipts: [r2] }, g1);
  add("late-not-listed", "a late receipt from a device the completion does not name", { ...base, receipt: late, completion: other }, { ok: false, error: "clock_skew" });
}
add("before-issue", "receipt signed more than 60 s before the handoff was issued", { ...base, receipt: receiptFor(dev, { signed_at: at(-120_000) }) }, { ok: false, error: "clock_skew" });
{
  const forged = handoffAction({ ...args, successor_name: "Attacker" });
  add("signature-over-other-bytes", "canonical bytes G1 did not sign, with G1's signature from the real handoff", { ...base, handoff: { ...handoff, canonical_bytes: forged.canonical_bytes } }, { ok: false, error: "gateway_signature_invalid" });
}
add("signed-by-successor", "the request is signed by another key than the pinned one", { ...base, handoff: request(action, ACTION_ID, g2) }, { ok: false, error: "gateway_signature_invalid" });
add("other-gateway-pin", "the device's pin is for another gateway", { ...base, pin: { ...pin, gateway_id: G2, public_key: pub(g2) } }, { ok: false, error: "gateway_not_pinned" });
{
  const merge = P.buildCanonicalAction(
    { tool: "github.merge_pull_request", template_version: 1, args_resolved: { repo: "acme/api", pr: 42, head_sha: "abc1234abc1234abc1234abc1234abc1234abc12", base: "main", method: "squash" }, requester: { agent: "claude-code", session_id: "sess_1", host: HOST, gateway_id: G1 }, origin_hash: "0".repeat(64), tier: 3, mode: "enforce" },
    { now: T0, nonce: NONCE },
  );
  const req = request(merge);
  add("not-a-handoff", "a G1-signed approval request for another tool", { ...base, handoff: req, receipt: receiptFor(dev, { hash: merge.canonical_bytes_sha256 }) }, { ok: false, error: "not_a_handoff" });
}
add("unsupported-version", "template_version 2, which this format does not define", { ...base, handoff: request(rawAction({ template_version: 2 })) }, { ok: false, error: "handoff_unsupported" });
add("tier-2", "a handoff is tier 3", { ...base, handoff: request(rawAction({ tier: 2 })) }, { ok: false, error: "handoff_malformed" });
add("extra-argument", "args_resolved has a member the format does not define", { ...base, handoff: request(rawAction({ args_resolved: { ...args, note: "x" } })) }, { ok: false, error: "handoff_malformed" });
add("successor-id-not-thumbprint", "successor_gateway_id is not the thumbprint of successor_public_key", { ...base, handoff: request(rawAction({ args_resolved: { ...args, successor_gateway_id: "gw_" + P.deviceIdFromJwk(dev).slice(4) } })) }, { ok: false, error: "successor_mismatch" });
add("successor-is-self", "a gateway handing off to itself", { ...base, handoff: request(rawAction({ args_resolved: { ...args, successor_gateway_id: G1, successor_public_key: pub(g1) } })) }, { ok: false, error: "successor_mismatch" });
add("receipt-from-other-device", "the receipt was signed by another device", { ...base, receipt: receiptFor(dev2) }, { ok: false, error: "receipt_not_own" });
add("receipt-for-other-action", "the receipt names another action_id", { ...base, receipt: receiptFor(dev, { action_id: "act_01JCQ0HANDXFF5ZCCE55RS0001" }) }, { ok: false, error: "receipt_mismatch" });
add("approver-mismatch", "the receipt names another approver than the pin", { ...base, receipt: receiptFor(dev, { approver_id: "someone-else" }) }, { ok: false, error: "approver_mismatch" });
add("denied", "the device denied the handoff", { ...base, receipt: receiptFor(dev, { decision: "deny" }) }, { ok: false, error: "handoff_not_approved" });
add("receipt-over-other-bytes", "the receipt signs another hash", { ...base, receipt: receiptFor(dev, { hash: P.sha256hex("other bytes") }) }, { ok: false, error: "hash_mismatch" });
add("bad-receipt-signature", "the receipt's signature is over another signing input", { ...base, receipt: { ...receipt, signature: receiptFor(dev, { signed_at: at(61_000) }).signature } }, { ok: false, error: "invalid_signature" });
{
  const flipped = { ...completion, final_seq: completion.final_seq + 1 };
  add("completion-altered", "the completion was changed after G1 signed it", { ...base, completion: flipped }, { ok: false, error: "completion_invalid" });
}
add("completion-not-after-head", "a completion whose final_seq is not after the handoff's ledger head", { ...base, completion: P.signHandoffCompletion({ ...completionFields, final_seq: 41 }, g1) }, { ok: false, error: "completion_invalid" });

write("device-cases.json", {
  description: "verifyHandoffForDevice (protocol.md §5.6.5): may a device that pinned G1 pin the successor? Each case gives the request, the device's pin, its public key, its own receipt and optionally G1's completion; `expected` is ok (with completed, late) or the first failing code",
  cases,
});
console.log(`wrote move.json and ${cases.length} device cases`);
