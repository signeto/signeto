// Fixtures for the SignetoSign Swift tests that the shared vectors in packages/protocol/vectors/ do not
// cover (yet): pairing (no `pairing/` vector set exists), extra JCS number/string/key-order cases, extra
// renderer cases, ES256 receipts with a reason, an ES256 gateway, and the bundled template registries.
//
// Everything is produced by the built `@signeto/protocol` package. Pairing follows protocol.md §5.2–§5.4
// using only protocol primitives (the reference handshake lives in the private gateway package; it was
// cross-checked against this output when the fixture was created).
//
//   pnpm --filter @signeto/protocol build            # from the repository root
//   node public/ios/Tests/SignetoSignTests/Fixtures/gen-fixtures.mjs
//
// Deterministic except ES256 signatures (randomised by ECDSA): re-running changes those bytes, and they
// still verify. Test keys come from packages/protocol/vectors/keys/ and MUST NOT be used elsewhere.
import { createHmac, createPrivateKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const protocolRoot = join(here, "..", "..", "..", "..", "packages", "protocol");
const P = await import(join(protocolRoot, "dist", "index.js"));
const key = (name) => JSON.parse(readFileSync(join(protocolRoot, "vectors", "keys", name + ".json"), "utf8"));
const pub = (jwk) => { const { d, ...rest } = jwk; return rest; };
const write = (name, obj) => writeFileSync(join(here, name), JSON.stringify(obj, null, 2) + "\n");

const gwKey = key("gateway-ed25519");
const devEs = key("device-es256");
const devEd = key("device-ed25519");
const gateway_id = P.gatewayIdFromJwk(gwKey);
const devEsId = P.deviceIdFromJwk(devEs);

// Seeded PRNG (xorshift32) so the non-signature output is reproducible.
let seed = 0x5197e70;
const rnd = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed; };
const rbytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);

// ---------- builtin registries (compared with Sources/SignetoSign/Resources/builtin-registries.json)
write("builtin-registries.json", P.builtinRegistries);

// ---------- numbers: IEEE 754 bit pattern → JSON.stringify / JCS text
const numbers = [];
const pushNum = (x) => {
  if (!Number.isFinite(x)) return;
  const b = Buffer.alloc(8); b.writeDoubleBE(x);
  numbers.push({ bits: b.toString("hex"), text: P.canonicalize(x) });
};
for (const x of [0, -0, 1, -1, 0.1, 0.2, 0.3, 1 / 3, 2 / 3, 1.5, 100, 1e20, 1e21, 1e-6, 1e-7, 123456789012345, 9007199254740991, 9007199254740992, -9007199254740993,
  5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, 4.35, 0.000001, 0.0000001, 123e-20, 1e300, 1.1e21, 999999999999999900000, 1e22, 0.1 + 0.2, 1234.5678, -0.0000033]) pushNum(x);
for (let i = 0; i < 2000; i++) { const b = Buffer.from(rbytes(8)); pushNum(b.readDoubleBE(0)); }
for (let i = 0; i < 1000; i++) pushNum((rnd() % 2000000 - 1000000) / 10 ** (rnd() % 12));
for (let i = 0; i < 500; i++) pushNum((rnd() * 4294967296 + rnd()) * (rnd() % 2 ? 1 : -1));
for (let e = -30; e <= 30; e++) pushNum(10 ** e), pushNum(3 * 10 ** e), pushNum(1.25 * 10 ** e);
write("numbers.json", { description: "IEEE 754 doubles (big-endian hex bits) → ECMAScript Number::toString as JCS emits it", cases: numbers });

// ---------- strings: every control character, escapes, non-BMP, U+2028/2029, DEL
const strings = [];
for (let c = 0; c < 0x20; c++) strings.push(String.fromCharCode(c));
strings.push('"', "\\", "/", "\u007f", " ", " ", "é", "é", "﻿", "😀", "😀\u0000x", "a\"b\\c\nd\te\u001bf", "", "naïve ẞ Ω 𝄞");
write("strings.json", { description: "String → JCS text (JSON.stringify escaping)", cases: strings.map((s) => ({ input: s, jcs: P.canonicalize(s) })) });

// ---------- objects: key order by UTF-16 code units (non-BMP sorts before U+E000–U+FFFF)
const objects = [
  { "￿": 1, "𐀀": 2, "": 3, "a": 4, "A": 5, "é": 6, "é": 7, "10": 8, "9": 9, "": 10 },
  { z: [3, 2, { b: null, a: true }], y: { "😀": "smile", "☺": "old" }, x: -0, w: 1e-7, v: " " },
  { "1": "one", "01": "zero-one", "-1": "minus", "1.5": "frac", "4294967295": "max+1", "4294967294": "max" },
];
write("objects.json", { description: "Pretty-printed JSON text → JCS text", cases: objects.map((o) => ({ input: JSON.stringify(o, null, 2), jcs: P.canonicalize(JSON.parse(JSON.stringify(o))) })) });

// ---------- renders
const requester = { agent: "claude-code", session_id: "sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3", host: "jason-mbp", gateway_id };
let nonceN = 0;
const mk = (tool, args, opts = {}) => P.buildCanonicalAction({ tool, template_version: opts.version ?? 1, args_resolved: args, requester, origin_hash: "0".repeat(64), tier: 3, mode: opts.mode ?? "enforce" },
  { now: Date.parse("2026-11-07T12:00:00.000Z") + nonceN, nonce: String.fromCharCode(65 + (nonceN++ % 26)).repeat(22) });
const custom = { adapter: "custom", templates: [
  { template_id: "custom.keys", template_version: 1, text: "only {name}", sha256: P.templateSha256({ text: "only {name}", elide: ["10", "9", "b", "a"] }), elide: ["10", "9", "b", "a"] },
  { template_id: "custom.values", template_version: 1, text: "obj {o} arr {a} null {n} num {x} str {s}", sha256: P.templateSha256("obj {o} arr {a} null {n} num {x} str {s}") },
  { template_id: "custom.badhash", template_version: 1, text: "x {a}", sha256: "0".repeat(64) },
  { template_id: "custom.stray", template_version: 1, text: "stray } brace {a}", sha256: P.templateSha256("stray } brace {a}") },
] };
const renderCases = [];
const rc = (description, enc, registries) => {
  const regs = registries === "builtin" ? P.builtinRegistries : registries;
  const r = P.renderTemplate(enc.canonical_bytes, regs);
  renderCases.push({ description, canonical_bytes: enc.canonical_bytes, registries, expected: r.status === "ok" ? { status: "ok", text: r.text, hidden: r.hidden } : { status: "unverified", reason: r.reason, ...(r.detail !== undefined ? { detail: r.detail } : {}) } });
};
rc("github.create_deployment with elided description", mk("github.create_deployment", { ref: "v2.0.0", environment: "production", repo: "acme/api", description: "ship it" }), "builtin");
rc("postgres.execute with unicode and newline in the statement", mk("postgres.execute", { statement_kind: "dml", database: "prod", host: "db-1", statement: "UPDATE users SET name = 'Zoë'\nWHERE id = 7;" }), "builtin");
rc("alpaca.place_order with both elided keys present", mk("alpaca.place_order", { side: "buy", qty: 10, symbol: "AAPL", type: "limit", account: "paper", notional_usd: "1912.40", limit_price: "191.24", time_in_force: "day" }), "builtin");
rc("alpaca.place_order with an unreferenced key", mk("alpaca.place_order", { side: "sell", qty: 1, symbol: "TSLA", type: "market", account: "live", notional_usd: "250.00", extended_hours: true }), "builtin");
rc("advisory mode renders the same line", mk("github.merge_pull_request", { repo: "acme/web", pr: 7, head_sha: "f".repeat(40), base: "main", method: "merge" }, { mode: "advisory" }), "builtin");
rc("hidden list follows ECMAScript key order (array-index keys first)", mk("custom.keys", { name: "n", a: 1, b: 2, "9": 3, "10": 4 }), [custom]);
rc("first unreferenced key follows ECMAScript key order", mk("custom.keys", { name: "n", zz: 1, "7": 2 }), [{ adapter: "c", templates: [{ ...custom.templates[0], elide: [], sha256: P.templateSha256("only {name}") }] }]);
rc("objects, arrays, null and numbers render as JCS text", mk("custom.values", { o: { b: [1, 2.5], a: "x" }, a: [true, null, "s"], n: null, x: 1e21, s: "plain" }), [custom]);
rc("template sha256 mismatch", mk("custom.badhash", { a: 1 }), [custom]);
rc("malformed template (stray closing brace)", mk("custom.stray", { a: 1 }), [custom]);
rc("unknown template id", mk("nobody.knows", { a: 1 }), "builtin");
renderCases.push({ description: "non-canonical bytes are action_malformed/not_canonical", canonical_bytes: JSON.stringify(JSON.parse(mk("github.merge_pull_request", { repo: "a/b", pr: 1, head_sha: "x", base: "main", method: "merge" }).canonical_bytes), null, 1), registries: "builtin", expected: { status: "unverified", reason: "action_malformed", detail: "not_canonical" } });
write("renders.json", { description: "renderTemplate cases beyond vectors/templates/ ('builtin' = @signeto/protocol builtinRegistries)", cases: renderCases });

// ---------- ES256 receipts with a reason, signed by @signeto/protocol
const merge = mk("github.merge_pull_request", { repo: "acme/api", pr: 42, head_sha: "abc1234abc1234abc1234abc1234abc1234abc12", base: "main", method: "squash" });
const ACTION_ID = "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C";
const signedAt = "2026-11-07T12:01:00.000Z";
const esDeny = P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: merge.canonical_bytes_sha256, decision: "deny", reason: "Nicht heute — 不 😀 \"quoted\"\n", approver_id: "jason", device_id: devEsId, signed_at: signedAt }, devEs);
const esApprove = P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: merge.canonical_bytes_sha256, decision: "approve", approver_id: "jason", device_id: devEsId, signed_at: signedAt }, devEs);
write("receipts-es256.json", {
  description: "ES256 receipts signed by @signeto/protocol signReceipt with vectors/keys/device-es256",
  canonical_bytes: merge.canonical_bytes, issued_at: merge.action.issued_at, expires_at: merge.action.expires_at, device_public_key: pub(devEs),
  cases: [
    { description: "deny with a unicode reason", receipt: esDeny, signing_input: P.receiptSigningInput(esDeny), verify: "ok" },
    { description: "approve, no reason", receipt: esApprove, signing_input: P.receiptSigningInput(esApprove), verify: "ok" },
    { description: "reason dropped after signing", receipt: (({ reason, ...r }) => r)(esDeny), verify: "invalid_signature" },
  ],
});

// ---------- an ES256 gateway (permitted by §5.1) signing an approval request
const esGatewayId = P.gatewayIdFromJwk(devEs);
const esReq = P.buildCanonicalAction({ tool: "github.merge_pull_request", template_version: 1, args_resolved: { repo: "acme/api", pr: 9, head_sha: "1".repeat(40), base: "main", method: "rebase" }, requester: { ...requester, gateway_id: esGatewayId }, origin_hash: "1".repeat(64), tier: 2, mode: "enforce" }, { now: Date.parse("2026-11-07T12:05:00.000Z"), nonce: "ZZZZZZZZZZZZZZZZZZZZZZ" });
const esSigned = P.signApprovalRequest({ action_id: ACTION_ID, canonical_bytes: esReq.canonical_bytes, expires_at: esReq.action.expires_at }, devEs);
write("approval-request-es256.json", { description: "Approval request signed by an ES256 gateway key (vectors/keys/device-es256 reused as a gateway key)", request: esSigned, pinned: { [esGatewayId]: pub(devEs) }, signing_input: P.approvalRequestSigningInput(P.approvalRequestFields(esSigned)) });

// ---------- pairing (protocol.md §5.2–§5.4)
const code = P.base64url.encode(Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 3));
const pairing_id = P.base64url.encode(P.sha256(P.utf8.encode(code))).slice(0, 22);
const code_hash = P.sha256hex(P.utf8.encode(code));
const qr = { v: 1, gateway_public_key: pub(gwKey), gateway_name: "home-01", relay: "https://api.signeto.dev", code, expires_at: "2026-11-07T12:10:00.000Z" };
const manual = P.base64url.encode(P.utf8.encode(P.canonicalize(qr)));
const proofInput = (device_id, device_public_key) => P.canonicalize({ device_id, device_public_key, gateway_id });
const proof = (device_id, device_public_key) => P.base64url.encode(new Uint8Array(createHmac("sha256", Buffer.from(code, "utf8")).update(Buffer.from(proofInput(device_id, device_public_key), "utf8")).digest()));
// §5.3 point 7: the gateway's local approver name for the device, inside the signed input. Deliberately not the
// relay account's approver id ("jaseinsa" below plays a relay substituting it).
const approver_id = "jason";
const confInput = (device_id, paired_at, templates_pinned, approver = approver_id) => P.canonicalize({ approver_id: approver, device_id, gateway_id, paired_at, pairing_id, templates_pinned: templates_pinned.map((t) => ({ sha256: t.sha256, template_id: t.template_id, template_version: t.template_version })) });
// The pre-approver_id signing input, for the negative "old gateway" case.
const legacyConfInput = (device_id, paired_at) => P.canonicalize({ device_id, gateway_id, paired_at, pairing_id, templates_pinned: [] });
const sign = (input, k = gwKey) => P.base64url.encode(P.signWithJwk(P.utf8.encode(input), k).signature);
const confirm = (device_id, paired_at, pins, k = gwKey) => sign(confInput(device_id, paired_at, pins), k);
const paired_at = "2026-11-07T12:02:03.456Z";
const pins = [
  { template_id: "acme.rotate_key", template_version: 3, sha256: P.templateSha256("Rotate {key} in {vault}") },
  { template_id: "acme.drop_table", template_version: 1, sha256: P.templateSha256("Drop table {table} in {db}") },
];
const c0 = confirm(devEsId, paired_at, []);
const c2 = confirm(devEsId, paired_at, pins);
const DROP = Symbol("no approver_id member");
const view = (confirmation, templates_pinned, approver = approver_id) => ({ pairing_id, status: "confirmed", device_id: devEsId, confirmation, paired_at, ...(approver !== DROP ? { approver_id: approver } : {}), ...(templates_pinned !== undefined ? { templates_pinned } : {}) });
const otherDevId = P.deviceIdFromJwk(devEd);
write("pairing.json", {
  description: "Pairing, device side: QR payload, pairing_id, code_hash, HMAC proof, claim, confirmations (approver_id, with and without template pins), and tampering negatives",
  approver_id,
  gateway_private_key_name: "gateway-ed25519",
  device_public_key: pub(devEs),
  device_id: devEsId,
  device_fingerprint: P.fingerprint(devEs),
  qr,
  qr_uri: "signeto://pair?d=" + manual,
  qr_manual: manual,
  gateway_id,
  gateway_fingerprint: P.fingerprint(gwKey),
  pairing_id,
  code_hash,
  proof_signing_input: proofInput(devEsId, pub(devEs)),
  proof: proof(devEsId, pub(devEs)),
  substituted_key_proof: proof(otherDevId, pub(devEd)),
  confirmation_signing_input_no_pins: confInput(devEsId, paired_at, []),
  confirmation_signing_input_pins: confInput(devEsId, paired_at, pins),
  pins,
  confirmations: [
    { description: "no pins, templates_pinned []", view: view(c0, []), expected: "ok", pins: [] },
    { description: "no pins, templates_pinned absent (treated as [])", view: view(c0, undefined), expected: "ok", pins: [] },
    { description: "two pins in the signed order", view: view(c2, pins), expected: "ok", pins },
    { description: "relay reordered the pins", view: view(c2, [pins[1], pins[0]]), expected: "pairing_confirmation_invalid" },
    { description: "relay dropped a pin", view: view(c2, [pins[0]]), expected: "pairing_confirmation_invalid" },
    { description: "relay dropped all pins", view: view(c2, undefined), expected: "pairing_confirmation_invalid" },
    { description: "relay added a pin", view: view(c0, [pins[0]]), expected: "pairing_confirmation_invalid" },
    { description: "relay altered a pin's sha256", view: view(c2, [{ ...pins[0], sha256: "f".repeat(64) }, pins[1]]), expected: "pairing_confirmation_invalid" },
    { description: "pin with an extra member", view: view(c2, [{ ...pins[0], elide: [] }, pins[1]]), expected: "pairing_confirmation_invalid" },
    { description: "pins not an array", view: view(c0, {}), expected: "pairing_confirmation_invalid" },
    { description: "signed by a key other than the QR's", view: view(confirm(devEsId, paired_at, [], devEd), []), expected: "pairing_confirmation_invalid" },
    { description: "paired_at altered", view: { ...view(c0, []), paired_at: "2026-11-07T12:02:03.457Z" }, expected: "pairing_confirmation_invalid" },
    { description: "confirmation for another device", view: { ...view(confirm(otherDevId, paired_at, []), []), device_id: otherDevId }, expected: "pairing_mismatch" },
    { description: "relay replaced approver_id with the account's approver id", view: view(c0, [], "jaseinsa"), expected: "pairing_confirmation_invalid" },
    { description: "relay dropped approver_id", view: view(c0, [], DROP), expected: "pairing_confirmation_invalid" },
    { description: "gateway without approver_id (pre-§5.3 point 7 confirmation)", view: view(sign(legacyConfInput(devEsId, paired_at)), [], DROP), expected: "pairing_confirmation_invalid" },
    { description: "approver_id empty", view: view(sign(confInput(devEsId, paired_at, [], "")), [], ""), expected: "pairing_confirmation_invalid" },
    { description: "approver_id not a string", view: view(c0, [], 7), expected: "pairing_confirmation_invalid" },
    { description: "approver_id longer than 64 characters", view: view(sign(confInput(devEsId, paired_at, [], "a".repeat(65))), [], "a".repeat(65)), expected: "pairing_confirmation_invalid" },
    { description: "approver_id with a control character", view: view(sign(confInput(devEsId, paired_at, [], "ja\nson")), [], "ja\nson"), expected: "pairing_confirmation_invalid" },
  ],
});
console.log("fixtures written under", here);
