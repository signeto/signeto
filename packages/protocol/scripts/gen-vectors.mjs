// Generates packages/protocol/vectors/** from the built package. Keys are test keys, generated once and committed.
// Re-running keeps existing keys; ES256 signatures are re-randomised (still valid), so commit only when intended.
import { generateKeyPairSync, createPrivateKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors");
const write = (rel, obj) => {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(obj, null, 2) + "\n");
};
const loadOrGenKey = (name, type) => {
  const p = join(root, "keys", name + ".json");
  if (existsSync(p)) return JSON.parse(readFileSync(p, "utf8"));
  const { privateKey } = type === "ES256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  write("keys/" + name + ".json", jwk);
  return jwk;
};
const pub = (jwk) => { const { d, ...rest } = jwk; return rest; };

const gwKey = loadOrGenKey("gateway-ed25519", "Ed25519");
const devEs = loadOrGenKey("device-es256", "ES256");
const devEd = loadOrGenKey("device-ed25519", "Ed25519");
const gateway_id = P.gatewayIdFromJwk(gwKey);
const devEsId = P.deviceIdFromJwk(devEs);
const devEdId = P.deviceIdFromJwk(devEd);
const ACTION_ID = "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C";

// ---------- canonical/
const requester = { agent: "claude-code", session_id: "sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3", host: "jason-mbp", gateway_id };
const mergePr = P.buildCanonicalAction({
  tool: "github.merge_pull_request", template_version: 1,
  args_resolved: { repo: "acme/api", pr: 42, head_sha: "abc1234abc1234abc1234abc1234abc1234abc12", base: "main", method: "squash" },
  requester, origin_hash: P.originHash.mcp("sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3", "toolu_01ABC"), tier: 3, mode: "enforce",
}, { now: Date.parse("2026-11-05T18:04:09.123Z"), nonce: "AAAAAAAAAAAAAAAAAAAAAA" });
const vec = (description, enc, extra = {}) => ({
  description, inputs: { action: enc.action },
  expected: { canonical_bytes: enc.canonical_bytes, canonical_bytes_sha256: enc.canonical_bytes_sha256, idempotency_key: enc.action.idempotency_key, ...extra },
});
write("canonical/merge-pr.json", vec("github.merge_pull_request, tier 3, enforce, no batch (protocol.md §9.1)", mergePr, {
  rendered: "Merge PR #42 into main on acme/api (squash) at abc1234abc1234abc1234abc1234abc1234abc12",
}));
const unicode = P.buildCanonicalAction({
  tool: "postgres.execute", template_version: 1,
  args_resolved: {
    statement_kind: "ddl", database: "prod", host: "db-1",
    statement: "COMMENT ON TABLE users IS 'naïve \"quoted\" \\ back\tslash\nnewline 😀 \u001b';",
    numbers: [0, -0, 1, 1.5, 1e21, 1e-7, 123456789012345, 0.1, 100000000000000000000],
    nested: { z: null, a: [true, false, { "é": "e", "E": 1, "e": 2, "ẞ": 3 }], "": "empty key" },
  },
  requester, origin_hash: P.originHash.hook({ tool_name: "Bash", tool_input: { command: "psql -f migrate.sql" } }), tier: 3, mode: "advisory",
}, { now: Date.parse("2026-11-05T18:10:00.000Z"), nonce: "BBBBBBBBBBBBBBBBBBBBBB" });
write("canonical/unicode-numbers-ordering.json", vec("Unicode escaping, number formatting, nested arrays/objects, UTF-16 key ordering, advisory mode", unicode));
const batch = P.buildCanonicalAction({
  tool: "cloudflare.delete_record", template_version: 1,
  args_resolved: { zone: "acme.com", name: "api.acme.com", type: "A", content: "203.0.113.9" },
  requester, origin_hash: P.originHash.ci("run_7781", "job_2"), tier: 2, mode: "enforce",
  batch: { batch_id: "CCCCCCCCCCCCCCCCCCCCCC", batch_index: 1, atomic: true },
  effective_at: Date.parse("2026-11-05T18:30:00.000Z"), expiry_ms: 5 * 60_000,
}, { now: Date.parse("2026-11-05T18:20:00.000Z"), nonce: "DDDDDDDDDDDDDDDDDDDDDD" });
write("canonical/batch-effective-at.json", vec("Batch step with atomic flag, effective_at (cooling-off), 5-minute expiry, CI origin", batch));

// ---------- canonical-invalid/
const inv = (name, description, mutate, expected_error) => {
  const a = JSON.parse(JSON.stringify(mergePr.action));
  const bytes = mutate(a);
  write("canonical-invalid/" + name + ".json", { description, inputs: { canonical_bytes: bytes ?? P.canonicalize(a) }, expected_error });
};
inv("extra-top-level-key", "Unknown top-level member", (a) => { a.summary = "Merge it"; }, "action_malformed");
inv("bad-timestamp", "Timestamp without fractional digits", (a) => { a.issued_at = "2026-11-05T18:04:09Z"; }, "action_malformed");
inv("expiry-too-long", "expires_at more than 5 minutes after issued_at", (a) => { a.expires_at = "2026-11-05T18:09:09.124Z"; }, "action_malformed");
inv("tier-4", "tier outside 1..3", (a) => { a.tier = 4; }, "action_malformed");
inv("batch-index-without-batch-id", "batch_index present without batch_id", (a) => { a.batch_index = 0; }, "action_malformed");
inv("not-canonical-whitespace", "Valid object, bytes contain whitespace", () => JSON.stringify(mergePr.action, null, 1), "not_canonical");
inv("not-canonical-key-order", "Valid object, members not in JCS order", () => { const s = JSON.stringify(mergePr.action); return s; }, "not_canonical");
inv("idempotency-key-mismatch", "idempotency_key does not match the hashed members", (a) => { a.idempotency_key = "0".repeat(64); }, "idempotency_key_mismatch");
inv("protocol-major-unsupported", "protocol_version MAJOR 2", (a) => { a.protocol_version = "2.0"; }, "protocol_version_unsupported");

// ---------- templates/
const regs = P.builtinRegistries;
const tv = (name, description, bytes, registries, expected) => write("templates/" + name + ".json", { description, inputs: { canonical_bytes: bytes, registries }, expected });
const testReg = { adapter: "test", templates: [
  { template_id: "test.braces", template_version: 1, text: "Literal {{braces}} around {name} and {{{name}}}", sha256: P.templateSha256("Literal {{braces}} around {name} and {{{name}}}") },
  { template_id: "test.nested", template_version: 1, text: "{order.side} {order.qty} {order.symbol}; first file {files.0}; flag {flag}; n {n}", sha256: P.templateSha256("{order.side} {order.qty} {order.symbol}; first file {files.0}; flag {flag}; n {n}") },
  { template_id: "test.elide", template_version: 1, text: "Deploy {ref} to {environment}", sha256: P.templateSha256("Deploy {ref} to {environment}"), elide: ["description", "auto_merge"] },
]};
const mk = (tool, template_id, args, now, nonce, tv_ = 1) => P.buildCanonicalAction({ tool, template_id, template_version: tv_, args_resolved: args, requester, origin_hash: "0".repeat(64), tier: 2, mode: "enforce" }, { now, nonce }).canonical_bytes;
tv("merge-pr-ok", "Builtin github template renders", mergePr.canonical_bytes, regs, { status: "ok", text: "Merge PR #42 into main on acme/api (squash) at abc1234abc1234abc1234abc1234abc1234abc12", hidden: [] });
tv("escaped-braces", "{{ and }} render as literal braces", mk("test.braces", "test.braces", { name: "x" }, 1, "EEEEEEEEEEEEEEEEEEEEEE"), [testReg], { status: "ok", text: "Literal {braces} around x and {x}", hidden: [] });
tv("nested-array-number-bool", "Dotted paths, array index, number/boolean rendered as JCS text", mk("test.nested", "test.nested", { order: { side: "buy", qty: 10, symbol: "AAPL" }, files: ["a.txt", "b.txt"], flag: true, n: 1.5 }, 2, "FFFFFFFFFFFFFFFFFFFFFF"), [testReg], { status: "ok", text: "buy 10 AAPL; first file a.txt; flag true; n 1.5", hidden: [] });
tv("elide-hidden", "Elided keys are reported as hidden, not unverified", mk("test.elide", "test.elide", { ref: "v1.2.0", environment: "production", description: "hotfix" }, 3, "GGGGGGGGGGGGGGGGGGGGGG"), [testReg], { status: "ok", text: "Deploy v1.2.0 to production", hidden: ["description"] });
tv("unreferenced-key", "args_resolved key no placeholder mentions → unverified", mk("test.elide", "test.elide", { ref: "v1.2.0", environment: "production", force: true }, 4, "HHHHHHHHHHHHHHHHHHHHHH"), [testReg], { status: "unverified", reason: "unreferenced_key", detail: "force" });
tv("unresolved-placeholder", "Placeholder path missing from args_resolved → unverified", mk("test.nested", "test.nested", { order: { side: "buy" }, files: [], flag: true, n: 1 }, 5, "JJJJJJJJJJJJJJJJJJJJJJ"), [testReg], { status: "unverified", reason: "unresolved_placeholder", detail: "order.qty" });
tv("unknown-template-version", "template_version 2 not in registry → unverified", mk("github.merge_pull_request", "github.merge_pull_request", { repo: "acme/api", pr: 1, head_sha: "x", base: "main", method: "merge" }, 6, "KKKKKKKKKKKKKKKKKKKKKK", 2), regs, { status: "unverified", reason: "unknown_template" });

// ---------- receipts/signing-input/
const h = mergePr.canonical_bytes_sha256;
const siWith = P.receiptSigningInput({ canonical_bytes_sha256: h, decision: "deny", reason: "Not during market hours", signed_at: "2026-11-05T18:05:00.000Z" });
const siWithout = P.receiptSigningInput({ canonical_bytes_sha256: h, decision: "approve", signed_at: "2026-11-05T18:05:00.000Z" });
write("receipts/signing-input/with-reason.json", { description: "Signing input with reason", inputs: { canonical_bytes_sha256: h, decision: "deny", reason: "Not during market hours", signed_at: "2026-11-05T18:05:00.000Z" }, expected: { signing_input: siWith, webauthn_challenge: P.base64url.encode(P.webauthnChallenge(siWith)) } });
write("receipts/signing-input/without-reason.json", { description: "Signing input without reason (member omitted)", inputs: { canonical_bytes_sha256: h, decision: "approve", signed_at: "2026-11-05T18:05:00.000Z" }, expected: { signing_input: siWithout, webauthn_challenge: P.base64url.encode(P.webauthnChallenge(siWithout)) } });

// ---------- receipts/
const actionCtx = { canonical_bytes: mergePr.canonical_bytes, issued_at: mergePr.action.issued_at, expires_at: mergePr.action.expires_at };
const rv = (name, description, receipt, device_public_key, expected, extra = {}) =>
  write("receipts/" + name + ".json", { description, inputs: { ...actionCtx, device_public_key, receipt, ...extra }, expected });
const esApprove = P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: h, decision: "approve", approver_id: "jason", device_id: devEsId, signed_at: "2026-11-05T18:05:00.000Z" }, devEs);
const edDeny = P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: h, decision: "deny", reason: "Not during market hours", approver_id: "jason", device_id: devEdId, signed_at: "2026-11-05T18:05:00.000Z" }, devEd);
rv("es256-approve", "ES256 software key, approve, no reason", esApprove, pub(devEs), { verify: "ok" });
rv("ed25519-deny", "Ed25519 software key, deny with reason (protocol.md §9.2)", edDeny, pub(devEd), { verify: "ok", signing_input: siWith, resulting_status: "denied", agent_sees: "Not during market hours" });
rv("tampered-decision", "deny flipped to approve without re-signing", { ...edDeny, decision: "approve" }, pub(devEd), { verify: "error", code: "invalid_signature" });
rv("tampered-reason", "reason altered after signing", { ...edDeny, reason: "Approved after all" }, pub(devEd), { verify: "error", code: "invalid_signature" });
rv("hash-mismatch", "receipt hash differs from the gateway's bytes", { ...esApprove, canonical_bytes_sha256: "1".repeat(64) }, pub(devEs), { verify: "error", code: "hash_mismatch" });
rv("clock-skew-late", "signed_at more than 60 s after expires_at", P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: h, decision: "approve", approver_id: "jason", device_id: devEsId, signed_at: "2026-11-05T18:08:09.124Z" }, devEs), pub(devEs), { verify: "error", code: "clock_skew" });
rv("clock-skew-early", "signed_at more than 60 s before issued_at", P.signReceipt({ action_id: ACTION_ID, canonical_bytes_sha256: h, decision: "approve", approver_id: "jason", device_id: devEsId, signed_at: "2026-11-05T18:03:09.122Z" }, devEs), pub(devEs), { verify: "error", code: "clock_skew" });
rv("alg-not-allowed", "alg says Ed25519 but pinned key is P-256", { ...esApprove, alg: "Ed25519" }, pub(devEs), { verify: "error", code: "alg_not_allowed" });
rv("wrong-key", "Valid Ed25519 receipt verified against a different Ed25519 key", edDeny, pub(gwKey), { verify: "error", code: "invalid_signature" });
rv("receipt-malformed-extra-field", "Unknown member in receipt", { ...esApprove, summary: "ok" }, pub(devEs), { verify: "error", code: "receipt_malformed" });
rv("receipt-malformed-reason-too-long", "reason over 512 bytes", { ...esApprove, reason: "x".repeat(513) }, pub(devEs), { verify: "error", code: "receipt_malformed" });
rv("receipt-version-unsupported", "receipt_version MAJOR 2", { ...esApprove, receipt_version: "2.0" }, pub(devEs), { verify: "error", code: "receipt_version_unsupported" });

// WebAuthn
const rpId = "approve.signeto.dev";
const origin = "https://approve.signeto.dev";
const waPolicy = { allowed_origins: [origin], rp_id: rpId, require_user_verified: true };
const mkWebAuthn = ({ type = "webauthn.get", challenge, origin: o = origin, rp = rpId, flags = 0x05, key = devEs } = {}) => {
  const authData = P.sha256(rp);
  const ad = new Uint8Array(37); ad.set(authData, 0); ad[32] = flags; // counter 0
  const cdj = P.utf8.encode(JSON.stringify({ type, challenge, origin: o, crossOrigin: false }));
  const data = new Uint8Array([...ad, ...P.sha256(cdj)]);
  const sig = P.signRaw("ES256", data, createPrivateKey({ key, format: "jwk" }));
  return { authenticator_data: P.base64url.encode(ad), client_data_json: P.base64url.encode(cdj), signature: P.base64url.encode(sig) };
};
const waFields = { action_id: ACTION_ID, canonical_bytes_sha256: h, decision: "approve", approver_id: "jason", device_id: devEsId, signed_at: "2026-11-05T18:05:30.000Z" };
const waSi = P.receiptSigningInput(waFields);
const goodChallenge = P.base64url.encode(P.webauthnChallenge(waSi));
const waReceipt = (w) => ({ receipt_version: "1.0", ...waFields, alg: "ES256", signature: w.signature, webauthn: { authenticator_data: w.authenticator_data, client_data_json: w.client_data_json } });
rv("webauthn-approve", "WebAuthn assertion, challenge = SHA-256(signing input), UP+UV", waReceipt(mkWebAuthn({ challenge: goodChallenge })), pub(devEs), { verify: "ok", signing_input: waSi }, { webauthn_policy: waPolicy });
rv("webauthn-wrong-origin", "Assertion from an origin not in the allow-list", waReceipt(mkWebAuthn({ challenge: goodChallenge, origin: "https://evil.example" })), pub(devEs), { verify: "error", code: "webauthn_origin" }, { webauthn_policy: waPolicy });
rv("webauthn-wrong-challenge", "Challenge is the hash of a different signing input", waReceipt(mkWebAuthn({ challenge: P.base64url.encode(P.webauthnChallenge(siWithout)) })), pub(devEs), { verify: "error", code: "webauthn_challenge" }, { webauthn_policy: waPolicy });
rv("webauthn-wrong-type", "clientDataJSON.type is webauthn.create", waReceipt(mkWebAuthn({ challenge: goodChallenge, type: "webauthn.create" })), pub(devEs), { verify: "error", code: "webauthn_type" }, { webauthn_policy: waPolicy });
rv("webauthn-empty-allowlist", "Default empty allow-list rejects every WebAuthn receipt", waReceipt(mkWebAuthn({ challenge: goodChallenge })), pub(devEs), { verify: "error", code: "webauthn_origin" }, { webauthn_policy: { ...waPolicy, allowed_origins: [] } });
rv("webauthn-no-uv-tier3", "User-verified flag missing when required", waReceipt(mkWebAuthn({ challenge: goodChallenge, flags: 0x01 })), pub(devEs), { verify: "error", code: "webauthn_user_flags" }, { webauthn_policy: waPolicy });
rv("webauthn-wrong-alg", "webauthn block with alg Ed25519 is malformed", { ...waReceipt(mkWebAuthn({ challenge: goodChallenge })), alg: "Ed25519" }, pub(devEs), { verify: "error", code: "receipt_malformed" }, { webauthn_policy: waPolicy });

// ---------- approval-request/
const reqBody = { action_id: ACTION_ID, canonical_bytes: mergePr.canonical_bytes, expires_at: mergePr.action.expires_at, targets: { tier: 3, approver_ids: ["jason"], device_ids: [] } };
const signed = P.signApprovalRequest(reqBody, gwKey);
const fields = P.approvalRequestFields(reqBody);
write("approval-request/ok.json", { description: "Gateway-signed request verifies against the pinned gateway key", inputs: { request: signed, pinned: { [gateway_id]: pub(gwKey) } }, expected: { signing_input: P.approvalRequestSigningInput(fields), verify: "ok" } });
write("approval-request/altered-expires-at.json", { description: "expires_at changed in transit", inputs: { request: { ...signed, expires_at: "2026-11-05T18:08:09.123Z" }, pinned: { [gateway_id]: pub(gwKey) } }, expected: { verify: "error", code: "request_malformed" } });
write("approval-request/altered-bytes.json", { description: "canonical_bytes swapped for another valid action", inputs: { request: { ...signed, canonical_bytes: unicode.canonical_bytes, expires_at: unicode.action.expires_at }, pinned: { [gateway_id]: pub(gwKey) } }, expected: { verify: "error", code: "gateway_signature_invalid" } });
write("approval-request/unpinned-gateway.json", { description: "gateway_id not pinned on the device", inputs: { request: signed, pinned: {} }, expected: { verify: "error", code: "gateway_not_pinned" } });

// ---------- relay-auth/ (protocol.md §7.1)
const raTs = "2026-11-05T18:04:10.000Z";
const raNow = Date.parse(raTs) + 5_000;
const ra = (name, description, inputs, expected) => write("relay-auth/" + name + ".json", { description, inputs, expected });
const raPost = { scheme: "Signeto-Gateway", method: "POST", path: "/v1/approvals", ts: raTs, body: JSON.stringify(signed) };
const raPostHeader = P.signRelayRequest(raPost, gwKey);
const raPostIn = { header: raPostHeader, method: raPost.method, path: raPost.path, body: raPost.body, public_key: pub(gwKey), now: raNow };
const raPostSi = P.relayAuthSigningInput({ method: raPost.method, path: raPost.path, ts: raTs, body_sha256: P.relayBodySha256(raPost.body) });
ra("gateway-post-with-body", "Signeto-Gateway, Ed25519, POST with a JSON body (deterministic header)",
  { ...raPostIn, scheme: raPost.scheme, ts: raTs, private_key: "gateway-ed25519" },
  { body_sha256: P.relayBodySha256(raPost.body), signing_input: raPostSi, header: raPostHeader, key_id: gateway_id, verify: "ok" });
const raGet = { scheme: "Signeto-Gateway", method: "GET", path: `/v1/gateways/${gateway_id}/events?since=41&wait=30`, ts: raTs, body: null };
const raGetHeader = P.signRelayRequest(raGet, gwKey);
ra("gateway-get-without-body", "Signeto-Gateway, GET with a query string and no body: body_sha256 is SHA-256 of the empty string, path includes the query",
  { header: raGetHeader, method: raGet.method, path: raGet.path, body: null, public_key: pub(gwKey), now: raNow, scheme: raGet.scheme, ts: raTs, private_key: "gateway-ed25519" },
  { body_sha256: P.EMPTY_BODY_SHA256, signing_input: P.relayAuthSigningInput({ method: "GET", path: raGet.path, ts: raTs, body_sha256: P.EMPTY_BODY_SHA256 }), header: raGetHeader, key_id: gateway_id, verify: "ok" });
const raDev = { scheme: "Signeto-Device", method: "POST", path: "/v1/approvals/apr_01JBXK4Q9R2T4V6W8Y0Z1A3B5D/receipt", ts: raTs, body: JSON.stringify(esApprove) };
const raDevHeader = P.signRelayRequest(raDev, devEs);
ra("device-es256-post-with-body", "Signeto-Device, ES256 (signature is randomised: verify it, do not compare the header)",
  { header: raDevHeader, method: raDev.method, path: raDev.path, body: raDev.body, public_key: pub(devEs), now: raNow, scheme: raDev.scheme, ts: raTs },
  { body_sha256: P.relayBodySha256(raDev.body), signing_input: P.relayAuthSigningInput({ method: raDev.method, path: raDev.path, ts: raTs, body_sha256: P.relayBodySha256(raDev.body) }), key_id: devEsId, verify: "ok" });
ra("expired-ts", "ts 61 s behind the relay clock", { ...raPostIn, now: Date.parse(raTs) + 61_000 }, { verify: "error", code: "clock_skew" });
ra("future-ts", "ts 61 s ahead of the relay clock", { ...raPostIn, now: Date.parse(raTs) - 61_000 }, { verify: "error", code: "clock_skew" });
ra("edge-of-window", "ts exactly 60 s behind the relay clock is accepted", { ...raPostIn, now: Date.parse(raTs) + 60_000 }, { verify: "ok" });
ra("wrong-key", "Header verified against a key whose thumbprint is not the header's key id", { ...raPostIn, public_key: pub(devEd) }, { verify: "error", code: "key_mismatch" });
ra("tampered-body", "Body altered after signing", { ...raPostIn, body: raPost.body.replace("jason", "mallory") }, { verify: "error", code: "invalid_signature" });
ra("altered-query", "Query string altered after signing (path covers the query)", { header: raGetHeader, method: "GET", path: raGet.path.replace("since=41", "since=0"), body: null, public_key: pub(gwKey), now: raNow }, { verify: "error", code: "invalid_signature" });
ra("altered-method", "Same path and body, different method", { ...raPostIn, method: "PUT" }, { verify: "error", code: "invalid_signature" });
ra("device-id-under-gateway-scheme", "Signeto-Gateway scheme carrying a dev_ id is malformed", { ...raPostIn, header: raPostHeader.replace(gateway_id, devEdId) }, { verify: "error", code: "auth_malformed" });

// ---------- ids/
write("ids/thumbprints.json", { description: "RFC 7638 thumbprints → gw_/dev_ ids and human fingerprints", inputs: { gateway: pub(gwKey), device_es256: pub(devEs), device_ed25519: pub(devEd) }, expected: { gateway_id, device_es256_id: devEsId, device_ed25519_id: devEdId, gateway_fingerprint: P.fingerprint(gwKey), device_es256_fingerprint: P.fingerprint(devEs) } });
console.log("vectors written under", root);
