// Generates packages/protocol/vectors/** from the built package. Keys are test keys, generated once and committed.
// Re-running keeps existing keys; ES256 signatures are re-randomised (still valid), so commit only when intended.
import { generateKeyPairSync, createPrivateKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors");
// Invisible and bidi characters are written as JSON \u escapes so the vector files show what they contain.
const INVISIBLE = /[\u007f-\u00a0\u061c\u200a-\u200f\u2028-\u202e\u2060-\u206a\ufeff]/g;
const write = (rel, obj) => {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(obj, null, 2).replace(INVISIBLE, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")) + "\n");
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
  { template_id: "test.elide", template_version: 1, text: "Deploy {ref} to {environment}", sha256: P.templateSha256({ text: "Deploy {ref} to {environment}", elide: ["description", "auto_merge"] }), elide: ["description", "auto_merge"] },
]};
const mk = (tool, template_id, args, now, nonce, tv_ = 1) => P.buildCanonicalAction({ tool, template_id, template_version: tv_, args_resolved: args, requester, origin_hash: "0".repeat(64), tier: 2, mode: "enforce" }, { now, nonce }).canonical_bytes;
tv("merge-pr-ok", "Builtin github template renders", mergePr.canonical_bytes, regs, { status: "ok", text: "Merge PR #42 into main on acme/api (squash) at abc1234abc1234abc1234abc1234abc1234abc12", hidden: [] });
tv("escaped-braces", "{{ and }} render as literal braces", mk("test.braces", "test.braces", { name: "x" }, 1, "EEEEEEEEEEEEEEEEEEEEEE"), [testReg], { status: "ok", text: "Literal {braces} around x and {x}", hidden: [] });
tv("nested-array-number-bool", "Dotted paths, array index, number/boolean rendered as JCS text", mk("test.nested", "test.nested", { order: { side: "buy", qty: 10, symbol: "AAPL" }, files: ["a.txt"], flag: true, n: 1.5 }, 2, "FFFFFFFFFFFFFFFFFFFFFF"), [testReg], { status: "ok", text: "buy 10 AAPL; first file a.txt; flag true; n 1.5", hidden: [] });
// §3.4 nested (SIG-92 N9): every leaf under a placeholder, not only every top-level key.
tv("nested-unreferenced-key", "A nested member no placeholder covers (order.limit_price) → unverified, detail is its dotted path", mk("test.nested", "test.nested", { order: { side: "buy", qty: 10, symbol: "AAPL", limit_price: "999.00" }, files: ["a.txt"], flag: true, n: 1.5 }, 9, "PPPPPPPPPPPPPPPPPPPPPP"), [testReg], { status: "unverified", reason: "unreferenced_key", detail: "order.limit_price" });
tv("array-unreferenced-element", "An array element no placeholder covers (files.1) → unverified", mk("test.nested", "test.nested", { order: { side: "buy", qty: 10, symbol: "AAPL" }, files: ["a.txt", "b.txt"], flag: true, n: 1.5 }, 10, "QQQQQQQQQQQQQQQQQQQQQQ"), [testReg], { status: "unverified", reason: "unreferenced_key", detail: "files.1" });
{
  const wholeText = "Order {order}; files {files}";
  const wholeReg = { adapter: "test", templates: [{ template_id: "test.whole", template_version: 1, text: wholeText, sha256: P.templateSha256(wholeText) }] };
  tv("whole-object-placeholder", "A placeholder naming an object or array covers everything beneath it (rendered as JCS)", mk("test.whole", "test.whole", { order: { side: "buy", limit_price: "999.00", tif: { kind: "gtc" } }, files: ["a.txt", "b.txt"] }, 11, "RRRRRRRRRRRRRRRRRRRRRR"), [wholeReg],
    { status: "ok", text: 'Order {"limit_price":"999.00","side":"buy","tif":{"kind":"gtc"}}; files ["a.txt","b.txt"]', hidden: [] });
  tv("empty-object-is-a-leaf", "An empty object no placeholder covers is itself unreferenced", mk("test.whole", "test.whole", { order: {}, files: [], extra: {} }, 12, "SSSSSSSSSSSSSSSSSSSSSS"), [wholeReg], { status: "unverified", reason: "unreferenced_key", detail: "extra" });
}
tv("alpaca-place-order-v2", "alpaca.place_order v2 shows limit_price and time_in_force in the sentence (v1 elided them)",
  mk("alpaca.place_order", "alpaca.place_order", { side: "buy", qty: 10, symbol: "AAPL", type: "limit", limit_price: "189.50", time_in_force: "day", account: "paper", notional_usd: "1895.00" }, 13, "TTTTTTTTTTTTTTTTTTTTTT", 2), regs,
  { status: "ok", text: "Place order: buy 10 AAPL limit, limit price 189.50, time in force day, on paper (notional 1895.00 USD)", hidden: [] });
tv("elide-hidden", "Elided keys are reported as hidden, not unverified", mk("test.elide", "test.elide", { ref: "v1.2.0", environment: "production", description: "hotfix" }, 3, "GGGGGGGGGGGGGGGGGGGGGG"), [testReg], { status: "ok", text: "Deploy v1.2.0 to production", hidden: ["description"] });
tv("unreferenced-key", "args_resolved key no placeholder mentions → unverified", mk("test.elide", "test.elide", { ref: "v1.2.0", environment: "production", force: true }, 4, "HHHHHHHHHHHHHHHHHHHHHH"), [testReg], { status: "unverified", reason: "unreferenced_key", detail: "force" });
tv("unresolved-placeholder", "Placeholder path missing from args_resolved → unverified", mk("test.nested", "test.nested", { order: { side: "buy" }, files: [], flag: true, n: 1 }, 5, "JJJJJJJJJJJJJJJJJJJJJJ"), [testReg], { status: "unverified", reason: "unresolved_placeholder", detail: "order.qty" });
{
  // elide widens what the card hides, so it is in the hash (§3.1): a relay cannot add a key to a pinned text-only template_source
  const text = "Deploy {ref} to {environment}";
  const bytes = mk("test.pinned_deploy", "test.pinned_deploy", { ref: "v1.2.0", environment: "production", force: true }, 7, "MMMMMMMMMMMMMMMMMMMMMM");
  tv("elide-added-after-hashing", "elide added to a template hashed (and pinned) as text-only → template_hash_mismatch", bytes,
    [{ adapter: "pinned", templates: [{ template_id: "test.pinned_deploy", template_version: 1, text, sha256: P.templateSha256(text), elide: ["force"] }] }], { status: "unverified", reason: "template_hash_mismatch" });
  tv("elide-hashed", "The same template with elide hashed (and pinned) with it renders, the key hidden", bytes,
    [{ adapter: "pinned", templates: [{ template_id: "test.pinned_deploy", template_version: 1, text, sha256: P.templateSha256({ text, elide: ["force"] }), elide: ["force"] }] }], { status: "ok", text: "Deploy v1.2.0 to production", hidden: ["force"] });
}
tv("unknown-template-version", "template_version 3 not in registry → unverified", mk("github.merge_pull_request", "github.merge_pull_request", { repo: "acme/api", pr: 1, head_sha: "x", base: "main", method: "merge" }, 6, "KKKKKKKKKKKKKKKKKKKKKK", 3), regs, { status: "unverified", reason: "unknown_template" });

{
  // §3.6: the rendered line shows control, bidi and invisible characters of a value as escapes.
  const text = "Merge {branch} as {who}";
  const escReg = { adapter: "test", templates: [{ template_id: "test.escape", template_version: 1, text, sha256: P.templateSha256(text) }] };
  const bytes = mk("test.escape", "test.escape", { branch: "dev\u001b[2K\rmain", who: "a\u202eb\nc\u200bd\tz\u0085\u007f\\n" }, 8, "NNNNNNNNNNNNNNNNNNNNNN");
  tv("escape-controls-in-value", "§3.6: ESC, CR, LF, TAB, NEL, DEL, RLO and ZWSP in values render as escapes; a literal backslash stays", bytes, [escReg],
    { status: "ok", text: "Merge dev\\u{1B}[2K\\rmain as a\\u{202E}b\\nc\\u{200B}d\\tz\\u{85}\\u{7F}\\n", hidden: [] });
}

// ---------- display-escape/ (§3.6). Expected values are written out by hand, not computed with displayEscape.
const dv = (name, description, value, escaped) => write("display-escape/" + name + ".json", { description, inputs: { value }, expected: { escaped } });
dv("plain", "Printable ASCII, Latin-1 letters, NBSP, emoji and combining marks are unchanged", "claude-code naïve\u00a0x 😀 e\u0301 ‰ \u200a\u206a", "claude-code naïve\u00a0x 😀 e\u0301 ‰ \u200a\u206a");
dv("backslash-unchanged", "A backslash is not escaped: the rule is not injective, the raw bytes view is authoritative", "C:\\dir\\n \\u{1B}", "C:\\dir\\n \\u{1B}");
dv("ansi-cursor", "The SIG-92 M6 agent name: ESC sequences, CR", "cc\u001b[3A\r\u001b[2K│ Merge PR #12\u001b[3B\r", "cc\\u{1B}[3A\\r\\u{1B}[2K│ Merge PR #12\\u{1B}[3B\\r");
dv("newline-tab", "LF, CR and TAB use the short escapes", "line1\nline2\r\n\tx", "line1\\nline2\\r\\n\\tx");
dv("c0-del-c1", "Every other C0, DEL and C1 as \\u{XX}, uppercase, at least two digits", "\u0000\u0001\u0008\u000b\u000c\u001f\u007f\u0080\u0085\u009b\u009f\u00a0", "\\u{00}\\u{01}\\u{08}\\u{0B}\\u{0C}\\u{1F}\\u{7F}\\u{80}\\u{85}\\u{9B}\\u{9F}\u00a0");
dv("bidi", "ALM, LRM, RLM, LRE..RLO, LRI..PDI", "a\u061cb\u200ec\u200fd\u202ae\u202bf\u202cg\u202dh\u202ei\u2066j\u2067k\u2068l\u2069m", "a\\u{61C}b\\u{200E}c\\u{200F}d\\u{202A}e\\u{202B}f\\u{202C}g\\u{202D}h\\u{202E}i\\u{2066}j\\u{2067}k\\u{2068}l\\u{2069}m");
dv("invisible-and-separators", "ZWSP, ZWNJ, ZWJ, LINE/PARAGRAPH SEPARATOR, WORD JOINER, invisible operators, BOM", "ma\u200bin\u200c\u200d\u2028\u2029\u2060\u2061\u2064\u2065\ufeff!", "ma\\u{200B}in\\u{200C}\\u{200D}\\u{2028}\\u{2029}\\u{2060}\\u{2061}\\u{2064}\\u{2065}\\u{FEFF}!");
dv("rlo-filename", "The classic extension spoof", "invoice\u202egpj.exe", "invoice\\u{202E}gpj.exe");
dv("empty", "Empty string", "", "");

// ---------- links/ (§3.5 review links, §3.2 note and :short) and template-sha256/ (§3.1)
// Expected values are written out by hand; vectors.test.ts and the Swift VectorTests check both renderers against them.
const tpl = (template_id, text, extra = {}) => {
  const body = { text, ...extra };
  return { template_id, template_version: 1, text, sha256: P.templateSha256(body), ...extra };
};
const HOSTS = { link_hosts: ["example.com"] };
const injectReg = { adapter: "test", templates: [
  tpl("test.inject", "{v}", { links: [
    { label: "plain", url: "https://example.com/p/{v}" },
    { label: "path", url: "https://example.com/{v:path}/end" },
    { label: "query", url: "https://example.com/s?q={v}#top" },
  ], ...HOSTS }),
] };
let ln = 0;
const lmk = (template_id, args) => mk(template_id, template_id, args, 1000 + ln, String.fromCharCode(65 + (ln++ % 26)).repeat(22));
const lv = (name, description, bytes, registries, expected) => write("links/" + name + ".json", { description, inputs: { canonical_bytes: bytes, registries }, expected });
const okv = (text, links, extra = {}) => ({ status: "ok", text, hidden: [], ...extra, links });
const L = (label, url) => ({ label, url });
const three = (v, plain, path, query) => [
  ...(plain ? [L("plain", `https://example.com/p/${plain}`)] : []),
  ...(path ? [L("path", `https://example.com/${path}/end`)] : []),
  ...(query ? [L("query", `https://example.com/s?q=${query}#top`)] : []),
];
const inject = (name, description, v, text, plain, path, query) =>
  lv(name, description, lmk("test.inject", { v }), [injectReg], okv(text, three(v, plain, path, query)));

// good cases
lv("github-merge-pr-v2", "Builtin github.merge_pull_request v2: note with {head_sha:short}, three github.com links, {repo:path}",
  P.buildCanonicalAction({ tool: "github.merge_pull_request", template_version: 2, args_resolved: { repo: "acme/api", pr: 42, head_sha: "abc1234abc1234abc1234abc1234abc1234abc12", base: "main", method: "squash" }, requester, origin_hash: "0".repeat(64), tier: 3, mode: "enforce" }, { now: Date.parse("2026-11-07T12:00:00.000Z"), nonce: "LLLLLLLLLLLLLLLLLLLLLL" }).canonical_bytes,
  regs, okv("Merge PR #42 into main on acme/api (squash) at abc1234abc1234abc1234abc1234abc1234abc12", [
    L("View pull request", "https://github.com/acme/api/pull/42"),
    L("Files changed", "https://github.com/acme/api/pull/42/files"),
    L("Code at approved commit", "https://github.com/acme/api/tree/abc1234abc1234abc1234abc1234abc1234abc12"),
  ], { note: "Approving commit abc1234. If the PR changes, this approval will not merge it." }));
inject("value-owner-name", "A '/' in a plain placeholder is encoded (%2F); {v:path} keeps it as a separator", "acme/api", "acme/api", "acme%2Fapi", "acme/api", "acme%2Fapi");
inject("value-integer", "An integer renders as its JCS text", 42, "42", "42", "42", "42");
inject("value-negative-integer", "A negative integer renders as its JCS text", -7, "-7", "-7", "-7", "-7");
inject("value-unreserved", "RFC 3986 unreserved characters stay as they are", "~user-name_1.0", "~user-name_1.0", "~user-name_1.0", "~user-name_1.0", "~user-name_1.0");

// injection attempts
inject("inject-query-fragment", "'?' and '#' in a value are encoded, so it cannot start a query or fragment", "a?b#c", "a?b#c", "a%3Fb%23c", "a%3Fb%23c", "a%3Fb%23c");
inject("inject-userinfo", "'@' in a value is encoded, so it cannot become userinfo", "evil.com@acme", "evil.com@acme", "evil.com%40acme", "evil.com%40acme", "evil.com%40acme");
inject("inject-percent-encoded-slash", "'%2F' in a value is encoded again ('%' → %25): no double decoding", "%2F..%2F", "%2F..%2F", "%252F..%252F", "%252F..%252F", "%252F..%252F");
inject("inject-dot-segments", "'..' segments: encoded '/' keeps a plain value one segment; {v:path} with a '..' segment drops that link", "../../etc", "../../etc", "..%2F..%2Fetc", null, "..%2F..%2Fetc");
inject("inject-dot-dot-value", "A value that is exactly '..' drops every link that uses it", "..", "..", null, null, null);
inject("inject-dot-value", "A value that is exactly '.' drops every link that uses it", ".", ".", null, null, null);
inject("inject-dot-segment-in-path", "{v:path} with a '.' segment drops that link", "a/./b", "a/./b", "a%2F.%2Fb", null, "a%2F.%2Fb");
inject("inject-empty-segment", "{v:path} with an empty segment drops that link", "a//b", "a//b", "a%2F%2Fb", null, "a%2F%2Fb");
inject("inject-empty-value", "An empty value drops every link that uses it", "", "", null, null, null);
inject("inject-absolute-url", "A full URL in a value stays data inside the path", "https://evil.com/x", "https://evil.com/x", "https%3A%2F%2Fevil.com%2Fx", null, "https%3A%2F%2Fevil.com%2Fx");
inject("inject-unicode-space", "Unicode and spaces are UTF-8 percent-encoded", "naïve 😀 x", "naïve 😀 x", "na%C3%AFve%20%F0%9F%98%80%20x", "na%C3%AFve%20%F0%9F%98%80%20x", "na%C3%AFve%20%F0%9F%98%80%20x");
inject("inject-backslash-controls", "Backslash, tab and newline are encoded (URL parsers would treat or strip them); the line shows tab and newline escaped (§3.6)", "a\\b\tc\nd", "a\\b\\tc\\nd", "a%5Cb%09c%0Ad", "a%5Cb%09c%0Ad", "a%5Cb%09c%0Ad");
inject("inject-bidi-override", "A bidi override in a value is encoded, and escaped on the line (§3.6)", "\u202eevil", "\\u{202E}evil", "%E2%80%AEevil", "%E2%80%AEevil", "%E2%80%AEevil");
inject("inject-combining-after-slash", "{v:path} splits on the code point '/', even when a combining mark follows it", "a/́b", "a/́b", "a%2F%CC%81b", "a/%CC%81b", "a%2F%CC%81b");
inject("value-float", "A non-integer number drops every link that uses it", 1.5, "1.5", null, null, null);
inject("value-unsafe-integer", "An integer beyond 2^53 - 1 drops every link that uses it", 9007199254740992, "9007199254740992", null, null, null);
inject("value-boolean", "A boolean drops every link that uses it", true, "true", null, null, null);
inject("value-null", "null drops every link that uses it", null, "null", null, null, null);
inject("value-object", "An object drops every link that uses it", { x: "y" }, "{\"x\":\"y\"}", null, null, null);

const partialReg = { adapter: "test", templates: [tpl("test.partial", "{v}", { links: [L("ok", "https://example.com/{v}"), L("missing", "https://example.com/{nope}"), L("array", "https://example.com/{list.0}")], ...HOSTS })] };
lv("unresolved-link-placeholder", "A link whose placeholder does not resolve is dropped; the others and the card render", lmk("test.partial", { v: "x" }), [partialReg], okv("x", [L("ok", "https://example.com/x")]));

// template-level failures: the card renders, every link is dropped, links_error names the rule
const bad = (name, description, extra, code) => {
  const id = "test.bad_" + name.replace(/-/g, "_");
  lv("invalid-" + name, description, lmk(id, { v: "x" }), [{ adapter: "test", templates: [tpl(id, "{v}", extra)] }], okv("x", [], { links_error: code }));
};
bad("host-not-allowed", "Host not in link_hosts", { links: [L("a", "https://evil.example/{v}")], ...HOSTS }, "host_not_allowed");
bad("host-placeholder", "Placeholder in the host", { links: [L("a", "https://{v}.example.com/x")], ...HOSTS }, "host_not_literal");
bad("host-placeholder-suffix", "Placeholder before the '/' that ends the host", { links: [L("a", "https://example.com{v}/x")], ...HOSTS }, "host_not_literal");
bad("host-no-path", "No '/' after the host", { links: [L("a", "https://example.com")], ...HOSTS }, "host_not_literal");
bad("http", "http:// is refused", { links: [L("a", "http://example.com/{v}")], ...HOSTS }, "url_not_https");
bad("scheme-placeholder", "Placeholder in the scheme", { links: [L("a", "{v}://example.com/x")], ...HOSTS }, "url_not_https");
bad("scheme-uppercase", "The scheme must be the literal lowercase https://", { links: [L("a", "HTTPS://example.com/{v}")], ...HOSTS }, "url_not_https");
bad("javascript", "javascript: is refused", { links: [L("a", "javascript:alert(1)//{v}")], ...HOSTS }, "url_not_https");
bad("userinfo", "Userinfo in the literal authority does not match an allowed host", { links: [L("a", "https://user@example.com/{v}")], ...HOSTS }, "host_not_allowed");
bad("port", "A port in the literal authority does not match an allowed host", { links: [L("a", "https://example.com:8443/{v}")], ...HOSTS }, "host_not_allowed");
bad("too-many-links", "More than 4 links", { links: [1, 2, 3, 4, 5].map((i) => L("l" + i, `https://example.com/${i}/{v}`)), ...HOSTS }, "too_many_links");
bad("wildcard-host", "Wildcards are not hostnames", { links: [L("a", "https://example.com/{v}")], link_hosts: ["*.example.com"] }, "link_hosts_invalid");
bad("uppercase-host", "link_hosts must be lowercase", { links: [L("a", "https://Example.com/{v}")], link_hosts: ["Example.com"] }, "link_hosts_invalid");
bad("host-with-port", "A port is not a hostname", { links: [L("a", "https://example.com:443/{v}")], link_hosts: ["example.com:443"] }, "link_hosts_invalid");
bad("no-link-hosts", "Links without link_hosts", { links: [L("a", "https://example.com/{v}")] }, "link_hosts_invalid");
bad("label-control", "A control character in a label", { links: [L("View\u0007", "https://example.com/{v}")], ...HOSTS }, "label_invalid");
bad("label-bidi", "A bidi override in a label", { links: [L("‮moc.live", "https://example.com/{v}")], ...HOSTS }, "label_invalid");
bad("label-empty", "An empty label", { links: [L("", "https://example.com/{v}")], ...HOSTS }, "label_invalid");
bad("url-space", "A space in the literal URL", { links: [L("a", "https://example.com/a b/{v}")], ...HOSTS }, "url_invalid");
bad("url-non-ascii", "Non-ASCII in the literal URL", { links: [L("a", "https://example.com/é/{v}")], ...HOSTS }, "url_invalid");
bad("url-short-formatter", "Only :path is allowed in a URL", { links: [L("a", "https://example.com/{v:short}")], ...HOSTS }, "url_invalid");
bad("url-two-fragments", "At most one '#'", { links: [L("a", "https://example.com/#a#{v}")], ...HOSTS }, "url_invalid");
bad("url-escaped-brace", "{{ and }} are literal braces, which a URL cannot contain", { links: [L("a", "https://example.com/{{v}}")], ...HOSTS }, "url_invalid");
bad("url-bad-percent", "'%' must start a %XX escape", { links: [L("a", "https://example.com/100%/{v}")], ...HOSTS }, "url_invalid");

// links and notes are covered by the template hash; neither counts as mentioning an argument
{
  const t = tpl("test.altered", "{v}", { links: [L("a", "https://example.com/{v}")], ...HOSTS });
  lv("hash-covers-links", "A link changed after hashing: the template fails its sha256", lmk("test.altered", { v: "x" }), [{ adapter: "test", templates: [{ ...t, links: [L("a", "https://example.com/{v}/x")] }] }], { status: "unverified", reason: "template_hash_mismatch" });
  const n = tpl("test.altered_note", "{v}", { note: "safe" });
  lv("hash-covers-note", "A note changed after hashing: the template fails its sha256", lmk("test.altered_note", { v: "x" }), [{ adapter: "test", templates: [{ ...n, note: "different" }] }], { status: "unverified", reason: "template_hash_mismatch" });
  const h = tpl("test.altered_hosts", "{v}", { links: [L("a", "https://example.com/{v}")], ...HOSTS });
  lv("hash-covers-link-hosts", "link_hosts changed after hashing: the template fails its sha256", lmk("test.altered_hosts", { v: "x" }), [{ adapter: "test", templates: [{ ...h, link_hosts: ["example.com", "evil.example"] }] }], { status: "unverified", reason: "template_hash_mismatch" });
}
lv("link-placeholder-not-a-mention", "A key used only in a link is still unreferenced", lmk("test.linkonly", { a: "x", b: "y" }), [{ adapter: "test", templates: [tpl("test.linkonly", "{a}", { links: [L("b", "https://example.com/{b}")], ...HOSTS })] }], { status: "unverified", reason: "unreferenced_key", detail: "b" });

const noteReg = { adapter: "test", templates: [
  tpl("test.note", "Ship {sha}", { note: "Approving commit {sha:short}." }),
  tpl("test.note_mention", "{a}", { note: "and {b}" }),
  tpl("test.note_unresolved", "{a}", { note: "and {missing}" }),
  tpl("test.note_badfmt", "{a}", { note: "{a:upper}" }),
  tpl("test.text_fmt", "{a:short}"),
] };
lv("note-short", "{sha:short} in a note: the first 7 characters", lmk("test.note", { sha: "0123456789abcdef0123456789abcdef01234567" }), [noteReg], okv("Ship 0123456789abcdef0123456789abcdef01234567", [], { note: "Approving commit 0123456." }));
lv("note-short-short-value", "{sha:short} of a value shorter than 7: the whole value", lmk("test.note", { sha: "abc" }), [noteReg], okv("Ship abc", [], { note: "Approving commit abc." }));
lv("note-short-code-points", "{sha:short} counts code points, not UTF-16 units", lmk("test.note", { sha: "😀😀😀😀😀😀😀😀😀" }), [noteReg], okv("Ship 😀😀😀😀😀😀😀😀😀", [], { note: "Approving commit 😀😀😀😀😀😀😀." }));
lv("note-short-number", "{sha:short} of a number does not resolve → unverified", lmk("test.note", { sha: 1234567890 }), [noteReg], { status: "unverified", reason: "unresolved_placeholder", detail: "sha" });
lv("note-not-a-mention", "A key used only in the note is still unreferenced", lmk("test.note_mention", { a: "x", b: "y" }), [noteReg], { status: "unverified", reason: "unreferenced_key", detail: "b" });
lv("note-unresolved", "A note placeholder that does not resolve → unverified", lmk("test.note_unresolved", { a: "x" }), [noteReg], { status: "unverified", reason: "unresolved_placeholder", detail: "missing" });
lv("note-unknown-formatter", "A formatter other than :short in a note → malformed", lmk("test.note_badfmt", { a: "x" }), [noteReg], { status: "unverified", reason: "malformed_template" });
lv("text-formatter", "No formatter in text: the sentence shows whole values → malformed", lmk("test.text_fmt", { a: "x" }), [noteReg], { status: "unverified", reason: "malformed_template" });

// template-sha256/: the hash input of §3.1
const sv = (name, description, template) => write("template-sha256/" + name + ".json", { description, inputs: { template }, expected: { hash_input: P.templateHashInput(template), sha256: P.templateSha256(template) } });
sv("text-only", "Text-only template: SHA-256 of the UTF-8 text", { text: "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}" });
sv("text-elide", "Text and a non-empty elide: the extended form, so elide is covered", { text: "Deploy {ref} to {environment} on {repo}", elide: ["description"] });
sv("text-empty-elide", "An empty elide counts as absent: the text alone", { text: "Deploy {ref} to {environment} on {repo}", elide: [] });
sv("empty-extensions", "Empty note, links and link_hosts count as absent: the text alone", { text: "Read PR #{pr} on {repo}", note: "", links: [], link_hosts: [] });
sv("links", "With links: JCS of text, elide, links and link_hosts", { text: "Run {workflow} on {ref} ({ref_sha}) in {repo}", elide: ["inputs"], links: [L("Actions", "https://github.com/{repo:path}/actions")], link_hosts: ["github.com"] });
sv("note-only", "A note alone selects the extended form", { text: "Ship {sha}", note: "Approving commit {sha:short}." });
sv("empty-elide-with-links", "An empty elide is omitted from the extended form", { text: "Read PR #{pr} on {repo}", elide: [], links: [L("View pull request", "https://github.com/{repo:path}/pull/{pr}")], link_hosts: ["github.com"] });
sv("unicode", "Unicode in the label and note is hashed as JCS UTF-8", { text: "{a}", note: "Zoë 😀", links: [L("Öffnen ↗", "https://example.com/{a}")], link_hosts: ["example.com"] });
sv("github-merge-pr-v2", "The bundled github.merge_pull_request v2", (({ template_id, template_version, sha256, ...b }) => b)(P.findTemplate(regs, "github.merge_pull_request", 2)));

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
// ---------- weak-keys/ (§5.1): small-order Ed25519 public keys are refused. Expected values written out by hand.
{
  const hx = (h) => P.base64url.encode(Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16)));
  const signBit = (h) => h.slice(0, 62) + (parseInt(h.slice(62), 16) | 0x80).toString(16).padStart(2, "0");
  const small = [
    ["0 (order 4)", "0000000000000000000000000000000000000000000000000000000000000000"],
    ["1, the identity (order 1)", "0100000000000000000000000000000000000000000000000000000000000000"],
    ["order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
    ["order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
    ["p - 1 (order 2)", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
    ["p, non-canonical 0 (order 4)", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
    ["p + 1, non-canonical 1 (order 1)", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ];
  const cases = [
    ...small.map(([d, h]) => ({ description: d, x: hx(h), weak: true })),
    ...small.map(([d, h]) => ({ description: d + ", sign bit set", x: hx(signBit(h)), weak: true })),
    { description: "the gateway test key", x: gwKey.x, weak: false },
    { description: "the Ed25519 device test key", x: devEd.x, weak: false },
    { description: "y = 2: not a small-order encoding (whether it decodes to a point is a separate check)", x: hx("0200000000000000000000000000000000000000000000000000000000000000"), weak: false },
  ];
  write("weak-keys/ed25519-small-order.json", { description: "Ed25519 public keys (JWK x) that are small-order points: refused at pairing, enrollment and QR parse, and nothing verifies under them (§5.1)", cases });
}
console.log("vectors written under", root);
