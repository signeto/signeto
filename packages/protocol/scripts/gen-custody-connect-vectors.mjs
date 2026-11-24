// Generates the vectors of the built-in tool `signeto.custody_connect` (SIG-224: connecting an Alpaca paper account to
// a hosted gateway) from the built package, and rewrites the bundled registries the Swift and Kotlin libraries embed
// (a data port of `builtinRegistries`):
//
//   pnpm --filter @signeto/protocol build
//   node public/packages/protocol/scripts/gen-custody-connect-vectors.mjs
//
// Nothing here is signed, so re-running reproduces every file byte for byte. The gateway id comes from the test key
// in vectors/keys/, which MUST NOT be used elsewhere.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const P = await import(join(root, "dist", "index.js"));
const write = (rel, obj) => writeFileSync(join(root, "vectors", rel), JSON.stringify(obj, null, 2) + "\n");
const gateway_id = P.gatewayIdFromJwk(JSON.parse(readFileSync(join(root, "vectors", "keys", "gateway-ed25519.json"), "utf8")));

const template = P.signetoRegistry.templates.find((t) => t.template_id === "signeto.custody_connect" && t.template_version === 1);
const registries = [{ adapter: "signeto", templates: [template] }];
const action = (args_resolved, nonce) =>
  P.buildCanonicalAction(
    {
      tool: "signeto.custody_connect",
      template_version: 1,
      args_resolved,
      requester: { agent: "signeto portal", session_id: "portal", host: "signeto-cloud-t7f3k2q9", gateway_id },
      origin_hash: P.sha256hex("cloud.command:cmd_01JCT0CUST0DYC0NNECT00000000"),
      tier: 3,
      mode: "enforce",
    },
    { now: Date.parse("2026-11-24T12:00:00.000Z"), nonce },
  ).canonical_bytes;

const ARGS = { adapter: "alpaca", account: "paper", account_last4: "FGH7", connection_id: "cxn_01JCT0C0NNECT10N00000000AB", gateway: "trader" };
const TEXT =
  "Connect Alpaca paper account …FGH7 to gateway trader. Signeto Cloud keeps an access token for this account (place and cancel orders, read market data) and uses it only for orders your policy allows.";

write("templates/custody-connect.json", {
  description: "signeto.custody_connect v1 (built in, tier 3): connect an Alpaca paper account to a hosted gateway; the connection id on the note line",
  inputs: { canonical_bytes: action(ARGS, "Q3VzdG9keUNvbm5lY3RWQQ"), registries },
  expected: { status: "ok", text: TEXT, note: "Connection cxn_01JCT0C0NNECT10N00000000AB.", hidden: ["adapter", "connection_id"] },
});
write("templates/custody-connect-extra-argument.json", {
  description: "signeto.custody_connect v1: an argument beside the five it names (here a token) → unverified",
  inputs: { canonical_bytes: action({ ...ARGS, access_token: "not-for-the-card" }, "Q3VzdG9keUNvbm5lY3RWQg"), registries },
  expected: { status: "unverified", reason: "unreferenced_key", detail: "access_token" },
});
write("template-sha256/custody-connect.json", {
  description: "signeto.custody_connect v1: text, elide and note, so the hash input is their JCS object",
  inputs: { template: { text: template.text, elide: template.elide, note: template.note } },
  expected: { hash_input: P.templateHashInput({ text: template.text, elide: template.elide, note: template.note }), sha256: template.sha256 },
});

// The registries the Swift and Kotlin libraries embed, and the Swift tests' fixture: the same bytes in all three.
const bundled = JSON.stringify(P.builtinRegistries, null, 2) + "\n";
for (const rel of ["ios/Sources/SignetoSign/Resources/builtin-registries.json", "ios/Tests/SignetoSignTests/Fixtures/builtin-registries.json", "android/src/main/resources/dev/signeto/sign/builtin-registries.json"])
  writeFileSync(join(root, "..", "..", rel), bundled);
