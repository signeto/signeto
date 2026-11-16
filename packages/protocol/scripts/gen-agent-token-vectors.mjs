// Generates the vectors of the built-in tool `signeto.agent_token_add` (protocol.md §3.1, §9) from the built package,
// and rewrites the bundled registries the Swift and Kotlin libraries embed (a data port of `builtinRegistries`):
//
//   pnpm --filter @signeto/protocol build
//   node public/packages/protocol/scripts/gen-agent-token-vectors.mjs
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

const template = P.signetoRegistry.templates.find((t) => t.template_id === "signeto.agent_token_add" && t.template_version === 1);
const registries = [{ adapter: "signeto", templates: [template] }];
const action = (args_resolved, nonce) =>
  P.buildCanonicalAction(
    {
      tool: "signeto.agent_token_add",
      template_version: 1,
      args_resolved,
      requester: { agent: "signeto-cloud", session_id: "cmd_01JCT0AGENTT0KENADD0000000", host: "signeto-cloud-t7f3k2q9", gateway_id },
      origin_hash: P.sha256hex("cloud.command:cmd_01JCT0AGENTT0KENADD0000000"),
      tier: 3,
      mode: "enforce",
    },
    { now: Date.parse("2026-11-15T12:00:00.000Z"), nonce },
  ).canonical_bytes;

write("templates/agent-token-add.json", {
  description: "signeto.agent_token_add v1 (built in, tier 3): a new MCP token for a hosted gateway, named with its key id",
  inputs: { canonical_bytes: action({ name: "claude-code", key_id: "Zk3vQ9aB_x-7" }, "QWdlbnRUb2tlbkFkZFZlYw"), registries },
  expected: { status: "ok", text: "Let a new agent connect to this gateway: claude-code (key Zk3vQ9aB_x-7)", hidden: [] },
});
write("templates/agent-token-add-extra-argument.json", {
  description: "signeto.agent_token_add v1 elides nothing: an argument beside name and key_id (here the token's hash) → unverified",
  inputs: { canonical_bytes: action({ name: "claude-code", key_id: "Zk3vQ9aB_x-7", hash: "$sha256$" + "A".repeat(43) }, "QWdlbnRUb2tlbkFkZFZlYg"), registries },
  expected: { status: "unverified", reason: "unreferenced_key", detail: "hash" },
});
write("templates/agent-token-add-printable-name.json", {
  description: "signeto.agent_token_add v1: a name with spaces and punctuation renders as given (names are printable ASCII)",
  inputs: { canonical_bytes: action({ name: "ci <deploy> #2", key_id: "0123456789ab" }, "QWdlbnRUb2tlbkFkZFZlYQ"), registries },
  expected: { status: "ok", text: "Let a new agent connect to this gateway: ci <deploy> #2 (key 0123456789ab)", hidden: [] },
});
write("template-sha256/agent-token-add.json", {
  description: "signeto.agent_token_add v1: text-only, so the hash input is the UTF-8 text",
  inputs: { template: { text: template.text } },
  expected: { hash_input: P.templateHashInput({ text: template.text }), sha256: template.sha256 },
});

// The registries the Swift and Kotlin libraries embed, and the Swift tests' fixture: the same bytes in all three.
const bundled = JSON.stringify(P.builtinRegistries, null, 2) + "\n";
for (const rel of ["ios/Sources/SignetoSign/Resources/builtin-registries.json", "ios/Tests/SignetoSignTests/Fixtures/builtin-registries.json", "android/src/main/resources/dev/signeto/sign/builtin-registries.json"])
  writeFileSync(join(root, "..", "..", rel), bundled);
