// Verifies artifacts signed by the Swift package (see CrossCheckExportTests.swift) with @signeto/protocol.
//   node Tests/SignetoSignTests/Fixtures/verify-swift-output.mjs <SIGNETO_EXPORT_DIR>
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const P = await import(join(here, "..", "..", "..", "..", "packages", "protocol", "dist", "index.js"));
const x = JSON.parse(readFileSync(join(process.argv[2] ?? ".", "swift-signed.json"), "utf8"));
let failed = 0;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed++; };
for (const r of x.receipts) {
  const v = P.verifyReceipt({ receipt: r, canonical_bytes: x.canonical_bytes, issued_at: x.issued_at, expires_at: x.expires_at, device_public_key: x.device_public_key });
  check(v.ok, `receipt ${r.decision}${r.reason ? " with reason" : ""} (${v.ok ? "verified" : v.code})`);
}
const ra = P.verifyRelayRequest({ header: x.relay.header, method: x.relay.method, path: x.relay.path, body: x.relay.body, public_key: x.device_public_key, now: x.relay.now, schemes: ["Signeto-Device"] });
check(ra.ok, `Signeto-Device header (${ra.ok ? ra.key_id : ra.code})`);
const fz = P.verifyWithJwk(P.utf8.encode(P.canonicalize({ frozen: x.freeze.frozen, signed_at: x.freeze.signed_at })), P.base64url.decode(x.freeze.signature), x.device_public_key);
check(fz, "freeze signature");
process.exit(failed ? 1 : 0);
