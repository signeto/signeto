# @signeto/protocol

The trust-path primitives every Signeto component shares. Normative spec: [`docs/protocol.md`](../../docs/protocol.md).

- `canonicalize` — RFC 8785 JCS. Frozen for `protocol_version` MAJOR 1.
- `buildCanonicalAction` / `encodeAction` / `parseCanonicalAction` — the canonical action (§2): schema, idempotency key, timestamps, expiry rules, receiver-side canonical check.
- `receiptSigningInput` / `signReceipt` / `verifyReceipt` — receipts (§4) for ES256, Ed25519 and WebAuthn, standalone verification steps 1, 2, 9–12 and the §4.4 WebAuthn order.
- `signApprovalRequest` / `verifyApprovalRequest` — `gateway_signature` on every approval request (§7.5).
- `renderTemplate` + `builtinRegistries` — display templates (§3): two inputs, byte-identical output on every surface, "unverified template" on any doubt. The result carries the template's note and its review links (§3.5), built from the canonical args and the template's `link_hosts`; `templateSha256` hashes text, note, links and hosts together (§3.1).
- `gatewayIdFromJwk` / `deviceIdFromJwk` / `fingerprint` / `newActionId` / `newNonce` — identifiers (§2.6, §5.1).

## Vectors

`vectors/` holds the conformance fixtures from §9 (`canonical`, `canonical-invalid`, `templates`, `links`, `template-sha256`, `receipts`, `receipts/signing-input`, `approval-request`, `ids`). iOS, web and any third-party implementation must pass them. Regenerate with `node scripts/gen-vectors.mjs` after `pnpm build`; keys under `vectors/keys/` are test keys, generated once, never to be used elsewhere. ES256 signatures are re-randomised on each run, so regenerate only when a vector's inputs change.

Not yet covered: `batch/`, `pairing/`, `relay-auth/`, `ledger/` (P1 and relay work).

## Runtime

Node 22+. Uses `node:crypto`; a browser build for `@signeto/approver-web` will swap in WebCrypto behind the same API.
