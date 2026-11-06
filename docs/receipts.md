# Verifying receipts

A Signeto receipt is the approver's signature over the exact action the gateway built. You can verify one with `@signeto/protocol` and the approver's public key, with no gateway or Signeto service involved.

## What is signed

The approver's device signs the RFC 8785 (JCS) serialization of:

```json
{ "canonical_bytes_sha256": "<hex SHA-256 of the canonical action bytes>",
  "decision": "approve" | "deny",
  "reason": "<only present if the approver wrote one>",
  "signed_at": "2026-11-06T18:05:00.000Z" }
```

Binding the decision and reason means a denial can't be relabelled as an approval and a relay can't add words the approver didn't write. Algorithms are ES256 (Secure Enclave, passkeys) and Ed25519 (software keys); nothing else verifies. Passkey (WebAuthn) receipts sign `authenticatorData || SHA-256(clientDataJSON)` with the challenge set to SHA-256 of the input above; the verifier checks challenge, origin and RP ID before the signature. Full rules: [protocol.md §4](protocol.md#4-receipts).

## Verify one

```ts
import { verifyReceipt, renderTemplate, builtinRegistries } from "@signeto/protocol";

const result = verifyReceipt({
  receipt,                       // the receipt JSON
  canonical_bytes,               // the action bytes exactly as the gateway stored them
  issued_at, expires_at,         // from the action
  device_public_key,             // the approver's enrolled JWK
  // webauthn: { allowed_origins: ["https://approve.signeto.dev"], rp_id: "approve.signeto.dev", require_user_verified: true },
});

if (!result.ok) throw new Error(`receipt rejected: ${result.code}`);
console.log(renderTemplate(canonical_bytes, builtinRegistries)); // what the approver saw
```

`verifyReceipt` checks the schema and version, the algorithm against the key, the hash of *your* copy of the bytes against the one signed, the clock window, and the signature. It returns a code for every failure (`hash_mismatch`, `invalid_signature`, `clock_skew`, …).

## Conformance vectors

`packages/protocol/vectors/` holds fixtures for canonical bytes, templates, receipts (positive and negative), WebAuthn receipts and gateway-signed approval requests. Any implementation of the protocol, in any language, should pass all of them.
