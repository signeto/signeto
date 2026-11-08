# SignetoSign

The approver-device side of the [Signeto protocol](../docs/protocol.md) as a Swift package for iOS 17+ and
macOS 14+. No third-party dependencies: CryptoKit, Foundation, Security and LocalAuthentication only. The
Signeto iOS app is built on it; anything else that wants to verify or produce device-side protocol objects in
Swift can use it too.

| File | Protocol | What |
|---|---|---|
| `JSON.swift`, `JCS.swift` | §2.3 | Strict JSON parser with `JSON.parse` semantics; RFC 8785 canonicalization byte-identical to `@signeto/protocol` (ECMAScript number formatting, UTF-16 member order, `JSON.stringify` escaping). |
| `Encoding.swift`, `Timestamp.swift` | §2.5 | base64url, hex, SHA-256, exact (non-normalising) string comparison, the fixed-width timestamp format. |
| `Keys.swift` | §5.1 | Public JWKs (EC P-256, OKP Ed25519), RFC 7638 thumbprints, `gw_`/`dev_` ids, fingerprints, ES256 and Ed25519 verification. |
| `Signer.swift` | §4.2, §7.9 | `DeviceSigner`: `SecureEnclaveSigner` (fresh biometric prompt per signature) and `SoftwareP256Signer` (tests and the simulator only); Keychain persistence. |
| `CanonicalAction.swift` | §2 | Receiver-side parse: schema, `not_canonical`, idempotency key, hash of the bytes as received. |
| `Templates.swift` | §3 | The renderer and the bundled registries (`Resources/builtin-registries.json`, a data port of `@signeto/protocol` `builtinRegistries`); the template hash (§3.1); notes and `:short` (§3.2); review links built from the verified args with the host allowlist (§3.5); pinned `template_source`; the §3.4 fallback. |
| `ApprovalRequest.swift` | §7.5 | `gateway_signature` verification against the pinned gateway key. Only a `VerifiedApprovalRequest` reaches the renderer. |
| `Receipt.swift` | §4 | Signing input, building and signing receipts, standalone verification (incl. WebAuthn, for the vectors). |
| `RelayAuth.swift` | §7.1 | `Signeto-Device` request signing for software keys (and relay-side verification for conformance tests). A biometric-bound key uses the relay's device session instead. |
| `Pairing.swift` | §5 | QR parsing, `pairing_id`, `code_hash`, HMAC proof, claim body, confirmation verification including `approver_id` (§5.3) and `templates_pinned` (§5.4), the pinned-gateway record. |
| `Freeze.swift` | §7.9 | Device-signed freeze objects. |

## The signing path (what to audit)

Everything a device signs goes through one function, `DeviceSigner.sign(_:)`, with an input built in this
package:

1. **Receipt** (`Receipts.sign`): the hash is computed here from the canonical bytes the caller rendered,
   never taken from the network. Signing input = UTF-8 JCS of `{canonical_bytes_sha256, decision, reason?, signed_at}`.
2. **Freeze** (`Freeze.body`): UTF-8 JCS of `{frozen, signed_at}`.
3. **Relay request** (`RelayAuth.deviceHeader`), software keys only: UTF-8 JCS of `{body_sha256, method, path, ts}`.
   A Secure Enclave key that needs Face ID per signature authenticates to the relay with the device session
   the relay issues at enrollment (protocol.md §7.1) and signs only receipts and freezes.

`SecureEnclaveSigner.sign` creates a new, unevaluated `LAContext` (with `promptReason` as its text), re-opens
the Secure Enclave key from its encrypted blob with it and calls CryptoKit's ECDSA P-256 over SHA-256 of the
input; `rawRepresentation` is the 64-byte `r || s` the protocol requires (base64url, 86 characters). The key is
created with `SecAccessControl` `.privateKeyUsage` + `.biometryCurrentSet` and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so every signature needs its own Face ID or Touch ID match:
there is no API for passing in an already-evaluated context. `sign` blocks while the prompt is shown; call it
off the main thread. The key dies if the biometric enrollment changes. The blob is stored in the data-protection Keychain,
this-device-only, never synced.

Before anything is rendered, `ApprovalRequests.verify` rebuilds the `gateway_signature` signing input from the
request as received (nonce and gateway id from inside the canonical bytes) and checks it against the key pinned
from the gateway's QR. The pin itself comes only from `Pairing.acceptConfirmation`, which verifies the gateway's
confirmation (with `approver_id` and `templates_pinned` in the order received) using the QR's key. Receipts for a
gateway carry the `approver_id` that gateway's confirmation named, never the relay account's approver id.

## Tests

```sh
cd public/ios
swift test
```

The suite runs the shared conformance vectors in `../packages/protocol/vectors/` (located from the test files
with `#filePath`): `canonical/`, `canonical-invalid/`, `templates/`, `links/`, `template-sha256/`, `receipts/` (ES256, Ed25519, WebAuthn and
every negative code), `receipts/signing-input/`, `approval-request/`, `ids/`, `relay-auth/`.

`Tests/SignetoSignTests/Fixtures/` holds what the vectors do not cover yet, generated from the built TS package:
pairing (there is no `pairing/` vector set), ~3,500 number formatting cases, string escaping and key ordering,
extra renderer cases, TS-signed ES256 receipts with a reason, an ES256 gateway, and the bundled registries.

```sh
pnpm --filter @signeto/protocol build            # from the repository root
node public/ios/Tests/SignetoSignTests/Fixtures/gen-fixtures.mjs
```

The reverse direction (Swift signs, TypeScript verifies) is an opt-in check:

```sh
SIGNETO_EXPORT_DIR=/tmp/sig swift test --filter CrossCheckExportTests
node Tests/SignetoSignTests/Fixtures/verify-swift-output.mjs /tmp/sig
```

`SIGNETO_SE_TESTS=1 swift test` also creates a real Secure Enclave key (Macs with a Secure Enclave).

## Known differences from the TypeScript reference

Both fail closed. `\u` escapes that produce a lone UTF-16 surrogate, and numbers that overflow to infinity,
are parse errors here (RFC 8785 / I-JSON forbid them); `JSON.parse` accepts the first, and the TS
canonicalizer throws on the second.
