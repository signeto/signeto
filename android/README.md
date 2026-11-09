# signeto-sign (Kotlin)

The approver-device side of the [Signeto protocol](../docs/protocol.md) as a Kotlin/JVM library for Android
(minSdk 28) and the JVM. The Signeto Android app is built on it. It is a port of the Swift package in
[`../ios`](../ios/README.md), file for file, with the same API shape and the same tests. It uses only the JDK
(`java.security`, `javax.crypto`) plus BouncyCastle's lightweight Ed25519 (`bcprov-jdk18on`, no JCA provider
registered). It uses no `java.time` and no Java 9+ APIs, so an Android app needs no desugaring.

| File | Protocol | What |
|---|---|---|
| `Json.kt`, `Jcs.kt`, `Shortest.kt` | §2.3 | Strict JSON parser with `JSON.parse` semantics and its own strict UTF-8 decoder. RFC 8785 canonicalization byte-identical to `@signeto/protocol`: ECMAScript number formatting, UTF-16 member order and `JSON.stringify` escaping. |
| `Encoding.kt`, `Timestamp.kt` | §2.5 | base64url, hex, SHA-256, constant-time comparison, the fixed-width timestamp format. |
| `Keys.kt`, `Crypto.kt` | §5.1 | Public JWKs (EC P-256, OKP Ed25519), RFC 7638 thumbprints, `gw_`/`dev_` ids, fingerprints, small-order Ed25519 keys. ES256 through JCA, with raw r‖s ⇄ DER conversion and an on-curve check. Ed25519 through BouncyCastle. |
| `Signer.kt` | §4.2, §7.9 | `DeviceSigner` (`suspend fun sign`) and `SoftwareP256Signer` (tests, the emulator and the demo only). The Android Keystore signer lives in the app. |
| `CanonicalAction.kt` | §2 | Receiver-side parse: schema, `not_canonical`, idempotency key, hash of the bytes as received. |
| `Templates.kt`, `Display.kt` | §3 | The renderer and the bundled registries, among them the template hash (§3.1), notes and `:short` (§3.2) and pinned `template_source`. Also review links (§3.5), the §3.4 fallback and the §3.6 display escape. |
| `ApprovalRequest.kt` | §7.5 | `gateway_signature` verification against the pinned gateway key. Only a `VerifiedApprovalRequest` reaches the renderer. |
| `Receipt.kt` | §4 | Signing input, building and signing receipts, standalone verification (incl. WebAuthn, for the vectors). |
| `RelayAuth.kt` | §7.1 | `Signeto-Device` request signing for software keys (and relay-side verification for conformance tests). |
| `Pairing.kt` | §5 | QR parsing, `pairing_id`, `code_hash`, HMAC proofs v1 and v2, and the claim body. Confirmation verification covers `approver_id` (§5.3) and `templates_pinned` (§5.4). Also the `PinnedGateway` record and its storage form, and the `android-key` attestation data. |
| `Freeze.kt` | §7.9 | Device-signed freeze objects. |

The bundled registries (`builtin-registries.json`) are a data port of `@signeto/protocol` `builtinRegistries`.

## The signing path (what to audit)

Everything a device signs goes through one function, `DeviceSigner.sign`, with an input built in this library.
The device signs three things:

1. **Receipt** (`Receipts.sign`): the hash is computed here from the canonical bytes the caller rendered. It is
   never taken from the network. The signing input is the UTF-8 JCS of
   `{canonical_bytes_sha256, decision, reason?, signed_at}`.
2. **Freeze** (`Freeze.body`): the UTF-8 JCS of `{frozen, signed_at}`.
3. **Relay request** (`RelayAuth.deviceHeader`), for software keys only: the UTF-8 JCS of
   `{body_sha256, method, path, ts}`. A hardware key that needs a biometric per signature does not sign relay
   requests. It authenticates to the relay with the device session the relay issues at enrollment
   (protocol.md §7.1), and signs only receipts and freezes.

`sign` returns the 64-byte `r || s` the protocol requires (base64url, 86 characters). JCA and the Android Keystore
produce DER, so `Der.derToRaw` converts their signatures. `sign` is a `suspend` function because the app's
Keystore signer has to wait for a BiometricPrompt. It creates a fresh `Signature` for each call, and the key
allows one operation per authentication, so one fingerprint or face match signs exactly one input.

Before anything is rendered, `ApprovalRequests.verify` checks the request's `gateway_signature`. It rebuilds the
signing input from the request as received, taking the nonce and gateway id from inside the canonical bytes. It
then checks the signature against the key pinned from the gateway's QR. The pin itself comes only from
`Pairing.acceptConfirmation`. That function verifies the gateway's confirmation with the QR's key, covering
`approver_id` and `templates_pinned` in the order received. Receipts for a gateway carry the `approver_id` that
the gateway's confirmation named, never the relay account's approver id.

## Tests

```sh
cd public/android
./gradlew test        # JDK 17 (Android Studio's: export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home")
```

The suite runs the shared conformance vectors in `../packages/protocol/vectors/`: `canonical/`,
`canonical-invalid/`, `templates/`, `links/`, `template-sha256/`, `display-escape/`, `weak-keys/` and
`receipts/` (ES256, Ed25519, WebAuthn and every negative code). It also runs `receipts/signing-input/`,
`approval-request/`, `ids/` and `relay-auth/`.

The suite also reads the Swift package's fixtures, read-only, from
`../ios/Tests/SignetoSignTests/Fixtures/`:

- pairing
- ~3,500 number formatting cases
- string escaping and key ordering
- extra renderer cases
- TS-signed ES256 receipts
- an ES256 gateway
- the bundled registries

A test checks that this library's registries resource is byte-identical to the Swift one. The README there
explains how to regenerate the fixtures.

The reverse direction (Kotlin signs, TypeScript verifies) is an opt-in check:

```sh
SIGNETO_EXPORT_DIR=/tmp/sig ./gradlew test --tests '*CrossCheckExportTest'
node ../ios/Tests/SignetoSignTests/Fixtures/verify-swift-output.mjs /tmp/sig
```

## Differences from the Swift package

- `DeviceSigner.sign`, `Receipts.sign`, `Freeze.body` and `RelayAuth.deviceHeader` are `suspend` functions.
- A Kotlin `String` can hold a lone UTF-16 surrogate, which a Swift `String` cannot. `Display.escape` escapes one
  as `\u{D800}`, as the TypeScript rule does. `Jcs.canonicalize` throws on one, as `@signeto/protocol` does.
- Number formatting: Swift's `description` gives the shortest round-trip digits, but ART's `Double.toString()`
  does not. `Shortest.kt` computes the ECMAScript digits exactly with `BigDecimal` from the double's rounding
  interval, instead of vendoring Ryu. The number fixture and `canonical/` vectors gate it.
- Ed25519: BouncyCastle verifies with the cofactored equation, while CryptoKit and Node use the cofactorless one.
  To make all three agree, `Ed25519.verify` also requires the key and the signature's R to be in the
  prime-order subgroup. That refuses the crafted torsion cases (tested), which an honest signer never produces.
- The build compiles against the Java 8 API (`-Xjdk-release=1.8`), so a Java 9+ call fails at compile time
  instead of on a phone.
- Results are `Outcome<T, E>` (`Ok`/`Err`) where Swift returns `Result`. Error codes are enums with the wire
  string in `.code`.
- `PinnedGateway`, `Template`, `TemplateRegistry` and `TemplateSource` read and write their JSON forms with
  `toJson`/`fromJson`-style members (`json`, `fromJson`) instead of `Codable`. The member names are the same.

## Known differences from the TypeScript reference

Both fail closed. Two inputs are parse errors here that `JSON.parse` treats differently:

- `\u` escapes that produce a lone UTF-16 surrogate. RFC 8785 and I-JSON forbid them; `JSON.parse` accepts them.
- Numbers that overflow to infinity. The TS canonicalizer throws on them later.
