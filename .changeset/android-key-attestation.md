---
"@signeto/protocol": minor
---

`@signeto/protocol/androidkey`: Android Key Attestation verification (protocol.md §5.3 point 3) for the Android approver app, with Google's hardware attestation roots pinned by key, the revocation list parser, and `@signeto/protocol/androidkey/testing` for Keystore-shaped test chains. The DER reader shared with App Attest moved to an internal module; App Attest behaviour is unchanged.
