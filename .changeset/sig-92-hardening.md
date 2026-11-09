---
"@signeto/protocol": minor
"@signeto/adapter-github": minor
---

Security hardening from review SIG-92.

- protocol: one display escape rule for every approver surface (`displayEscape`, §3.6); printable `requester.agent`; pairing proof v2 covering device name, platform and attestation (§5.3); small-order Ed25519 public keys refused; `verifyWebAuthnAssertion` exported; nested unreferenced-key rule for templates; `canonicalize` rejects lone surrogates (RFC 8785).
- adapter-github: a merge re-reads the pull request and refuses unless base, base repository and head match the signed values; a workflow dispatch re-reads the ref afterwards and cancels runs not on the signed commit; `dispatch_workflow` v3 shows `inputs` in the sentence.
