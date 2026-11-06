# Signeto Protocol Specification

**Status:** draft v0.1, 2026-11-05. Normative for `@signeto/protocol` 1.x.
**Companion documents:** `SPEC.md` (product, v0.4), `docs/DESIGN.md` (design plan), `docs/architecture.md`, `docs/threat-model.md`, `docs/ledger.md` (normative for the ledger event list).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be interpreted as described in RFC 2119 and RFC 8174 when they appear in capitals.

This document defines the wire formats and procedures that sit on the trust path between an AI agent, an Signeto gateway, an Signeto relay, and an approver device. Anything not on the trust path (portal, billing, push transport internals) is out of scope.

Actors:

- **Agent.** The AI process calling tools. Untrusted. Holds no credentials.
- **Gateway.** Customer-run process that holds credentials, builds canonical actions, verifies receipts, executes frozen actions. The only enforcement point.
- **Relay.** Transport and queue between gateway and devices. Holds public keys, pending requests, receipts. Untrusted for authorization: a compromised relay MUST NOT be able to produce a valid approval.
- **Approver device.** Phone, browser, or CLI that renders a canonical action and signs a receipt with a hardware-backed key where available.

---

> **Public edition.** This is the normative protocol Signeto implements. Section references to `SPEC`, `architecture.md`, `ledger.md`, `policy.md` and `threat-model.md` point to Signeto's internal design documents; everything an integrator needs to produce or verify protocol objects is in this file, `docs/receipts.md`, and `@signeto/protocol` with its conformance vectors.

## 1. Scope and versioning

### 1.1 Version fields

Every canonical action carries `protocol_version`. Every receipt carries `receipt_version`. Both are strings of the form `MAJOR.MINOR` where MAJOR and MINOR are non-negative integers without leading zeros. This document defines `protocol_version: "1.0"` and `receipt_version: "1.0"`.

The two numbers are independent. The canonical action format and the receipt format can evolve separately; a receipt format change does not require re-versioning the action format.

### 1.2 Compatibility rules

- A MINOR increment MUST be backward compatible: a consumer that understands `1.0` MUST be able to verify and execute a `1.3` action or receipt by ignoring fields it does not know, provided the fields it does know keep their meaning. New fields in a MINOR release MUST be optional.
- A MAJOR increment MAY change field semantics, remove fields, or change the signing input. A consumer MUST NOT attempt to interpret a MAJOR it does not implement.
- Canonicalization (JCS) and the signing input definition in §4.2 are frozen for the lifetime of a MAJOR version.

### 1.3 Behaviour on unknown versions

- A gateway that receives a receipt whose `receipt_version` MAJOR is not implemented MUST reject it with `receipt_version_unsupported`. The action remains pending until it expires or another valid receipt arrives.
- A gateway MUST NOT build canonical actions with a `protocol_version` it cannot itself verify receipts for.
- An approver device that receives an action whose `protocol_version` MAJOR it does not implement MUST NOT sign it. It SHOULD display "unsupported protocol version" and MAY offer to sign a denial; the denial receipt uses the device's own supported `receipt_version` and the hash of the bytes as received.
- A relay MUST pass through actions and receipts of any version without interpreting their contents beyond the fields it needs for routing (§7). The relay MUST NOT reject traffic on version grounds.
- Unknown MINOR versions MUST be accepted by every party.

### 1.4 Package versioning

`@signeto/protocol` follows semver. Its MAJOR tracks the highest `protocol_version` MAJOR it can produce. A package release MUST state the set of `protocol_version` and `receipt_version` MAJORs it verifies.

---

## 2. Canonical action

The canonical action is the only thing an approver ever signs and the only thing a gateway ever executes. The gateway builds it; the agent never does. See SPEC §2 principle 3 and §9.

### 2.1 Fields

| Field | Type | Req | Meaning |
|---|---|---|---|
| `protocol_version` | string | MUST | `"1.0"` for this document. |
| `tool` | string | MUST | Fully qualified tool name, `<adapter>.<tool>`, e.g. `github.merge_pull_request`. Lowercase, `[a-z0-9_]+(\.[a-z0-9_]+)+`. |
| `template_id` | string | MUST | Display template identifier (§3). By convention equal to `tool`. |
| `template_version` | integer | MUST | Positive integer. Template registry version used to render this action. |
| `args_resolved` | object | MUST | Arguments after gateway resolution: IDs looked up, amounts normalized, paths absolute. Values MUST be JSON primitives, arrays, or objects. No floats where an exact decimal is meaningful; amounts MUST be strings or integer minor units as the adapter manifest declares. |
| `requester` | object | MUST | `{agent, session_id, host, gateway_id}`, all strings, all REQUIRED. `agent` is the client name as reported by MCP initialization or the hook environment. `gateway_id` is defined in §5.1. |
| `nonce` | string | MUST | 16 random bytes from a CSPRNG, base64url without padding (22 characters). Single use per gateway. |
| `idempotency_key` | string | MUST | Lowercase hex SHA-256, see §2.4. |
| `issued_at` | string | MUST | RFC 3339 UTC timestamp, §2.5. |
| `expires_at` | string | MUST | RFC 3339 UTC timestamp, §2.5. |
| `origin_hash` | string | MUST | Lowercase hex SHA-256 of an integration-defined correlation string (§2.8). Agent-controlled correlation metadata, not evidence: never an input to policy, never shown as proof of intent; used for deduplication and ledger correlation only. |
| `tier` | integer | MUST | `1`, `2`, or `3` as assigned by policy (SPEC §7). Tier 1 actions are built and ledgered but not sent for approval. |
| `mode` | string | MUST | `"enforce"` or `"advisory"`. See SPEC §5 P1 and §9. |
| `batch_id` | string | MAY | Present when the action is a step in an approved plan. 22-character base64url nonce shared by all steps. |
| `batch_index` | integer | MAY | Zero-based position in the batch. REQUIRED when `batch_id` is present. |
| `atomic` | boolean | MAY | REQUIRED when `batch_id` is present, MUST NOT appear otherwise. `true`: the batch is approved by one receipt over the batch manifest and executed all-or-nothing (§6.6). `false`: this step is approved on its own receipt. A gateway creating a batch MUST default to `true`. |
| `effective_at` | string | MAY | RFC 3339 UTC. Earliest time the gateway may execute, for cooling-off. MUST be later than `issued_at` if present. |

Fields not listed here MUST NOT appear in a `1.x` canonical action. Adapters put adapter-specific data inside `args_resolved`, never at the top level.

`id` and `canonical_bytes` from SPEC §8 are gateway-local storage columns and are not fields of the canonical action. `action_id` is defined in §2.6.

### 2.2 JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://signeto.dev/schemas/canonical-action-1.json",
  "title": "Signeto canonical action 1.x",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "protocol_version", "tool", "template_id", "template_version",
    "args_resolved", "requester", "nonce", "idempotency_key",
    "issued_at", "expires_at", "origin_hash", "tier", "mode"
  ],
  "properties": {
    "protocol_version": { "type": "string", "pattern": "^1\\.(0|[1-9][0-9]*)$" },
    "tool": { "type": "string", "pattern": "^[a-z0-9_]+(\\.[a-z0-9_]+)+$" },
    "template_id": { "type": "string", "minLength": 1, "maxLength": 128 },
    "template_version": { "type": "integer", "minimum": 1 },
    "args_resolved": { "type": "object" },
    "requester": {
      "type": "object",
      "additionalProperties": false,
      "required": ["agent", "session_id", "host", "gateway_id"],
      "properties": {
        "agent": { "type": "string", "minLength": 1, "maxLength": 128 },
        "session_id": { "type": "string", "minLength": 1, "maxLength": 256 },
        "host": { "type": "string", "minLength": 1, "maxLength": 253 },
        "gateway_id": { "type": "string", "pattern": "^gw_[A-Za-z0-9_-]{43}$" }
      }
    },
    "nonce": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$" },
    "idempotency_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "issued_at": { "$ref": "#/$defs/ts" },
    "expires_at": { "$ref": "#/$defs/ts" },
    "origin_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "tier": { "type": "integer", "enum": [1, 2, 3] },
    "mode": { "type": "string", "enum": ["enforce", "advisory"] },
    "batch_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$" },
    "batch_index": { "type": "integer", "minimum": 0 },
    "atomic": { "type": "boolean" },
    "effective_at": { "$ref": "#/$defs/ts" }
  },
  "dependentRequired": { "batch_id": ["batch_index", "atomic"], "batch_index": ["batch_id"], "atomic": ["batch_id"] },
  "$defs": {
    "ts": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    }
  }
}
```

### 2.3 Canonicalization

The canonical bytes of an action are the UTF-8 encoding of the JSON Canonicalization Scheme (RFC 8785, JCS) serialization of the action object. Consequences that implementers MUST honour:

- Object members are sorted by UTF-16 code unit order of their names.
- No whitespace.
- Numbers are serialized per ECMAScript `Number.prototype.toString`; integers appear without a fractional part or exponent. Adapters MUST NOT place values outside the IEEE 754 safe integer range in `args_resolved` as numbers; such values MUST be strings.
- Strings are escaped per RFC 8785 §3.2.2.2.
- A gateway MUST produce the bytes once, store them, and treat them as immutable. Every later step (sending to relay, hashing for the signing input, execution) MUST use the stored bytes, never a re-serialization.

Receivers (device, relay, verifier) MUST operate on the bytes as received. A receiver MAY parse them for display or validation but MUST hash the received bytes, not a re-serialization. A receiver SHOULD check that re-serializing the parsed object with JCS reproduces the received bytes and MUST refuse to sign if it does not (`not_canonical`).

### 2.4 Idempotency key

`idempotency_key` is the lowercase hex SHA-256 of the JCS serialization of the action object with the following members removed:

- `nonce`
- `idempotency_key`
- `issued_at`
- `expires_at`
- `effective_at`
- `origin_hash`

All other members, including `requester` (and therefore `session_id`), are included. This satisfies SPEC §5 "hash(canonical action minus nonce/timestamps) + requester session": the session is inside the hashed object.

`origin_hash` is excluded because its input changes on every retry: an MCP client assigns a new request id (`tool_use_id`, §2.8) each time it calls the tool, so a hash that included it would never match. The ledger keeps the `origin_hash` of the action as first issued.

Two actions with the same `idempotency_key` are the same request. The gateway MUST reattach a retry to the existing pending action (§6.3) rather than issue a second nonce while the first is unexpired.

### 2.5 Timestamps, expiry, clock skew

- All timestamps are RFC 3339 in UTC with exactly three fractional-second digits and the `Z` designator: `2026-11-05T18:04:09.123Z`. Offsets other than `Z` MUST NOT be used. The fixed width makes the format unambiguous under JCS.
- `expires_at - issued_at` defaults to 3 minutes and MUST NOT exceed 5 minutes. A policy file that configures a longer expiry MUST be rejected at load time; the gateway MUST NOT silently clamp.
- Clock skew tolerance is 60 seconds. A device MUST NOT sign an action if its local clock is later than `expires_at + 60 s`, and SHOULD warn if `issued_at` is more than 60 s in its future. A gateway MUST reject a receipt whose `signed_at` is earlier than `issued_at - 60 s` or later than `expires_at + 60 s`.
- Expiry at the gateway is judged against the gateway's own clock with no tolerance: the gateway MUST NOT execute after `expires_at` even if a valid receipt arrives.
- Approvers display `expires_at` as a countdown from their own clock. A device MUST refresh its displayed state at least every second while an approval is on screen.

### 2.6 Action identifier

`action_id` is assigned by the gateway: the string `act_` followed by a ULID (26 Crockford base32 characters, uppercase). It is a routing handle, is not part of the canonical bytes, and is not signed. Nothing in the protocol relies on `action_id` for integrity; the binding between a receipt and an action is the hash in the signing input (§4.2).

### 2.7 Example

```json
{
  "protocol_version": "1.0",
  "tool": "github.merge_pull_request",
  "template_id": "github.merge_pull_request",
  "template_version": 1,
  "args_resolved": {
    "repo": "acme/api",
    "pr": 42,
    "head_sha": "abc1234abc1234abc1234abc1234abc1234abc12",
    "base": "main",
    "method": "squash"
  },
  "requester": {
    "agent": "claude-code",
    "session_id": "sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3",
    "host": "jason-mbp",
    "gateway_id": "gw_jtl8uXbA19Z9r2ZrSBMGyfEddtXMM_d4wo1k0O_GMrs"
  },
  "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
  "idempotency_key": "d6c9ba6711cedcb098ec0694c215d960b8b130a03f74378fc4b31c36fcad5376",
  "issued_at": "2026-11-05T18:04:09.123Z",
  "expires_at": "2026-11-05T18:07:09.123Z",
  "origin_hash": "93ac2a7de1b680ac6c0d62713c372d3f223cc0d1b41df20150946fd082755967",
  "tier": 3,
  "mode": "enforce"
}
```

### 2.8 `origin_hash` per integration

MCP tool calls carry no conversation transcript, so there is no "originating message" for the gateway to hash. Each integration defines the string whose UTF-8 bytes are hashed:

| Integration | Input to SHA-256 |
|---|---|
| Claude Code and other MCP clients | `session_id || "\n" || tool_use_id` |
| Hook-based adapters (`PreToolUse` and equivalents) | JCS serialization of the hook payload as received |
| CI runners | `run_id || "\n" || job_id` |

Every one of these inputs is supplied by the agent side and is therefore attacker-controlled. `origin_hash` is correlation metadata, not evidence. The gateway MUST NOT use it in a policy decision, approver surfaces MUST NOT present it as proof of intent, and the ledger records it only so that entries can be deduplicated and correlated with the integration's own logs. The requester fields an auditor can rely on are `gateway_id` and `host` (SPEC §9).

---

## 3. Display templates

### 3.1 Registry

Each adapter ships a template registry: a JSON file listing, for each tool it exposes, one or more templates keyed by `template_id` and `template_version`. Templates are immutable once published; a change to the text MUST increment `template_version`.

```json
{
  "adapter": "github",
  "templates": [
    {
      "template_id": "github.merge_pull_request",
      "template_version": 1,
      "text": "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}",
      "sha256": "0280710fb0ac477803f2002b1c52027717ed45bc7e8da1ec79b87ec7754d75de"
    }
  ]
}
```

`@signeto/protocol` bundles the registries of the reference adapters (`github`, `postgres`, `alpaca`). Approver implementations MUST embed the registries of the protocol package version they build against. A gateway MAY also send a template's source alongside an approval request (§7.5, `template_source`); a device MUST treat that copy as unverified unless `template_id`, `template_version`, and `sha256` all match an entry in its embedded registry or an entry pinned at pairing time (§5.4).

### 3.2 Placeholder syntax

- A placeholder is `{path}` where `path` is a dotted path into `args_resolved`: `{repo}`, `{order.symbol}`, `{files.0}`. Path segments match `[A-Za-z0-9_]+`.
- `{{` and `}}` render as literal `{` and `}`.
- No conditionals, loops, filters, or formatting directives. Formatting is the adapter's job at resolution time (for example, `args_resolved.notional_usd = "512.00"`).
- Value rendering: strings verbatim; numbers, booleans, `null`, arrays, and objects as their JCS JSON text.
- The rendered line is the template text with placeholders replaced. Renderers MUST NOT trim, wrap, truncate, or reorder. Line wrapping for display is a presentation concern and MUST be applied after rendering, on a copy.

### 3.3 Renderer rules

1. The renderer takes exactly two inputs: the canonical bytes as received, and the template from the registry. It MUST NOT accept a separate display string, summary, or pre-rendered text from the gateway, relay, or agent.
2. The renderer parses the canonical bytes, reads `template_id` and `template_version` from the parsed object, looks the template up, and substitutes values from `args_resolved`.
3. Output MUST be byte-identical across gateway, CLI, phone, and web for the same bytes and the same registry. Conformance vectors (§9) exercise this.
4. Every approver surface MUST also show the full canonical bytes (pretty-printed is acceptable, with a toggle to the raw JCS string) and MUST show `requester`, `tier`, `mode`, and `expires_at` separately from the template line.
5. `mode: "advisory"` MUST be visibly labelled on every surface, with wording that says it can be bypassed. See SPEC §9.

### 3.4 Unknown or failing templates

If the template is not in the device's registry, the version is unknown, a placeholder path does not resolve, or `args_resolved` contains keys that no placeholder references, the device MUST:

- Show the raw canonical bytes as the primary content.
- Mark the request "unverified template" with a visible warning.
- Still allow approve and deny. The signature covers the bytes, not the rendering, so an unverified template does not weaken the receipt; it only weakens the human's understanding.

The "unreferenced key" rule exists so that an adapter cannot hide a material argument behind a template that does not mention it. Adapters whose templates intentionally omit arguments MUST list those keys in the template's `elide` array; the device then shows an "N hidden fields" disclosure instead of the warning.

---

## 4. Receipts

A receipt is the approver's signed decision about one canonical action. Approvals and denials are both receipts.

### 4.1 Fields

| Field | Type | Req | Meaning |
|---|---|---|---|
| `receipt_version` | string | MUST | `"1.0"`. |
| `action_id` | string | MUST | The gateway's `action_id` (§2.6), copied from the approval request. Unsigned routing handle. |
| `decision` | string | MUST | `"approve"` or `"deny"`. |
| `reason` | string | MAY | Free text entered by the approver. At most 512 UTF-8 bytes. Returned to the agent verbatim on denial. MUST NOT contain the matching policy rule. |
| `approver_id` | string | MUST | Account-level approver name as it appears in `signeto.yml` `approvers:`. |
| `device_id` | string | MUST | `dev_` + base64url RFC 7638 JWK thumbprint of the signing public key (§5.1). |
| `alg` | string | MUST | `"ES256"` or `"Ed25519"`. No other value is valid. |
| `signature` | string | MUST | base64url without padding. ES256: 64 bytes, `r || s` fixed-width (JWS form, not DER). Ed25519: 64 bytes. |
| `signed_at` | string | MUST | RFC 3339 UTC, §2.5 format. |
| `canonical_bytes_sha256` | string | MUST | Lowercase hex SHA-256 of the canonical bytes the device rendered and signed. |
| `webauthn` | object | MAY | Present if and only if the signature was produced by WebAuthn; `alg` MUST then be `"ES256"`. `{authenticator_data, client_data_json}`, both base64url without padding. See §4.4. |
| `relay_id` | string | MAY | Added by the relay on pass-through. Unsigned. Identifies the relay deployment. |

### 4.2 Signing input

The signing input is the UTF-8 encoding of the JCS serialization of:

```json
{
  "canonical_bytes_sha256": "<lowercase hex SHA-256 of canonical bytes>",
  "decision": "approve" | "deny",
  "reason": "<string, member omitted entirely when absent>",
  "signed_at": "<RFC 3339 UTC>"
}
```

- For `alg: "ES256"` the signature is ECDSA over P-256 with SHA-256 of the signing input (the standard ES256 construction; Secure Enclave `SecKeyCreateSignature` with `ecdsaSignatureMessageX962SHA256` then DER-to-raw conversion).
- For `alg: "Ed25519"` the signature is PureEdDSA over the signing input bytes directly.
- For WebAuthn, the challenge is the 32-byte SHA-256 of the signing input, and the signature is ECDSA P-256 over `authenticator_data || SHA-256(client_data_json)` as WebAuthn defines. The signing input is bound through `clientDataJSON.challenge`, not signed directly. See §4.4.

Why these four fields and nothing else:

- **`canonical_bytes_sha256` rather than the bytes themselves.** Secure Enclave and WebAuthn sign small fixed-size inputs cleanly; hardware tokens (P2) and QR/NFC transports have hard size limits. Hashing keeps the signed input under 200 bytes regardless of action size. Collision resistance of SHA-256 makes the hash as binding as the bytes. The device MUST compute this hash from the bytes it rendered, never accept a hash supplied by the relay or gateway; that rule is what makes "what you see is what you sign" hold.
- **`decision`.** A signature over the hash alone could be relabelled from deny to approve by anyone holding it. Binding the decision makes signed denials meaningful (SPEC §5, §9).
- **`reason`.** Bound so that the relay cannot attach or alter a reason the approver did not write.
- **`signed_at`.** Bounds the receipt in time independently of the action's expiry and lets the gateway enforce the skew rule in §2.5. It also makes two receipts for the same action by the same device distinguishable in the ledger.
- **Omitted:** `action_id`, `approver_id`, `device_id`, `alg`, `relay_id`. These are all either derivable from the verifying key the gateway already pinned or are routing hints. The gateway looks up the pinned key by `device_id` and verifies with that key; a swapped `device_id` fails verification. Binding them would add nothing and would make the signed input depend on relay-assigned values.
- **No domain separator.** Enrolled keys are generated for Signeto and used for nothing else (§5), so cross-protocol signature reuse is excluded by key hygiene rather than by prefixing. `receipt_version` MAJOR 2 MUST introduce a separator if keys ever become shared.

### 4.3 Receipt JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://signeto.dev/schemas/receipt-1.json",
  "title": "Signeto receipt 1.x",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "receipt_version", "action_id", "decision", "approver_id", "device_id",
    "alg", "signature", "signed_at", "canonical_bytes_sha256"
  ],
  "properties": {
    "receipt_version": { "type": "string", "pattern": "^1\\.(0|[1-9][0-9]*)$" },
    "action_id": { "type": "string", "pattern": "^act_[0-9A-HJKMNP-TV-Z]{26}$" },
    "decision": { "type": "string", "enum": ["approve", "deny"] },
    "reason": { "type": "string", "maxLength": 512 },
    "approver_id": { "type": "string", "minLength": 1, "maxLength": 64 },
    "device_id": { "type": "string", "pattern": "^dev_[A-Za-z0-9_-]{43}$" },
    "alg": { "type": "string", "enum": ["ES256", "Ed25519"] },
    "signature": { "type": "string", "pattern": "^[A-Za-z0-9_-]{86}$" },
    "signed_at": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    },
    "canonical_bytes_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "webauthn": {
      "type": "object",
      "additionalProperties": false,
      "required": ["authenticator_data", "client_data_json"],
      "properties": {
        "authenticator_data": { "type": "string" },
        "client_data_json": { "type": "string" }
      }
    },
    "relay_id": { "type": "string", "maxLength": 128 }
  }
}
```

### 4.4 WebAuthn receipts

The web approver signs with `navigator.credentials.get`. The challenge passed to WebAuthn MUST be the 32-byte SHA-256 of the signing input from §4.2 (not the signing input itself, and not the canonical bytes). The device fills `webauthn.authenticator_data` and `webauthn.client_data_json` from the assertion, base64url without padding, sets `alg: "ES256"`, and converts the DER ECDSA signature to raw `r || s`.

The verifier MUST, in addition to the generic steps in §4.5, and in this order:

1. Decode `client_data_json`; require `type == "webauthn.get"`.
2. Rebuild the signing input itself (§4.5 step 11), hash it with SHA-256, and require `challenge` (base64url) to equal base64url of that hash.
3. Require `origin` to be in the gateway's configured allow-list of approver origins. The default allow-list is empty; an empty list rejects every WebAuthn receipt.
4. Require the RP ID hash in `authenticator_data` to equal SHA-256 of the configured RP ID, and the user-present flag to be set. User-verified SHOULD be required and MUST be required for Tier 3.
5. Verify `signature` over `authenticator_data || SHA-256(client_data_json)` with the pinned key.

Steps 1 to 4 run before step 5 so that an assertion from the wrong origin or for the wrong challenge never reaches the cryptographic check.

### 4.5 Verification algorithm

A gateway MUST perform every step below, in order, and MUST stop at the first failure. Any failure means the action is not executed. The listed code is the rejection reason recorded in the ledger and returned to the relay.

1. Parse the receipt against the schema in §4.3. Failure: `receipt_malformed`.
2. Check `receipt_version` MAJOR is implemented. Failure: `receipt_version_unsupported`.
3. Look up the action by `action_id` in local storage. Not found: `approval_not_found`. Status not `pending`: `approval_already_decided`.
4. Check the gateway's clock is not past the action's `expires_at`. Failure: `action_expired`.
5. Look up the device by `device_id` among devices paired with this gateway. Not found: `unknown_device`. Revoked: `device_revoked`.
6. Check the device's pinned key algorithm equals `alg`. Mismatch: `alg_not_allowed`.
7. Check `approver_id` equals the approver recorded for the device at pairing. Mismatch: `approver_mismatch`.
8. Check the device (or its approver) satisfies the action's tier and policy rule: Tier 2 any paired device; Tier 3 the named approver or quorum member. Failure: `approver_not_permitted`.
9. Compute SHA-256 of the gateway's own stored canonical bytes. Compare to `canonical_bytes_sha256`. Mismatch: `hash_mismatch`.
10. Check `signed_at` is within `[issued_at - 60 s, expires_at + 60 s]`. Failure: `clock_skew`.
11. Rebuild the signing input from the gateway's own hash, the receipt's `decision`, `reason` (omitted if absent), and `signed_at`.
12. Verify the signature with the pinned public key: ES256 or Ed25519 per §4.2, or the WebAuthn procedure in §4.4 if `webauthn` is present. If `webauthn` is present and `alg` is not `ES256`: `receipt_malformed`. Failure: `invalid_signature`.
13. Atomically check and record the action's `nonce` in the single-use store. Already present: `nonce_reused`. The nonce MUST be marked used before any execution begins. The store is a table in the same SQLite database as the ledger, written in the same transaction as the ledger entry, and survives restarts; §4.7 defines how a restore from backup is detected. For a quorum action (§4.8) this step runs once, when the receipt that meets the threshold arrives.
14. If `decision == "deny"`: set status `denied`, ledger the receipt, return `reason` to the agent. Stop. For a quorum action a single valid denial from any approver the rule names denies the action regardless of approvals already collected (§4.8).
15. If the rule requires a quorum and the threshold is not yet met: store the receipt, keep status `pending`, stop (§4.8). Otherwise, if `effective_at` is present and in the future: set status `approved`, schedule execution for `effective_at`, keep the action cancellable until then. Otherwise set status `approved` and proceed to execution with the stored bytes.

Standalone verifiers (`signeto verify receipt.json`, P1) perform steps 1, 2, 9, 10, 11, 12 against a supplied action, receipt, and public key, and report the result without consulting a nonce store.

### 4.6 Rejection reasons

| Code | Step | Meaning |
|---|---|---|
| `receipt_malformed` | 1, 12 | Schema violation or inconsistent fields. |
| `receipt_version_unsupported` | 2 | Unknown MAJOR. |
| `approval_not_found` | 3 | No such `action_id` at this gateway. |
| `approval_already_decided` | 3 | Action is not pending. |
| `action_expired` | 4 | Gateway clock past `expires_at`. |
| `unknown_device` | 5 | `device_id` not paired with this gateway. |
| `device_revoked` | 5 | Device revoked before `signed_at`. |
| `alg_not_allowed` | 6 | `alg` is not the pinned key's algorithm. |
| `approver_mismatch` | 7 | `approver_id` does not own `device_id`. |
| `approver_not_permitted` | 8 | Device or approver cannot satisfy the tier. |
| `hash_mismatch` | 9 | Signed hash differs from the gateway's bytes. |
| `clock_skew` | 10 | `signed_at` outside the tolerance window. |
| `invalid_signature` | 12 | Cryptographic verification failed. |
| `nonce_reused` | 13 | Replay. |
| `nonce_store_behind` | startup | Nonce store `seq` is behind the chain head; gateway refuses to start until `signeto ledger repair` runs (§4.7). |

### 4.7 Nonce store durability

The nonce store is a table in the gateway's ledger database (`docs/ledger.md` §4). Each row records the nonce, the `action_id`, and the ledger `seq` of the entry written in the transaction that consumed it. The chain head (§7.10) carries the ledger's monotonic `seq`.

On start the gateway MUST compare the highest `seq` referenced by the nonce store with the highest chain head `seq` it has signed, as recorded in the `chain_head` table and in the local heads file (`docs/ledger.md` §6). If the nonce store is behind, the database was restored from a backup taken before heads the gateway already published, and nonces consumed after that point would be usable again. The gateway MUST refuse to start with `nonce_store_behind` until the operator runs `signeto ledger repair`. Repair appends a `fail_closed` entry naming the condition and then marks every action issued before the chain head `seq` that has no terminal entry as `expired`, each with its own ledger entry. Those actions can never be approved; a retry creates a new action with a new nonce (§6.3). A restore therefore cannot make an already-used nonce usable again.

### 4.8 Quorum

A Tier 3 rule MAY require a quorum (`quorum: N` in `signeto.yml`, P2). The rule names the eligible approvers. The gateway MUST require N receipts with `decision: "approve"` that all carry the same `canonical_bytes_sha256`, from N distinct paired devices belonging to N distinct approvers named by the rule. Each receipt is an independent signature over its own signing input (§4.2): the receipts agree on `canonical_bytes_sha256` and `decision` and differ only in `signed_at`, `reason`, and signer. Receipts are not chained; the second signer signs the same canonical bytes, not the first receipt. Two receipts from devices of the same approver count once.

Each receipt is verified with §4.5 steps 1 to 12 as it arrives and stored. The action becomes `approved` when the N-th valid approval arrives before `expires_at`; the nonce is consumed at that moment (step 13) and execution proceeds. If `expires_at` passes first the action is `expired`. A single valid receipt with `decision: "deny"` from any approver the rule names denies the action immediately, whatever approvals have accumulated; the denial is ledgered with the approvals collected so far. The ledger `approved` entry carries every contributing receipt in `receipts[]` (`docs/ledger.md` §3).

---

## 5. Pairing handshake

Pairing establishes mutual key pinning between one gateway and one approver device. The relay carries the messages and learns both public keys; it cannot substitute either one.

### 5.1 Keys and identifiers

- **Gateway key.** Generated at `signeto init`. Ed25519 RECOMMENDED; ES256 permitted. Stored under the same protection as credentials (SPEC §9). Used to authenticate to the relay (§7.1), to sign pairing confirmations, to sign every approval request (`gateway_signature`, §7.5), and to sign chain heads (§7.10). Never used to sign receipts.
- **Device key.** Generated in secure hardware where available (Secure Enclave, WebAuthn authenticator, StrongBox). ES256 for hardware keys; Ed25519 permitted for software keys, which MUST be labelled `software: true` at enrollment and shown as such in policy lint output and ledger entries.
- **Public key encoding.** JWK (RFC 7517). ES256: `{"kty":"EC","crv":"P-256","x":...,"y":...}`. Ed25519: `{"kty":"OKP","crv":"Ed25519","x":...}`.
- **Identifiers.** `gateway_id = "gw_" + base64url(RFC 7638 JWK thumbprint, SHA-256)`; `device_id = "dev_" + base64url(thumbprint)`. 43 characters after the prefix. Identifiers are therefore derived from keys and cannot be chosen by the relay.
- **Fingerprint for humans.** The first 16 hex characters of the thumbprint, grouped in fours: `3fa9 1c02 b77e d410`. Both sides display the other's fingerprint at the end of pairing.

### 5.2 QR payload

The gateway generates a 128-bit pairing code from a CSPRNG and prints a QR encoding the URI `signeto://pair?d=<base64url(JCS(payload))>` where `payload` is:

```json
{
  "v": 1,
  "gateway_public_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "gateway_name": "home-01",
  "relay": "https://relay.signeto.dev",
  "code": "<22-char base64url, 16 random bytes>",
  "expires_at": "2026-11-05T18:14:09.000Z"
}
```

The QR MUST expire within 10 minutes. The CLI MUST also print the same payload as a manual-entry string for devices without a camera.

The gateway registers the pairing with the relay by sending only `SHA-256(code)` (§7.3). The relay never sees `code`. Everything that reaches the relay is therefore either public (keys) or useless without the code (proofs).

### 5.3 Handshake

```mermaid
sequenceDiagram
    participant G as Gateway
    participant R as Relay
    participant D as Approver device

    G->>G: generate code (128-bit), pairing_id = base64url(SHA-256(code))[0:22]
    G->>R: POST /v1/pairings {pairing_id, code_hash, expires_at}  [gateway-signed]
    G-->>D: QR: gateway_public_key, relay, code, expires_at  (out of band)
    D->>D: verify QR expires_at; compute gateway_id from key
    D->>D: proof = HMAC-SHA256(key=code, msg=JCS{gateway_id, device_id, device_public_key})
    D->>R: POST /v1/pairings/{pairing_id}/claim {device_public_key, attestation, proof}  [device-signed]
    R->>G: event pairing.claimed {pairing_id, device_public_key, attestation, proof}
    G->>G: recompute proof with own code; verify; verify attestation; pin device key
    G->>G: confirmation = Sign_gw(JCS{gateway_id, device_id, pairing_id, paired_at, templates_pinned})
    G->>R: POST /v1/pairings/{pairing_id}/confirm {confirmation, paired_at, templates_pinned}
    R->>D: push {pairing_id}; D fetches GET /v1/pairings/{pairing_id}
    D->>D: verify confirmation with gateway_public_key from QR; pin gateway key
    D-->>G: both display fingerprints; pairing complete
```

Normative points:

1. The device MUST take the gateway public key from the QR, never from the relay. The relay's copy of the key is informational.
2. The device MUST compute `proof` over its own `device_id` and the QR's `gateway_id`. The gateway MUST recompute the proof from the device key it received and its own code. A relay that substitutes a device key cannot produce a matching proof because it holds only `SHA-256(code)`.
3. The gateway MUST verify the attestation where the platform provides one (App Attest, WebAuthn attestation, Android Key Attestation) and MUST record `software: true` when none is provided or the policy permits software keys.
4. The device MUST verify `confirmation` with the QR's key before pinning. A confirmation that fails verification MUST abort pairing on the device side, and the device SHOULD tell the user the relay or network may be hostile.
5. The gateway MUST reject a claim after `expires_at` or a second claim for the same `pairing_id`.
6. The pairing record on both sides stores: the peer's public key, the peer's identifier, `paired_at`, `attestation` (gateway side), and `software` flag.

### 5.4 Template pinning at pairing

The gateway's confirmation carries `templates_pinned`: a list of `{template_id, template_version, sha256}` for custom adapters not bundled in `@signeto/protocol`, `[]` when there are none. The list is part of the confirmation's signing input, which is the UTF-8 JCS serialization of

```json
{ "device_id": "dev_...", "gateway_id": "gw_...", "paired_at": "...", "pairing_id": "...", "templates_pinned": [ { "sha256": "<hex>", "template_id": "...", "template_version": 1 } ] }
```

with the list in the order the gateway sent it and each entry having exactly those three members. The device MUST verify the confirmation over the list it received, and MUST NOT store any pin from a confirmation that does not verify: a relay that adds, drops, reorders or alters a pin breaks the signature, and pairing aborts with `pairing_confirmation_invalid`. The device stores the verified list under the gateway's record. A later `template_source` sent with an approval request (§7.5) is verified against this list; a match renders as a verified template.

### 5.5 What the relay can and cannot do after pairing

The relay can:

- Deliver approval requests to paired devices and receipts to gateways.
- Delay, drop, or reorder messages. All of these fail closed: the action expires.
- See canonical bytes (the action content) and receipts. Canonical bytes are not secret from the relay; they are secret from lock screens and push transports.
- Observe which gateway talks to which device and when.

The relay cannot:

- Produce a receipt that a gateway accepts, because it holds no device private key.
- Substitute a device key or gateway key, because pinning is complete and the proof/confirmation exchange detects substitution during pairing.
- Fabricate an approval request, or alter one in transit, and have a device render it: every request carries `gateway_signature` (§7.5) and the device verifies it against the pinned gateway key before rendering. A request that fails is never shown.
- Alter a canonical action in transit without the device's hash failing to match the gateway's bytes (§4.5 step 9), even if the device-side check were somehow skipped.
- Alter a receipt's decision or reason without invalidating the signature.
- Unfreeze a frozen gateway (§7.9: a freeze set by a device is signed; the local freeze file wins).

---

## 6. Approval request lifecycle

### 6.1 States

```
pending ──▶ approved ──▶ executed
   │            │   └───▶ failed
   │            └───────▶ cancelled   (only while effective_at is in the future)
   ├──▶ denied
   ├──▶ expired
   └──▶ cancelled   (agent, gateway shutdown, or freeze)
```

| State | Terminal | Entered when |
|---|---|---|
| `pending` | no | Canonical action built and (Tier 2/3) submitted to relay. Tier 1 actions pass through `pending` to `approved` without a receipt. |
| `approved` | no | Valid approval receipt verified (§4.5). For Tier 1, policy decision. |
| `denied` | yes | Valid denial receipt verified. |
| `expired` | yes | Gateway clock passed `expires_at` without a verified receipt. |
| `executed` | yes | Upstream call returned. Result ledgered. |
| `failed` | yes | Upstream call failed, token minting failed, or any fail-closed condition after approval. |
| `cancelled` | yes | Agent cancelled the MCP request, gateway shut down, freeze engaged, or approver cancelled during cooling-off. |

A receipt that arrives for an action not in `pending` is rejected with `approval_already_decided` and ledgered as such; the receipt itself is retained for audit.

### 6.2 Approval flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant G as Gateway
    participant R as Relay
    participant D as Approver device
    participant U as Upstream API

    A->>G: MCP tools/call github.merge_pull_request {...}
    G->>G: policy match → tier 3; resolve args; build canonical bytes; nonce; expiry
    G->>G: idempotency_key lookup → new action, status pending; ledger "requested"
    G->>R: POST /v1/approvals {action_id, canonical_bytes, expires_at, targets, gateway_signature}  [gateway-signed]
    R-->>G: 201 {approval_id}
    R->>D: push {approval_id}
    loop every 15 s until terminal
        G-->>A: MCP progress notification (pending, seconds remaining)
    end
    D->>R: GET /v1/approvals/{approval_id}  [device-signed]
    R-->>D: {canonical_bytes, gateway_id, expires_at, gateway_signature, template_source?}
    D->>D: verify gateway_signature with pinned gateway key; if it fails, log and do not render
    D->>D: parse; render from bytes; show requester, tier, mode, countdown
    D->>D: biometric; hash bytes; build signing input; sign
    D->>R: POST /v1/approvals/{approval_id}/receipt {receipt}  [device-signed]
    R->>G: event receipt {approval_id, action_id, receipt}
    G->>G: verify (§4.5); mark nonce; status approved; ledger "approved"
    G->>U: mint scoped token; execute frozen bytes
    U-->>G: result
    G->>G: status executed; ledger "executed"; discard token
    G->>R: POST /v1/approvals/{approval_id}/status {status: executed}
    G-->>A: MCP tool result
```

### 6.3 Idempotent retry

When a gated tool call arrives, the gateway computes `idempotency_key` (§2.4) before generating a nonce.

- If an action with that key exists and is `pending` or `approved` (unexecuted), the gateway MUST NOT create a new action. It reattaches the caller to the existing one: blocking mode waits on it; async mode returns its `action_id`.
- If the existing action is `executed`, the gateway MUST return the stored result without executing again, for as long as the record is retained (at least 24 hours).
- If the existing action is `denied`, `expired`, `failed`, or `cancelled`, the gateway creates a new action with a new nonce. The ledger links it to the prior action by `idempotency_key`.
- A relay MUST treat a repeated `POST /v1/approvals` with the same `action_id` as the same request and return the original `approval_id` (§7.5).

### 6.4 Wait semantics

**Blocking (default).** The MCP tool call does not return until the action is terminal. While pending, the gateway MUST emit MCP progress notifications at least every 15 seconds carrying `{status: "pending", action_id, expires_at, seconds_remaining}` as the progress message. On `denied` the tool result is an error whose text is the approver's `reason` if present, else "Denied by approver". On `expired` the text is "Approval expired". The tool result MUST NOT reveal which policy rule matched.

**Async.** Enabled per tool or per call by policy (`wait: async`). The tool returns immediately with:

```json
{ "status": "pending", "action_id": "act_...", "expires_at": "...", "check": "signeto.check_approval" }
```

The gateway exposes `signeto.check_approval {action_id}` which returns `{status, result?, reason?, expires_at?, effective_at?}`. `result` is present only when `status == "executed"`. Async mode is REQUIRED for actions whose `effective_at` exceeds the blocking timeout and for standing-mandate issuance (P1).

**Timeout.** The blocking timeout equals the action's expiry. There is no separate timeout: if the agent's client disconnects, the action continues to its own terminal state, and a retry reattaches (§6.3).

### 6.5 Fail-closed rules

The gateway MUST NOT execute, and MUST set `failed` or leave the action to expire, when any of the following holds:

1. The relay is unreachable at submit time and no other paired channel (local CLI approval) is configured. Submit MUST NOT be retried past `expires_at`.
2. A receipt fails any step in §4.5.
3. The nonce store is unavailable (step 13 cannot be performed atomically).
4. The credential store or token minting fails.
5. The freeze flag is set locally or via the relay (§7.9) at any point before execution begins. A freeze observed after `approved` but before execution MUST cancel the action.
6. The policy file hash at execution time differs from the hash at build time (policy changed under a pending action).
7. The gateway process cannot write the ledger entry for the state transition.
8. The action's `expires_at` has passed, even by one millisecond, on the gateway's clock.

Every fail-closed event MUST produce a ledger entry with the condition and SHOULD trigger the alert hook (SPEC §5 P1 observability).

Chain-head publication is deliberately absent from this list. A failure to publish a head to the relay or to a git target (§7.10) is retried with backoff and alerted, and the gateway keeps approving: the local ledger is the authoritative chain and the relay is transport only. SPEC §9 names this as the one exception to fail-closed; `docs/ledger.md` §6 has the retry and alert rules.

### 6.6 Batches (P1)

A batch is a set of steps that share a `batch_id`. Every step is its own canonical action with `batch_id`, `batch_index`, and `atomic` inside its bytes (§2.1), so a step cannot be executed outside the plan it was built for. All steps of one batch share `issued_at` and `expires_at`.

**`atomic: true` (default).** The gateway builds every step, then submits one approval request (§7.5) whose `canonical_bytes` is the batch manifest: the JCS serialization of

```json
{ "protocol_version": "1.0", "batch_id": "<22-char>", "atomic": true, "expires_at": "<RFC 3339 UTC>", "steps": [ "<hex SHA-256 of step 0 canonical bytes>", "<hex SHA-256 of step 1 canonical bytes>" ] }
```

The request also carries every step's canonical bytes (`steps[]` in the request body) so the device can render each one. The device MUST hash each step it rendered and require the list to equal `manifest.steps` in order; a mismatch is `hash_mismatch` and the device MUST NOT sign. One receipt over the manifest (its `canonical_bytes_sha256` is the SHA-256 of the manifest bytes) approves every step. The gateway verifies it per §4.5 against its stored manifest bytes, consumes every step's nonce in one transaction, releases no token or credential until that point, and executes steps in `batch_index` order. If any step fails, the gateway MUST NOT execute the remaining steps: it sets each remaining step to `cancelled` and writes one `batch_aborted` ledger entry (`docs/ledger.md` §3).

**`atomic: false`.** Each step is submitted as its own approval request and carries its own receipt. Steps are approved, denied, or expire independently; a failed step does not affect the others. `batch_id` is then a grouping key for the approver's inbox and the ledger, nothing more.

---

## 7. Relay API

### 7.1 Conventions

- Base path `/v1`. JSON request and response bodies, `Content-Type: application/json`. TLS REQUIRED.
- Identifiers: `approval_id` is `apr_` + ULID assigned by the relay; `pairing_id` is derived by the gateway (§5.3); `relay_id` is a stable string chosen by the relay operator.
- Canonical bytes are transported as a JSON string containing the exact JCS text (`canonical_bytes`). Because the JCS text is itself JSON, implementers MUST take care to transmit it as a string, not re-embed it as an object; the receiver MUST use the string's UTF-8 bytes directly.
- Three authentication schemes:
  - `Bearer <session>` — account session obtained by email + passkey login. Used for account-level operations: gateway registration, device enrollment.
  - `Signeto-Gateway <gateway_id>.<ts>.<sig>` — request signed by the gateway key. `sig` is base64url of the signature over the signing input `JCS({"method", "path", "ts", "body_sha256"})`. `ts` is RFC 3339; the relay MUST reject requests whose `ts` is more than 60 s from its clock. `body_sha256` is the hex SHA-256 of the raw request body, or of the empty string when there is none.
  - `Signeto-Device <device_id>.<ts>.<sig>` — same construction with the device key. For WebAuthn devices, the relay issues a device session token at enrollment instead, delivered as `Bearer`, because WebAuthn cannot sign arbitrary requests without a user gesture; such sessions MUST be scoped to read-only approval fetches, and receipt submission is still authenticated by the receipt's own signature.
- Signed request details (`@signeto/protocol` `signRelayRequest` / `verifyRelayRequest`, vectors in `relay-auth/`):
  - `method` is the HTTP method in upper case.
  - `path` is the request-target exactly as sent on the request line (RFC 9112 origin-form): the absolute path plus `?` and the query string when present, byte for byte, percent-encoding untouched. No scheme, host, port or fragment. A relay behind a proxy that rewrites paths MUST verify against the path the client sent.
  - `ts` uses the §2.5 format (UTC, exactly three fractional digits, `Z`). The window is ±60 s inclusive.
  - `body_sha256` hashes the body bytes as transmitted, before any JSON parsing; a re-serialized body does not verify. With no body it is `e3b0c442…b855`, the SHA-256 of the empty string.
  - The signature is the key's own algorithm over the UTF-8 signing input: Ed25519 over the bytes, ES256 over their SHA-256 with raw `r || s`; `sig` is 86 base64url characters without padding.
  - The header is `<scheme> <key_id>.<ts>.<sig>` with one space. `ts` contains a `.`, so the credential is split at its first and last `.` (neither ids nor base64url contain one). The scheme name is case-insensitive; the rest is not. `key_id` MUST be `gw_…` under `Signeto-Gateway` and `dev_…` under `Signeto-Device` and MUST equal the thumbprint id of the registered key.
  - The relay MUST refuse a second request carrying the same `(key_id, sig)` within 120 s (replay). Ed25519 is deterministic, so a client retrying a request MUST re-sign it with a fresh `ts`.
  - Order of checks: header shape, registered key, key id matches the key, `ts` window, signature, revocation, replay, rate limit. Revocation is reported only after the signature verifies.
  - Failures are `401` with code `unauthorized`, except `clock_skew` (stale or future `ts`) and `device_revoked` (signature valid, device revoked), which are also `401` so a client can tell resynchronising its clock from re-enrolling.
- Errors: HTTP status plus body `{"error": {"code": "<§8 code>", "message": "<human text>", "retry_after"?: seconds}}`. A `429` also carries a `Retry-After` header.
- Every response carries `X-Signeto-Relay-Id`, including errors.
- Request objects are strict: an unknown member is `request_malformed` rather than ignored. Bodies larger than the relay's limit (256 KiB by default) are `413 request_malformed`.

### 7.2 Gateway registration

`POST /v1/gateways` — auth `Bearer` (account session)

Request:
```json
{ "public_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." }, "name": "home-01", "protocol_versions": ["1.0"] }
```
Response `201`:
```json
{ "gateway_id": "gw_...", "relay_id": "relay-eu-1", "created_at": "..." }
```
Errors: `401 unauthorized`, `409 gateway_exists` (same thumbprint already registered to another account, or a revoked key registered again), `422 key_invalid` (not an EC P-256 or OKP Ed25519 public JWK, coordinates not 32 bytes, point not on the curve, or private member `d` present), `422 unsupported_protocol_version` (no `1.x` in `protocol_versions`), `403 gateway_limit` (plan gateway limit; Free allows one active gateway). Re-registering the same key on the same account while it is active returns `200` with the same body. The relay stores only the RFC 7638 required members of the JWK.

`DELETE /v1/gateways/{gateway_id}` — auth `Signeto-Gateway` (the gateway itself) or `Bearer` (its account). Revokes; a revoked key can no longer authenticate and its approvals are no longer served. Response `204`, also when already revoked. Errors: `403 forbidden` (another gateway), `404 not_found`.

### 7.3 Pairing

`POST /v1/pairings` — auth `Signeto-Gateway`

Request: `{ "pairing_id": "...", "code_hash": "<hex SHA-256(code)>", "expires_at": "..." }`
Response `201`: `{ "pairing_id": "...", "status": "open" }`
Errors: `409 pairing_exists`, `422 pairing_expired` (expiry in the past or more than 10 min plus the 60 s skew allowance out), `422 request_malformed` (`pairing_id` is not `base64url(code_hash bytes)[0:22]`; both derive from the same SHA-256, so the relay checks they agree).

`POST /v1/pairings/{pairing_id}/claim` — auth `Signeto-Device` (or `Bearer` device session for WebAuthn)

Request:
```json
{
  "device": { "public_key": {...}, "platform": "ios", "name": "iPhone 17", "attestation": { "format": "apple-appattest", "data": "..." }, "software": false },
  "proof": "<base64url HMAC-SHA256>"
}
```
Response `200`: `{ "status": "claimed" }`
Errors: `404 pairing_not_found` (also when the pairing belongs to a gateway of another account: a device claims only pairings opened by its own account's gateways), `410 pairing_expired`, `409 pairing_already_claimed`, `403 forbidden` (`device.public_key` is not the authenticated device's enrolled key). The relay does not verify `proof`; it cannot. It forwards `device` exactly as sent (the proof covers the JWK as the device serialised it) in the `pairing.claimed` event.

`GET /v1/pairings/{pairing_id}` — auth `Signeto-Gateway` or the claiming device
Response `200`: `{ "pairing_id": "...", "status": "open" | "claimed" | "confirmed" | "rejected" | "expired", "device_id"?: "dev_...", "device"?: {...}, "proof"?: "...", "confirmation"?: "...", "paired_at"?: "...", "templates_pinned"?: [...] }`. `expired` is reported for an `open` or `claimed` pairing past `expires_at`. Anyone other than the owning gateway and the claiming device gets `404 pairing_not_found`.

`POST /v1/pairings/{pairing_id}/confirm` — auth `Signeto-Gateway`
Request: `{ "confirmation": "<base64url Sign_gw>", "paired_at": "...", "templates_pinned": [ { "template_id", "template_version", "sha256" } ] }`
Response `200`: `{ "status": "confirmed" }`. The relay pushes `{pairing_id}` to the device. Repeating the identical confirmation returns `200`; a different one for a confirmed pairing is `409 pairing_already_claimed`. The relay does not verify `confirmation`; the device does, with the QR's key. A confirmed pairing is what makes a device "paired with this gateway" for §7.5 and §7.6.
Errors: `409 pairing_not_claimed` (open or rejected), `410 pairing_expired`.

`POST /v1/pairings/{pairing_id}/reject` — auth `Signeto-Gateway`. Proof failed on the gateway. Response `204` (also when already rejected); status becomes `rejected`. Rejecting a confirmed pairing withdraws it: the device is no longer paired with that gateway. The relay SHOULD notify the device and MUST ledger the event in its audit mirror.

### 7.4 Device enrollment

`POST /v1/devices` — auth `Bearer` (account session)

Request:
```json
{ "public_key": {...}, "platform": "ios" | "web" | "macos-cli" | "android", "name": "...", "attestation": {...} | null, "push": { "kind": "apns" | "webpush" | "none", "token": "..." } }
```
Response `201`: `{ "device_id": "dev_...", "approver_id": "jason", "enrolled_at": "...", "software": false, "attestation_status": "none" | "unverified" | "verified", "device_session"?: "<token>" }`
`software` is `false` only when the relay has verified a hardware attestation for this key; a relay that does not verify attestation reports `true` for every key and `attestation_status: "unverified"` when one was supplied (the gateway still runs its own check at pairing, §5.3 point 3). `device_session` is present for `platform: "web"` only: the device `Bearer` token of §7.1, shown once. `push` is optional (default `{ "kind": "none" }`); `token` is required for `apns` and `webpush`.
Errors: `422 key_invalid`, `422 attestation_invalid` (not `{format, data}`, or attestation on an Ed25519 key), `409 device_exists` (thumbprint already enrolled, in any account or state), `403 device_limit` (free tier: two active devices).

`DELETE /v1/devices/{device_id}` — auth `Bearer` or `Signeto-Device` (an enrolled device of the same account, including the device itself). Revokes, and revokes its device session. Response `204`, also when already revoked. `404 not_found` for a device of another account. The relay MUST propagate `device.revoked` to every gateway the device is paired with (§7.8). Gateways MUST then refuse receipts from it (§4.5 step 5).

### 7.5 Submit approval request

`POST /v1/approvals` — auth `Signeto-Gateway`

Request:
```json
{
  "action_id": "act_...",
  "canonical_bytes": "{\"args_resolved\":{...},...}",
  "expires_at": "...",
  "targets": { "tier": 3, "approver_ids": ["jason"], "device_ids": [] },
  "template_source": { "template_id": "...", "template_version": 1, "text": "...", "sha256": "...", "elide": [] },
  "gateway_signature": "<base64url Sign_gw(JCS{canonical_bytes_sha256, action_id, expires_at, nonce, gateway_id})>"
}
```
`targets.device_ids` empty means every device of the listed approvers (Tier 2: every device paired with this gateway). `template_source` is OPTIONAL. `steps` (OPTIONAL, atomic batches only, §6.6) is an array of each step's canonical bytes as strings in `batch_index` order; when present, `canonical_bytes` is the batch manifest.

`gateway_signature` is REQUIRED on every approval request, whatever the transport (relay, local socket §7.11, or any push payload that carries content). Its signing input is the UTF-8 JCS serialization of

```json
{ "action_id": "act_...", "canonical_bytes_sha256": "<hex SHA-256 of canonical_bytes>", "expires_at": "...", "gateway_id": "gw_...", "nonce": "<22-char>" }
```

where `nonce` and `gateway_id` are the values inside `canonical_bytes` (`nonce` and `requester.gateway_id`), and `expires_at` equals the canonical action's `expires_at`. The signature is produced with the gateway key (§5.1) in that key's algorithm (Ed25519: over the bytes; ES256: over their SHA-256), base64url without padding. The relay stores and forwards the field unmodified; it MUST NOT verify it as a condition of acceptance and cannot produce one. Before rendering, the device MUST rebuild the signing input from the request it received, look up the gateway key pinned at pairing for `gateway_id`, and verify. A request whose `gateway_id` is not pinned or whose signature fails MUST NOT be rendered or offered for signing; the device logs it locally as `gateway_signature_invalid` and MAY report it to the relay. Nothing the relay can send puts a card in front of the user without the gateway key.
Response `201`: `{ "approval_id": "apr_...", "action_id": "act_...", "status": "pending" }`
Repeated submission with the same `action_id` from the same gateway returns `200` with the original `approval_id` and current status; the stored request is not replaced.
Errors: `409 frozen` (account freeze set; relay refuses to queue), `422 action_expired` (`expires_at` not in the future), `422 request_malformed` (`expires_at` more than 5 min plus 60 s out, or a malformed body), `422 targets_invalid`, `429 rate_limited`.

The relay does not parse `canonical_bytes` (it may be a batch manifest) and stores it, `steps`, and `gateway_signature` as received. `targets.tier` is `2` or `3`. `targets_invalid` covers: an approver id that is not an approver of the gateway's account, a device id that is not an active device paired with this gateway, a malformed `targets` object, and targets that match no paired device (nobody could approve). Recipients are the active devices paired with the gateway that match `device_ids` if non-empty, else `approver_ids` if non-empty, else all of them; each receives a push carrying only `approval_id`.

`POST /v1/approvals/{approval_id}/status` — auth `Signeto-Gateway`
Request: `{ "status": "approved" | "denied" | "executed" | "failed" | "cancelled" | "expired", "at": "..." }`. Lets devices show the outcome. Response `204`. `approved` is not terminal (receipts are still accepted, e.g. for a cooling-off cancellation); the others are. Repeating the current status is `204`; any change from a terminal status, or `approved` → `denied`, is `409 approval_already_decided`. `404 approval_not_found` for another gateway's approval.

### 7.6 Fetch pending (device)

`GET /v1/approvals?status=pending` — auth `Signeto-Device` or device `Bearer`
Response `200`:
```json
{ "approvals": [ { "approval_id": "apr_...", "gateway_id": "gw_...", "expires_at": "...", "tier": 3 } ] }
```
List entries carry no action content; the device fetches each on open.

`GET /v1/approvals/{approval_id}` — same auth
Response `200`:
```json
{
  "approval_id": "apr_...", "action_id": "act_...", "gateway_id": "gw_...", "gateway_name": "home-01",
  "canonical_bytes": "...", "expires_at": "...", "status": "pending",
  "gateway_signature": "...",
  "template_source": {...} | null, "receipts": [ {...} ]
}
```
`gateway_signature` is the value the gateway submitted (§7.5), returned verbatim; the device verifies it before rendering. `receipts` lists receipts already accepted for this approval (quorum, §4.8).
Errors: `404 approval_not_found` (unknown, another account's, or its gateway revoked), `403 forbidden` (device not among targets or not paired with the gateway). `status` reads `expired` once `expires_at` has passed without a terminal status. The response also carries `tier`, `targets`, and `steps` when the request had them. The list returns only `pending` approvals that have not expired; `status` is optional and `pending` is its only accepted value.

### 7.7 Submit receipt

`POST /v1/approvals/{approval_id}/receipt` — auth `Signeto-Device` or device `Bearer`
Request: the receipt object (§4.1) without `relay_id`.
Response `202`: `{ "accepted": true, "relay_id": "..." }`

The relay MUST validate only the schema (§4.3) and that `action_id` matches the approval. It MUST NOT verify the signature as a condition of acceptance, MUST NOT alter any field, and MUST attach `relay_id` before forwarding. It stores the receipt and forwards it to the gateway over the subscription (§7.8). Multiple receipts for one approval (quorum, P2) are each forwarded.

Errors: `404 approval_not_found`, `403 forbidden` (submitting device may not fetch this approval, §7.6), `409 approval_already_decided` (gateway already reported a terminal status), `410 action_expired`, `422 receipt_malformed` (schema, `action_id` mismatch, or `relay_id` already present: only the relay sets it). The relay does not require `receipt.device_id` to equal the submitting device.

### 7.8 Gateway subscribe

`GET /v1/gateways/{gateway_id}/events` — auth `Signeto-Gateway`

Two transports, same event format. The gateway MUST support long-poll; WebSocket is OPTIONAL for both sides.

- **WebSocket.** `Upgrade: websocket`. Auth header on the upgrade request. Server sends one JSON event per text frame. Client sends `{"ack": "<cursor>"}` frames. Server MUST ping every 30 s.
- **Long-poll.** `?since=<cursor>&wait=30`. Returns `200 { "events": [...], "cursor": "..." }` as soon as at least one event is available or after `wait` seconds with an empty list. `wait` MUST be clamped to 60. `wait` defaults to 0 (return at once). `cursor` in the response is the last event's cursor, or `since` when the list is empty; pass it back as `since`. Cursors are decimal strings that increase in commit order. A cursor the relay never issued (higher than any it holds, e.g. after a relay database reset) is treated as missing. A page holds at most 100 events; poll again with the returned cursor.

Event envelope: `{ "cursor": "...", "type": "<type>", "at": "...", "data": {...} }`

| Type | Data |
|---|---|
| `receipt` | `{approval_id, action_id, receipt}` |
| `pairing.claimed` | `{pairing_id, device, proof}` |
| `device.revoked` | `{device_id, revoked_at}` |
| `freeze` | `{frozen: true|false, set_by_device_id, signed_at, signature}` (§7.9) |
| `approval.cancelled` | `{approval_id, by_device_id, reason?}` — cooling-off cancellation from a device, carried as a signed denial receipt in `data.receipt` |

Events are retained for at least 24 hours. A gateway that reconnects with a stale or missing cursor receives all retained events. Delivery is at-least-once; gateways MUST be idempotent on `cursor`.

### 7.9 Freeze flag

`PUT /v1/accounts/me/freeze` — auth `Signeto-Device` (signed; WebAuthn devices use the receipt-style WebAuthn assertion)
Request: `{ "frozen": true, "signed_at": "...", "signature": "<Sign_dev(JCS{frozen, signed_at})>" }`
Response `200`: `{ "frozen": true, "set_by_device_id": "dev_...", "signed_at": "..." }`

The relay verifies `signature` with the authenticated device's key (`422 signature_invalid`), requires `signed_at` within 60 s of its clock and later than the stored state's `signed_at` (`422 clock_skew`; an old signed unfreeze cannot be replayed), and emits a `freeze` event carrying the signed object to every active gateway of the account.

`GET /v1/accounts/me/freeze` — auth `Signeto-Gateway` or device. Returns the same shape plus `signature`, so the gateway can verify the state against its own pinned device key: `{ "frozen": true, "set_by_device_id": "dev_...", "signed_at": "...", "signature": "..." }`. An account never frozen returns `{ "frozen": false, "set_by_device_id": null, "signed_at": null, "signature": null }`. Gateways MUST poll this at least every 60 s in addition to consuming `freeze` events, and MUST treat the local freeze file (SPEC §7 `freeze_file`) as authoritative when it exists regardless of relay state. Unfreeze via the relay requires a device signature over `{frozen: false, ...}`; unfreeze of the local file requires local operator action.

### 7.10 Publish chain head

`PUT /v1/gateways/{gateway_id}/chain-head` — auth `Signeto-Gateway`
Request:
```json
{ "seq": 1842, "entry_hash": "<hex>", "policy_hash": "<hex>", "ts": "...", "signature": "<Sign_gw(JCS{gateway_id, seq, entry_hash, policy_hash, ts})>" }
```
Response `200`: `{ "seq": 1842, "received_at": "..." }`
Errors: `409 chain_head_regressed` (`seq` lower than stored, or same `seq` with a different hash; the relay MUST keep both and flag the account), `422 signature_invalid`, `403 forbidden` (another gateway's path). The body MAY also carry `gateway_id` (the ledger's head object); it MUST equal the path. The same `seq` with the same `entry_hash` is accepted again (the periodic re-publish); a lower `seq` whose `(seq, entry_hash)` the relay already holds is accepted as a retry. Gateways therefore publish a backlog in `seq` order.

`GET /v1/gateways/{gateway_id}/chain-heads?after=<cursor>&limit=<n>` — auth `Signeto-Gateway` (itself), `Bearer` (its account), or a device paired with it. Returns every head the relay holds for the gateway in arrival order, regressions included, for `signeto ledger verify --relay` and the approver app:
```json
{ "gateway_id": "gw_...", "heads": [ { "cursor": "41", "gateway_id": "gw_...", "seq": 1842, "entry_hash": "<hex>", "policy_hash": "<hex>", "ts": "...", "signature": "...", "received_at": "...", "regressed": false } ], "next": "41" | null }
```
Each head is the complete signed object, verifiable on its own. `limit` defaults to and is capped at 500; `next` is the `after` value for the following page, `null` on the last. Errors: `404 not_found` (unknown gateway or another account's), `403 forbidden` (another gateway, or a device not paired with it).

Gateways SHOULD publish after every ledger append and MUST publish at least every 5 minutes while running. `seq` is the ledger's monotonic sequence; it is what the nonce-store startup check compares against (§4.7).

The same signed head object is appended to the gateway's local `~/.signeto/ledger/heads.jsonl` before any remote publication and MAY be committed to a git repository when `ledger.publish.git` is configured (`docs/ledger.md` §6, `docs/policy.md` §13). The relay is one publication target among others. Publication failure to the relay or to git is NOT fail-closed (§6.5): the gateway retries with backoff, raises an alert, and keeps approving.

### 7.11 Local socket transport (solo topology)

In the solo topology (`docs/architecture.md` §3.1, milestone M1) there is no relay. The gateway listens on a Unix domain socket at `$XDG_RUNTIME_DIR/signeto/gateway.sock`, falling back to `~/.signeto/gateway.sock` when `XDG_RUNTIME_DIR` is unset. The socket file MUST be created with mode `0600`, and the gateway MUST accept a connection only when the peer's uid (`SO_PEERCRED` / `LOCAL_PEERCRED`) equals its own; any other peer is closed without a response and ledgered as `fail_closed` with `stage: relay`.

Frames are the same JSON objects this section defines, one per line, `\n`-delimited (JCS text contains no newlines, so bodies never need escaping beyond ordinary JSON). The HTTP method, path, and authentication header are replaced by a `type` member on the frame; the remaining members are exactly the corresponding relay API body:

| Frame `type` | Direction | Body |
|---|---|---|
| `approval.request` | gateway → approver | §7.5 request body, including `gateway_signature` |
| `approval.get` | approver → gateway | `{approval_id}`; response frame `approval` with the §7.6 body |
| `receipt` | approver → gateway | §7.7 receipt object |
| `status` | gateway → approver | §7.5 status body |
| `event` | gateway → approver | §7.8 event envelope |

On the socket `approval_id` equals `action_id` and `relay_id` is absent. Signature-based request authentication (`Signeto-Gateway`, `Signeto-Device`) is not used: the uid check protects the transport, and the signed objects (the request's `gateway_signature`, the receipt's signature) protect the content. The CLI approver MUST verify `gateway_signature` exactly as a remote device would; a local transport does not relax §7.5.

---

## 8. Error codes

Codes are stable strings. HTTP status is advisory; clients MUST branch on `code`.

| Code | HTTP | Raised by | Meaning |
|---|---|---|---|
| `unauthorized` | 401 | relay | Missing or invalid auth. |
| `forbidden` | 403 | relay | Authenticated but not permitted for this resource. |
| `not_found` | 404 | relay | No such endpoint, or a gateway/device id that does not exist for this account. |
| `request_malformed` | 422 (400, 413) | relay | Body not JSON (400), over the size limit (413), or failing the endpoint's schema (422). |
| `internal_error` | 500 | relay | Unexpected failure; nothing was stored. |
| `device_limit` | 403 | relay | Plan device limit reached. |
| `gateway_limit` | 403 | relay | Plan gateway limit reached (Free: one active gateway). |
| `rate_limited` | 429 | relay | Fair-use limit; `retry_after` present. |
| `frozen` | 409 | relay, gateway | Freeze flag set; nothing is queued or executed. |
| `relay_unavailable` | 503 | gateway, relay | Relay unreachable; action will expire. The relay's `/healthz` returns it when its database is down. |
| `unsupported_protocol_version` | 422 | gateway, device | Unknown `protocol_version` MAJOR. |
| `receipt_version_unsupported` | 422 | gateway | Unknown `receipt_version` MAJOR. |
| `invalid_canonical_action` | 422 | gateway, device | Schema violation in the action. |
| `not_canonical` | 422 | device | Received bytes are not JCS output. |
| `unknown_template` | n/a | device | Template not in registry; shown as unverified, not an error response. |
| `receipt_malformed` | 422 | gateway, relay | Receipt schema violation. |
| `invalid_signature` | 422 | gateway | Cryptographic verification failed. |
| `alg_not_allowed` | 422 | gateway, relay | `alg` not ES256/Ed25519 or not the pinned algorithm. |
| `unknown_device` | 422 | gateway | Device not paired. |
| `device_revoked` | 422 | gateway, relay | Device revoked. The relay returns it with 401 when a revoked device authenticates (§7.1). |
| `approver_mismatch` | 422 | gateway | `approver_id` does not own `device_id`. |
| `approver_not_permitted` | 422 | gateway | Tier or named-approver rule not satisfied. |
| `hash_mismatch` | 422 | gateway | Signed hash is not the stored bytes. |
| `clock_skew` | 422 | gateway, relay | Timestamp outside 60 s tolerance. 401 for a signed request's `ts` (§7.1). |
| `nonce_reused` | 409 | gateway | Replay. |
| `nonce_store_behind` | n/a | gateway | Startup refused: nonce store `seq` is behind the chain head; run `signeto ledger repair` (§4.7). |
| `gateway_signature_invalid` | n/a | device | `gateway_signature` on an approval request failed against the pinned gateway key, or `gateway_id` is not pinned; the request is not rendered (§7.5). |
| `action_expired` | 410 | gateway, relay | Past `expires_at`. |
| `approval_not_found` | 404 | gateway, relay | Unknown `action_id` or `approval_id`. |
| `approval_already_decided` | 409 | gateway, relay | Not pending. |
| `idempotency_conflict` | 409 | gateway | Same `idempotency_key`, different bytes. Indicates a gateway bug; fail closed. |
| `policy_changed` | 409 | gateway | Policy hash changed between build and execute. |
| `execution_failed` | 502 | gateway | Upstream call failed after approval. |
| `mint_failed` | 502 | gateway | Token minting or credential unlock failed. |
| `pairing_not_found` | 404 | relay | Unknown `pairing_id`. |
| `pairing_expired` | 410 | relay, gateway | Past QR expiry. |
| `pairing_already_claimed` | 409 | relay | Second claim. |
| `pairing_not_claimed` | 409 | relay | Confirm before claim. |
| `pairing_proof_invalid` | 422 | gateway | HMAC proof did not verify; possible relay substitution. |
| `pairing_confirmation_invalid` | 422 | device | Gateway confirmation did not verify against QR key. |
| `attestation_invalid` | 422 | gateway, relay | Hardware attestation failed or did not match policy. |
| `key_invalid` | 422 | relay | JWK unparseable or wrong curve. |
| `gateway_exists` / `device_exists` / `pairing_exists` | 409 | relay | Duplicate registration. |
| `targets_invalid` | 422 | relay | Unknown approver or device in targets. |
| `chain_head_regressed` | 409 | relay | Ledger chain head moved backwards or forked. |
| `signature_invalid` | 422 | relay | Gateway or device signature on a relay-level object failed. |

---

## 9. Test vectors

`packages/protocol/vectors/` ships JSON fixtures that every implementation (gateway, CLI, iOS, web, standalone verifier) MUST pass. Each file has `description`, `inputs`, `expected`, and, for negative vectors, `expected_error`. Keys in vectors are test keys and MUST NOT be used elsewhere.

| Directory | Covers |
|---|---|
| `canonical/` | Action object → JCS bytes, SHA-256, `idempotency_key`. Includes unicode escaping, number formatting, nested arrays, key ordering, optional fields present and absent, batch fields, `effective_at`. |
| `canonical-invalid/` | Schema violations: extra top-level key, bad timestamp format, expiry over 5 min, tier 4, `batch_index` without `batch_id`, non-canonical input bytes. |
| `templates/` | Template + canonical bytes → rendered line. Includes escaped braces, nested paths, array index, numeric and boolean values, `elide` lists, unreferenced key (expected `unverified`), unknown template version. |
| `receipts/` | Action, device JWK, receipt → verify result. Positive vectors for ES256, Ed25519, and WebAuthn (with `authenticator_data`, `client_data_json`, challenge equal to SHA-256 of the signing input). Negative vectors for every code in §4.6, plus WebAuthn wrong origin, wrong challenge, and wrong `type`. |
| `receipts/signing-input/` | Receipt fields → exact signing input bytes, with and without `reason`; the WebAuthn challenge derived from each. |
| `approval-request/` | Request body → `gateway_signature` signing input and signature; negative vectors for an altered `expires_at`, altered `canonical_bytes`, and an unpinned `gateway_id`. |
| `batch/` | Steps → manifest bytes and hash for `atomic: true`; a reordered-steps negative vector. |
| `pairing/` | Code, keys → `pairing_id`, `proof`, confirmation signing input, and a substituted-key negative vector. |
| `relay-auth/` | Request → `Signeto-Gateway` / `Signeto-Device` header value, with body and without (query string in `path`); negative vectors for an expired or future `ts`, the 60 s edge, a wrong key, an altered body, query or method, and a device id under the gateway scheme. |
| `ledger/` | Chain head signing input; genesis `prev_hash` from a gateway public key. |

### 9.1 Worked example: canonical action and idempotency key

```json
{
  "description": "github.merge_pull_request, tier 3, enforce, no batch",
  "inputs": {
    "action": {
      "protocol_version": "1.0",
      "tool": "github.merge_pull_request",
      "template_id": "github.merge_pull_request",
      "template_version": 1,
      "args_resolved": { "repo": "acme/api", "pr": 42, "head_sha": "abc1234abc1234abc1234abc1234abc1234abc12", "base": "main", "method": "squash" },
      "requester": { "agent": "claude-code", "session_id": "sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3", "host": "jason-mbp", "gateway_id": "gw_jtl8uXbA19Z9r2ZrSBMGyfEddtXMM_d4wo1k0O_GMrs" },
      "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
      "idempotency_key": "d6c9ba6711cedcb098ec0694c215d960b8b130a03f74378fc4b31c36fcad5376",
      "issued_at": "2026-11-05T18:04:09.123Z",
      "expires_at": "2026-11-05T18:07:09.123Z",
      "origin_hash": "93ac2a7de1b680ac6c0d62713c372d3f223cc0d1b41df20150946fd082755967",
      "tier": 3,
      "mode": "enforce"
    }
  },
  "expected": {
    "idempotency_key": "d6c9ba6711cedcb098ec0694c215d960b8b130a03f74378fc4b31c36fcad5376",
    "canonical_bytes": "{\"args_resolved\":{\"base\":\"main\",\"head_sha\":\"abc1234abc1234abc1234abc1234abc1234abc12\",\"method\":\"squash\",\"pr\":42,\"repo\":\"acme/api\"},\"expires_at\":\"2026-11-05T18:07:09.123Z\",\"idempotency_key\":\"d6c9ba6711cedcb098ec0694c215d960b8b130a03f74378fc4b31c36fcad5376\",\"issued_at\":\"2026-11-05T18:04:09.123Z\",\"mode\":\"enforce\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin_hash\":\"93ac2a7de1b680ac6c0d62713c372d3f223cc0d1b41df20150946fd082755967\",\"protocol_version\":\"1.0\",\"requester\":{\"agent\":\"claude-code\",\"gateway_id\":\"gw_jtl8uXbA19Z9r2ZrSBMGyfEddtXMM_d4wo1k0O_GMrs\",\"host\":\"jason-mbp\",\"session_id\":\"sess_01JBXK3M8PQ7R2T4V6W8Y0Z1A3\"},\"template_id\":\"github.merge_pull_request\",\"template_version\":1,\"tier\":3,\"tool\":\"github.merge_pull_request\"}",
    "canonical_bytes_sha256": "f98e7401f10035c4b06232e3a47e637edfb7141db831caef4d281cc59dcfdf4a",
    "rendered": "Merge PR #42 into main on acme/api (squash) at abc1234abc1234abc1234abc1234abc1234abc12"
  }
}
```

Note the member order in `canonical_bytes`: `args_resolved`, `expires_at`, `idempotency_key`, `issued_at`, `mode`, `nonce`, `origin_hash`, `protocol_version`, `requester`, `template_id`, `template_version`, `tier`, `tool`. This is the JCS sort and is the order every implementation MUST produce.

### 9.2 Worked example: Ed25519 denial receipt

```json
{
  "description": "Ed25519 software key, decision deny with reason",
  "inputs": {
    "canonical_bytes_sha256": "f98e7401f10035c4b06232e3a47e637edfb7141db831caef4d281cc59dcfdf4a",
    "device_public_key": { "kty": "OKP", "crv": "Ed25519", "x": "tBsN_24rEyvNtlfAwMOMFI4-o3VXG8chyJg_V_K1Xt8" },
    "device_private_key_seed": "lRjDf1TqC80UW4at-i81Td658VW3QFzRPsbyICQQmTc",
    "receipt": {
      "receipt_version": "1.0",
      "action_id": "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C",
      "decision": "deny",
      "reason": "Not during market hours",
      "approver_id": "jason",
      "device_id": "dev_M-3A8OrhpRe76wmCIbkfXUGgPsZd7Etzl43As47c8rY",
      "alg": "Ed25519",
      "signature": "GUsYHAnJMXsVfNfqtlS3bgM5W11sNA79SA76-7r-SuREE2bL8pa89zggCpyNIX9kiipVrfjxG882WdH5TvwADg",
      "signed_at": "2026-11-05T18:05:00.000Z",
      "canonical_bytes_sha256": "f98e7401f10035c4b06232e3a47e637edfb7141db831caef4d281cc59dcfdf4a"
    }
  },
  "expected": {
    "signing_input": "{\"canonical_bytes_sha256\":\"f98e7401f10035c4b06232e3a47e637edfb7141db831caef4d281cc59dcfdf4a\",\"decision\":\"deny\",\"reason\":\"Not during market hours\",\"signed_at\":\"2026-11-05T18:05:00.000Z\"}",
    "verify": "ok",
    "resulting_status": "denied",
    "agent_sees": "Not during market hours"
  }
}
```

A companion negative vector flips `decision` to `approve` without re-signing and expects `invalid_signature`.

---

## 10. Security considerations

This section lists only what the protocol adds to SPEC §9; the SPEC requirements apply in full.

- **Trust root is the pairing QR, not the relay.** Everything the device knows about a gateway originates from the QR (§5.2). Everything the gateway knows about a device is validated by a proof keyed on a secret the relay never holds (§5.3). Implementations MUST NOT add a "fetch gateway key from relay" convenience path.
- **The hash is computed where the bytes are rendered.** A device that accepts `canonical_bytes_sha256` from the network instead of hashing the bytes it displayed breaks principle 3 of SPEC §2 silently. Conformance vectors include a case where the supplied hash and bytes disagree; a compliant device signs the hash of the bytes.
- **Nonce before execution.** The single-use nonce is consumed at §4.5 step 13, before minting or execution. A crash between the two leaves an unexecuted, consumed action; that is the correct failure. The reverse order would allow double execution.
- **Receipts are not confidential.** They contain nothing an attacker can use without the device key. Canonical bytes may contain sensitive arguments (SQL text, repo names) and are protected by TLS in transit and by the push-payload rule (SPEC §9) at rest on lock screens.
- **Relay-assigned identifiers are never signed.** `approval_id`, `relay_id`, and `cursor` are routing state. A relay that lies about them can only cause delivery failure, which fails closed.
- **Gateway-signed requests close the relay's last write path to the human.** Without `gateway_signature` (§7.5) a relay could put a fabricated card in front of an approver; the resulting receipt would be useless, but the attention spent and the habituation are real. With it, the device refuses before rendering, and the relay is reduced to delay and drop.
- **`origin_hash` is not evidence.** It is computed from agent-supplied identifiers (§2.8) and MUST NOT be used in policy or presented as proof of what the human intended. It is in the signed bytes only so that the ledger can be correlated with the integration's own logs.
- **Advisory mode is inside the signed bytes.** `mode` is a canonical field so that a receipt for an advisory-mode action cannot be presented as proof of enforcement, and so that the ledger and the approver's screen agree.
- **Clock skew tolerance is asymmetric.** The 60 s window applies to `signed_at` only. `expires_at` on the gateway is strict. A device with a slow clock can still sign a nearly-expired action; the gateway, not the device, decides whether it arrived in time.
- **Idempotency key collisions across sessions are impossible by construction** because `requester.session_id` is in the hashed object. Two agents proposing identical actions get separate approvals, which is the intended behaviour: an approval is for one requester.
- **Template registry is a display aid, not a trust boundary.** A wrong or missing template degrades to raw bytes with a warning (§3.4). It MUST NOT degrade to a silently different rendering, and an adapter MUST NOT be able to elide arguments without the device showing a count of hidden fields.
- **WebAuthn origin binding.** The gateway's allow-list of approver origins (§4.4) is the only thing that prevents a phishing page from obtaining a valid assertion. Self-hosted deployments MUST configure it; the default MUST be the empty list, not a wildcard.
- **Threat model.** Attack trees for compromised agent, compromised relay, lost device, malicious adapter, and rogue gateway are in `docs/threat-model.md`. Each mitigation there references a section of this document.
