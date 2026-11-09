// docs/protocol.md §7.5: `gateway_signature` on every approval request. The device rebuilds the signing
// input from the request as received (nonce and gateway_id from inside the canonical bytes), looks up the
// gateway key pinned at pairing for that gateway_id, and verifies before anything is rendered.
// Mirrors src/request.ts. Port of SignetoSign ApprovalRequest.swift.
package dev.signeto.sign

data class ApprovalRequestSigningFields(
    val actionId: String,
    val canonicalBytesSha256: String,
    val expiresAt: String,
    val gatewayId: String,
    val nonce: String,
)

enum class ApprovalRequestVerifyCode(val code: String) {
    GATEWAY_SIGNATURE_INVALID("gateway_signature_invalid"),
    GATEWAY_NOT_PINNED("gateway_not_pinned"),
    REQUEST_MALFORMED("request_malformed"),
}

/** A request that passed `gateway_signature` verification. Only this type reaches the renderer. */
data class VerifiedApprovalRequest(
    val actionId: String,
    val gatewayId: String,
    /** Parsed from the verified canonical bytes; `encoded.canonicalBytes` is what is shown and hashed. */
    val encoded: EncodedAction,
)

object ApprovalRequests {
    fun signingInput(f: ApprovalRequestSigningFields): String = Jcs.canonicalize(
        JsonValue.obj(
            "action_id" to JsonValue.of(f.actionId),
            "canonical_bytes_sha256" to JsonValue.of(f.canonicalBytesSha256),
            "expires_at" to JsonValue.of(f.expiresAt),
            "gateway_id" to JsonValue.of(f.gatewayId),
            "nonce" to JsonValue.of(f.nonce),
        ),
    )

    /**
     * The signing fields derived from the request body itself; null when the bytes are not a valid canonical action
     * or the request's `expires_at` differs from the one inside the bytes.
     */
    fun fields(actionId: String, canonicalBytes: String, expiresAt: String): Pair<ApprovalRequestSigningFields, EncodedAction>? {
        val enc = CanonicalActions.parse(canonicalBytes).valueOrNull ?: return null
        val a = enc.action
        if (a.expiresAt != expiresAt) return null
        return ApprovalRequestSigningFields(actionId, enc.canonicalBytesSha256, a.expiresAt, a.requester.gatewayId, a.nonce) to enc
    }

    /** Device side, before rendering. `pinned` maps gateway_id → the public key taken from that gateway's QR. */
    fun verify(
        actionId: String,
        canonicalBytes: String,
        expiresAt: String,
        gatewaySignature: String,
        pinned: Map<String, PublicJwk>,
    ): Outcome<VerifiedApprovalRequest, ApprovalRequestVerifyCode> {
        val (f, enc) = fields(actionId, canonicalBytes, expiresAt) ?: return Outcome.Err(ApprovalRequestVerifyCode.REQUEST_MALFORMED)
        val key = pinned[f.gatewayId] ?: return Outcome.Err(ApprovalRequestVerifyCode.GATEWAY_NOT_PINNED)
        if (!key.verify(gatewaySignature, signingInput(f))) return Outcome.Err(ApprovalRequestVerifyCode.GATEWAY_SIGNATURE_INVALID)
        return Outcome.Ok(VerifiedApprovalRequest(actionId, f.gatewayId, enc))
    }
}
