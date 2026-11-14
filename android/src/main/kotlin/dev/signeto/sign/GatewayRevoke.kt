// SIG-157: a device revokes a gateway on its account (`POST /v1/gateways/{id}/revoke`) with a device-signed object,
// like the freeze flag (Freeze.kt).
package dev.signeto.sign

object GatewayRevoke {
    const val PURPOSE = "gateway.revoke"

    /** UTF-8 JCS of `{gateway_id, purpose: "gateway.revoke", signed_at}`. */
    fun signingInput(gatewayId: String, signedAt: String): String =
        Jcs.canonicalize(
            JsonValue.obj("gateway_id" to JsonValue.of(gatewayId), "purpose" to JsonValue.of(PURPOSE), "signed_at" to JsonValue.of(signedAt)),
        )

    /** `POST /v1/gateways/{gateway_id}/revoke` body, signed with the device key. `purpose` is signed but not sent. */
    suspend fun body(gatewayId: String, signedAt: String, signer: DeviceSigner): JsonValue {
        val sig = signer.signBase64Url(signingInput(gatewayId, signedAt))
        return JsonValue.obj("gateway_id" to JsonValue.of(gatewayId), "signed_at" to JsonValue.of(signedAt), "signature" to JsonValue.of(sig))
    }
}
