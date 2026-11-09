// docs/protocol.md §7.9: the account freeze flag, set or lifted by a device-signed object.
// Port of SignetoSign Freeze.swift.
package dev.signeto.sign

data class FreezeState(
    val frozen: Boolean,
    val setByDeviceId: String?,
    val signedAt: String?,
    val signature: String?,
) {
    /** True when the state carries a signature that verifies with `key` (e.g. this device's own key). */
    fun verifies(key: PublicJwk): Boolean {
        val at = signedAt ?: return false
        val sig = signature ?: return false
        return key.verify(sig, Freeze.signingInput(frozen, at))
    }

    companion object {
        /** From `GET /v1/accounts/me/freeze`. */
        fun fromJson(json: JsonValue): FreezeState? {
            val f = json["frozen"]?.boolValue ?: return null
            return FreezeState(f, json["set_by_device_id"]?.stringValue, json["signed_at"]?.stringValue, json["signature"]?.stringValue)
        }
    }
}

object Freeze {
    /** UTF-8 JCS of `{frozen, signed_at}`. */
    fun signingInput(frozen: Boolean, signedAt: String): String =
        Jcs.canonicalize(JsonValue.obj("frozen" to JsonValue.of(frozen), "signed_at" to JsonValue.of(signedAt)))

    /** `PUT /v1/accounts/me/freeze` body, signed with the device key. */
    suspend fun body(frozen: Boolean, signedAt: String, signer: DeviceSigner): JsonValue {
        val sig = signer.signBase64Url(signingInput(frozen, signedAt))
        return JsonValue.obj("frozen" to JsonValue.of(frozen), "signed_at" to JsonValue.of(signedAt), "signature" to JsonValue.of(sig))
    }
}
