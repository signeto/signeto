// docs/protocol.md §7.1: request authentication to a relay.
//   Authorization: Signeto-Device <device_id>.<ts>.<sig>
// `sig` is base64url (86 chars) of the device key's signature over the UTF-8 JCS of
// `{body_sha256, method, path, ts}`. Mirrors src/relay-auth.ts. Port of SignetoSign RelayAuth.swift.
package dev.signeto.sign

enum class RelayAuthScheme(val wire: String) {
    GATEWAY("Signeto-Gateway"),
    DEVICE("Signeto-Device"),
}

enum class RelayAuthError(val code: String) {
    AUTH_MALFORMED("auth_malformed"),
    SCHEME_NOT_ALLOWED("scheme_not_allowed"),
    KEY_MISMATCH("key_mismatch"),
    CLOCK_SKEW("clock_skew"),
    INVALID_SIGNATURE("invalid_signature"),
}

class RelayAuthException(val error: RelayAuthError) : Exception(error.code)

data class ParsedRelayAuth(val scheme: RelayAuthScheme, val keyId: String, val ts: String, val signature: String)

object RelayAuth {
    const val WINDOW_MS: Long = Timestamp.CLOCK_SKEW_MS

    /** SHA-256 of the empty string. */
    const val EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    /** Hex SHA-256 of the raw body bytes as sent; null and empty both hash the empty string. */
    fun bodySha256(body: ByteArray?): String = if (body == null) EMPTY_BODY_SHA256 else Digest.sha256Hex(body)

    /** JCS of `{body_sha256, method, path, ts}`. Throws `auth_malformed` on a malformed field. */
    fun signingInput(method: String, path: String, ts: String, bodySha256: String): String {
        if (method.isEmpty() || !method.all { it in 'A'..'Z' }) throw RelayAuthException(RelayAuthError.AUTH_MALFORMED)
        // origin-form request-target: starts with "/", no whitespace, no fragment
        if (!path.startsWith("/") || path.any { it == '#' || isWhitespace(it.code) }) throw RelayAuthException(RelayAuthError.AUTH_MALFORMED)
        if (Timestamp.parse(ts) == null) throw RelayAuthException(RelayAuthError.AUTH_MALFORMED)
        if (!Chars.hex64(bodySha256)) throw RelayAuthException(RelayAuthError.AUTH_MALFORMED)
        return Jcs.canonicalize(
            JsonValue.obj("body_sha256" to JsonValue.of(bodySha256), "method" to JsonValue.of(method), "path" to JsonValue.of(path), "ts" to JsonValue.of(ts)),
        )
    }

    /**
     * JS `\s` (WhiteSpace and LineTerminator) together with Unicode White_Space, which the Swift port also refuses.
     * All of these are BMP code points, so checking UTF-16 code units is enough.
     */
    internal fun isWhitespace(u: Int): Boolean = when (u) {
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, in 0x2000..0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF -> true
        else -> false
    }

    /**
     * The `Authorization` header value for one request, signed with `signer` (device scheme). For software keys; a
     * key that needs a biometric per signature uses the relay's device session instead (§7.1). `path` is the
     * request-target exactly as it will be sent (base path + path + query).
     */
    suspend fun deviceHeader(method: String, path: String, body: ByteArray?, ts: String, signer: DeviceSigner): String {
        val si = signingInput(method, path, ts, bodySha256(body))
        val sig = signer.signBase64Url(si)
        return "${RelayAuthScheme.DEVICE.wire} ${signer.deviceId}.$ts.$sig"
    }

    fun parseHeader(value: String?): Outcome<ParsedRelayAuth, RelayAuthError> {
        val bad = Outcome.Err(RelayAuthError.AUTH_MALFORMED)
        if (value == null) return bad
        // ^([A-Za-z-]+) +([^\s]+)$
        var i = 0
        while (i < value.length && (value[i] in 'A'..'Z' || value[i] in 'a'..'z' || value[i] == '-')) i++
        if (i == 0 || i >= value.length || value[i] != ' ') return bad
        val schemeName = value.substring(0, i)
        while (i < value.length && value[i] == ' ') i++
        val cred = value.substring(i)
        if (cred.isEmpty() || cred.any { isWhitespace(it.code) }) return bad
        val scheme = RelayAuthScheme.entries.firstOrNull { it.wire.lowercase() == schemeName.lowercase() } ?: return bad
        val first = cred.indexOf('.')
        val last = cred.lastIndexOf('.')
        if (first <= 0 || first == last) return bad
        val keyId = cred.substring(0, first)
        val ts = cred.substring(first + 1, last)
        val sig = cred.substring(last + 1)
        val idOk = if (scheme == RelayAuthScheme.GATEWAY) Identifiers.isGatewayId(keyId) else Identifiers.isDeviceId(keyId)
        if (!idOk || Timestamp.parse(ts) == null || !Chars.base64Url(sig, 86)) return bad
        return Outcome.Ok(ParsedRelayAuth(scheme, keyId, ts, sig))
    }

    /**
     * Relay-side check, in §7.1 order (shape, scheme, key id = thumbprint, ±60 s, signature). Included for
     * conformance tests; a device never needs it.
     */
    fun verify(
        header: String?,
        method: String,
        path: String,
        body: ByteArray?,
        publicKey: PublicJwk,
        nowMs: Long,
        schemes: List<RelayAuthScheme>? = null,
    ): Outcome<ParsedRelayAuth, RelayAuthError> {
        val p = when (val r = parseHeader(header)) {
            is Outcome.Err -> return r
            is Outcome.Ok -> r.value
        }
        if (schemes != null && p.scheme !in schemes) return Outcome.Err(RelayAuthError.SCHEME_NOT_ALLOWED)
        val expected = if (p.scheme == RelayAuthScheme.GATEWAY) publicKey.gatewayId else publicKey.deviceId
        if (expected != p.keyId) return Outcome.Err(RelayAuthError.KEY_MISMATCH)
        val ts = Timestamp.parse(p.ts)
        if (ts == null || Math.abs(nowMs - ts) > WINDOW_MS) return Outcome.Err(RelayAuthError.CLOCK_SKEW)
        val si = try {
            signingInput(method, path, p.ts, bodySha256(body))
        } catch (_: RelayAuthException) {
            return Outcome.Err(RelayAuthError.AUTH_MALFORMED)
        }
        if (!publicKey.verify(p.signature, si)) return Outcome.Err(RelayAuthError.INVALID_SIGNATURE)
        return Outcome.Ok(p)
    }
}
