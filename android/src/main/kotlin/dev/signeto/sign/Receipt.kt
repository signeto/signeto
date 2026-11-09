// docs/protocol.md §4: receipts. Building and signing (device side) and standalone verification
// (§4.5 steps 1, 2, 6, 9, 10, 11, 12 and the WebAuthn procedure of §4.4). Mirrors src/receipt.ts.
// Port of SignetoSign Receipt.swift.
package dev.signeto.sign

enum class Decision(val wire: String) {
    APPROVE("approve"),
    DENY("deny");

    companion object {
        fun fromWire(s: String): Decision? = entries.firstOrNull { it.wire == s }
    }
}

data class WebAuthnBlock(val authenticatorData: String, val clientDataJson: String)

data class Receipt(
    val receiptVersion: String,
    val actionId: String,
    val decision: Decision,
    val reason: String?,
    val approverId: String,
    val deviceId: String,
    val alg: SignatureAlgorithm,
    val signature: String,
    val signedAt: String,
    val canonicalBytesSha256: String,
    val webauthn: WebAuthnBlock? = null,
    val relayId: String? = null,
) {
    /** The receipt object as sent to the relay (§7.7: without `relay_id` unless the relay added it). */
    val json: JsonValue
        get() {
            val m = ArrayList<Pair<String, JsonValue>>()
            m += "receipt_version" to JsonValue.of(receiptVersion)
            m += "action_id" to JsonValue.of(actionId)
            m += "decision" to JsonValue.of(decision.wire)
            reason?.let { m += "reason" to JsonValue.of(it) }
            m += "approver_id" to JsonValue.of(approverId)
            m += "device_id" to JsonValue.of(deviceId)
            m += "alg" to JsonValue.of(alg.wire)
            m += "signature" to JsonValue.of(signature)
            m += "signed_at" to JsonValue.of(signedAt)
            m += "canonical_bytes_sha256" to JsonValue.of(canonicalBytesSha256)
            webauthn?.let {
                m += "webauthn" to JsonValue.obj("authenticator_data" to JsonValue.of(it.authenticatorData), "client_data_json" to JsonValue.of(it.clientDataJson))
            }
            relayId?.let { m += "relay_id" to JsonValue.of(it) }
            return JsonValue.Obj(JsonObject(m))
        }

    /** JCS bytes of `json`: the exact request body for `POST /v1/approvals/{id}/receipt`. */
    fun body(): ByteArray = Jcs.canonicalBytes(json)
}

enum class ReceiptVerifyCode(val code: String) {
    RECEIPT_MALFORMED("receipt_malformed"),
    RECEIPT_VERSION_UNSUPPORTED("receipt_version_unsupported"),
    ALG_NOT_ALLOWED("alg_not_allowed"),
    HASH_MISMATCH("hash_mismatch"),
    CLOCK_SKEW("clock_skew"),
    INVALID_SIGNATURE("invalid_signature"),
    WEBAUTHN_TYPE("webauthn_type"),
    WEBAUTHN_CHALLENGE("webauthn_challenge"),
    WEBAUTHN_ORIGIN("webauthn_origin"),
    WEBAUTHN_RP_ID("webauthn_rp_id"),
    WEBAUTHN_USER_FLAGS("webauthn_user_flags"),
}

data class WebAuthnPolicy(val allowedOrigins: List<String>, val rpId: String, val requireUserVerified: Boolean)

sealed class ReceiptBuildException(message: String) : Exception(message) {
    class ReasonTooLong : ReceiptBuildException("reason is longer than 512 UTF-8 bytes")
    class Malformed(val problem: String) : ReceiptBuildException("receipt malformed: $problem")
}

object Receipts {
    const val RECEIPT_VERSION = "1.0"
    const val RECEIPT_MAJOR = 1
    const val MAX_REASON_UTF8_BYTES = 512

    /** §4.2: UTF-8 JCS of `{canonical_bytes_sha256, decision, reason?, signed_at}`; `reason` omitted when absent. */
    fun signingInput(canonicalBytesSha256: String, decision: Decision, reason: String?, signedAt: String): String {
        val m = ArrayList<Pair<String, JsonValue>>()
        m += "canonical_bytes_sha256" to JsonValue.of(canonicalBytesSha256)
        m += "decision" to JsonValue.of(decision.wire)
        reason?.let { m += "reason" to JsonValue.of(it) }
        m += "signed_at" to JsonValue.of(signedAt)
        return Jcs.canonicalize(JsonValue.Obj(JsonObject(m)))
    }

    /** §4.4: the WebAuthn challenge is the 32-byte SHA-256 of the signing input. */
    fun webauthnChallenge(signingInput: String): ByteArray = Digest.sha256(signingInput)

    /**
     * Build and sign a receipt over canonical bytes the caller rendered. The hash is computed here from those bytes,
     * never accepted from the network (§4.2, "what you see is what you sign").
     */
    suspend fun sign(
        actionId: String,
        canonicalBytes: String,
        decision: Decision,
        reason: String?,
        approverId: String,
        signedAt: String,
        signer: DeviceSigner,
    ): Receipt = signHash(actionId, Digest.sha256Hex(canonicalBytes), decision, reason, approverId, signedAt, signer)

    suspend fun signHash(
        actionId: String,
        canonicalBytesSha256: String,
        decision: Decision,
        reason: String?,
        approverId: String,
        signedAt: String,
        signer: DeviceSigner,
    ): Receipt {
        if (reason != null && Utf8.length(reason) > MAX_REASON_UTF8_BYTES) throw ReceiptBuildException.ReasonTooLong()
        val si = signingInput(canonicalBytesSha256, decision, reason, signedAt)
        val sig = signer.signBase64Url(si)
        val r = Receipt(RECEIPT_VERSION, actionId, decision, reason, approverId, signer.deviceId, signer.algorithm, sig, signedAt, canonicalBytesSha256)
        schemaProblem(r.json)?.let { throw ReceiptBuildException.Malformed(it) }
        return r
    }

    /** Trim a free-text reason to at most 512 UTF-8 bytes without splitting a character (grapheme cluster). */
    fun clampReason(s: String): String {
        val it = java.text.BreakIterator.getCharacterInstance()
        it.setText(s)
        var n = 0
        var start = it.first()
        var end = it.next()
        while (end != java.text.BreakIterator.DONE) {
            val w = Utf8.length(s.substring(start, end))
            if (n + w > MAX_REASON_UTF8_BYTES) return s.substring(0, start)
            n += w
            start = end
            end = it.next()
        }
        return s
    }

    /** §4.3 schema check, strict. null when valid, else a description. */
    fun schemaProblem(v: JsonValue): String? = parse(v).errorOrNull

    private val allowed = setOf(
        "receipt_version", "action_id", "decision", "reason", "approver_id", "device_id", "alg", "signature", "signed_at",
        "canonical_bytes_sha256", "webauthn", "relay_id",
    )

    internal fun parse(v: JsonValue): Outcome<Receipt, String> {
        val o = v.objectValue ?: return Outcome.Err("not an object")
        for (k in o.keys) if (k !in allowed) return Outcome.Err("unknown member $k")
        val rv = o["receipt_version"]?.stringValue
        if (rv == null || !isVersion(rv)) return Outcome.Err("receipt_version")
        val aid = o["action_id"]?.stringValue
        if (aid == null || !Identifiers.isActionId(aid)) return Outcome.Err("action_id")
        val decision = o["decision"]?.stringValue?.let { Decision.fromWire(it) } ?: return Outcome.Err("decision")
        var reason: String? = null
        o["reason"]?.let { rvv ->
            val s = rvv.stringValue
            if (s == null || s.length > 512 || Utf8.length(s) > MAX_REASON_UTF8_BYTES) return Outcome.Err("reason")
            reason = s
        }
        val ap = o["approver_id"]?.stringValue
        if (ap == null || ap.length !in 1..64) return Outcome.Err("approver_id")
        val dev = o["device_id"]?.stringValue
        if (dev == null || !Identifiers.isDeviceId(dev)) return Outcome.Err("device_id")
        val alg = o["alg"]?.stringValue?.let { SignatureAlgorithm.fromWire(it) } ?: return Outcome.Err("alg")
        val sig = o["signature"]?.stringValue
        if (sig == null || !Chars.base64Url(sig, 86)) return Outcome.Err("signature")
        val sat = o["signed_at"]?.stringValue
        if (sat == null || !isTimestampShape(sat)) return Outcome.Err("signed_at")
        val h = o["canonical_bytes_sha256"]?.stringValue
        if (h == null || !Chars.hex64(h)) return Outcome.Err("canonical_bytes_sha256")
        var webauthn: WebAuthnBlock? = null
        o["webauthn"]?.let { w ->
            val wo = w.objectValue
            val ad = wo?.get("authenticator_data")?.stringValue
            val cd = wo?.get("client_data_json")?.stringValue
            if (wo == null || wo.size != 2 || ad == null || cd == null) return Outcome.Err("webauthn")
            webauthn = WebAuthnBlock(ad, cd)
            if (alg != SignatureAlgorithm.ES256) return Outcome.Err("webauthn receipts must use ES256")
        }
        var relayId: String? = null
        o["relay_id"]?.let { r ->
            val s = r.stringValue
            if (s == null || s.length > 128) return Outcome.Err("relay_id")
            relayId = s
        }
        return Outcome.Ok(Receipt(rv, aid, decision, reason, ap, dev, alg, sig, sat, h, webauthn, relayId))
    }

    /** `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$` */
    internal fun isVersion(s: String): Boolean {
        val parts = s.split(".")
        return parts.size == 2 && parts.all { Chars.isCanonicalUInt(it) }
    }

    /** The §2.5 regex alone (the TS schema checks the shape; verify parses the instant later). */
    internal fun isTimestampShape(s: String): Boolean {
        if (s.length != 24) return false
        val digits = intArrayOf(0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22)
        return digits.all { s[it] in '0'..'9' } && s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' && s[16] == ':' && s[19] == '.' && s[23] == 'Z'
    }

    data class Verified(val receipt: Receipt, val signingInput: String)

    /**
     * Standalone verification against a pinned device key, in §4.5 order. Pass either the canonical bytes or their
     * SHA-256 (a gateway hashes its own stored bytes).
     */
    fun verify(
        receipt: JsonValue,
        canonicalBytes: String? = null,
        canonicalBytesSha256: String? = null,
        issuedAt: String,
        expiresAt: String,
        devicePublicKey: PublicJwk,
        webauthn: WebAuthnPolicy? = null,
    ): Outcome<Verified, ReceiptVerifyCode> {
        val r = parse(receipt).valueOrNull ?: return Outcome.Err(ReceiptVerifyCode.RECEIPT_MALFORMED)
        val major = r.receiptVersion.split(".").firstOrNull()?.toIntOrNull()
        if (major != RECEIPT_MAJOR) return Outcome.Err(ReceiptVerifyCode.RECEIPT_VERSION_UNSUPPORTED)
        if (devicePublicKey.algorithm != r.alg) return Outcome.Err(ReceiptVerifyCode.ALG_NOT_ALLOWED)

        val ownHash = canonicalBytesSha256 ?: canonicalBytes?.let { Digest.sha256Hex(it) } ?: return Outcome.Err(ReceiptVerifyCode.HASH_MISMATCH)
        if (!timingSafeEqual(ownHash, r.canonicalBytesSha256)) return Outcome.Err(ReceiptVerifyCode.HASH_MISMATCH)

        val signedAt = Timestamp.parse(r.signedAt)
        val issued = Timestamp.parse(issuedAt)
        val expires = Timestamp.parse(expiresAt)
        if (signedAt == null || issued == null || expires == null) return Outcome.Err(ReceiptVerifyCode.RECEIPT_MALFORMED)
        if (signedAt < issued - Timestamp.CLOCK_SKEW_MS || signedAt > expires + Timestamp.CLOCK_SKEW_MS) return Outcome.Err(ReceiptVerifyCode.CLOCK_SKEW)

        val si = signingInput(ownHash, r.decision, r.reason, r.signedAt)
        val sig = Base64Url.decode(r.signature) ?: return Outcome.Err(ReceiptVerifyCode.RECEIPT_MALFORMED)

        r.webauthn?.let { wa ->
            verifyWebAuthn(wa, si, sig, webauthn, devicePublicKey)?.let { return Outcome.Err(it) }
            return Outcome.Ok(Verified(r, si))
        }
        if (!devicePublicKey.verify(sig, si.toByteArray(Charsets.UTF_8))) return Outcome.Err(ReceiptVerifyCode.INVALID_SIGNATURE)
        return Outcome.Ok(Verified(r, si))
    }

    internal fun verifyWebAuthn(wa: WebAuthnBlock, signingInput: String, signature: ByteArray, policy: WebAuthnPolicy?, key: PublicJwk): ReceiptVerifyCode? {
        val authData = Base64Url.decode(wa.authenticatorData) ?: return ReceiptVerifyCode.RECEIPT_MALFORMED
        val cdjBytes = Base64Url.decode(wa.clientDataJson) ?: return ReceiptVerifyCode.RECEIPT_MALFORMED
        val cdj = try {
            JsonParser.parse(cdjBytes)
        } catch (_: JsonParseException) {
            return ReceiptVerifyCode.RECEIPT_MALFORMED
        }
        // §4.4 order: type → challenge → origin → rpIdHash/flags → signature.
        if (cdj["type"]?.stringValue != "webauthn.get") return ReceiptVerifyCode.WEBAUTHN_TYPE
        val expected = Base64Url.encode(webauthnChallenge(signingInput))
        val ch = cdj["challenge"]?.stringValue
        if (ch == null || !timingSafeEqual(ch, expected)) return ReceiptVerifyCode.WEBAUTHN_CHALLENGE
        val origin = cdj["origin"]?.stringValue
        if (policy == null || policy.allowedOrigins.isEmpty() || origin == null || origin !in policy.allowedOrigins) return ReceiptVerifyCode.WEBAUTHN_ORIGIN
        if (authData.size < 37) return ReceiptVerifyCode.RECEIPT_MALFORMED
        if (!timingSafeEqual(Hex.encode(authData.copyOfRange(0, 32)), Digest.sha256Hex(policy.rpId))) return ReceiptVerifyCode.WEBAUTHN_RP_ID
        val flags = authData[32].toInt()
        val up = flags and 0x01 != 0
        val uv = flags and 0x04 != 0
        if (!up || (policy.requireUserVerified && !uv)) return ReceiptVerifyCode.WEBAUTHN_USER_FLAGS
        if (key.algorithm != SignatureAlgorithm.ES256 || !key.verify(signature, authData + Digest.sha256(cdjBytes))) return ReceiptVerifyCode.INVALID_SIGNATURE
        return null
    }
}
