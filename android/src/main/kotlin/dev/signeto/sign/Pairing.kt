// docs/protocol.md §5: the pairing handshake, device side.
//   parse QR (gateway key comes from here and nowhere else, §5.3 point 1)
//   → claim body with HMAC proofs v1 and v2 (§5.3 point 2; v2 also covers name, platform and attestation)
//   → verify the gateway's confirmation with the QR's key, including approver_id and templates_pinned
//     (§5.3 points 4 and 7, §5.4)
//   → PinnedGateway record, whose approverId every receipt for that gateway carries.
// Mirrors packages/gateway/src/pairing/{qr,handshake}.ts. As there: SHA-256(code) and the HMAC key are
// over the UTF-8 text of the 22-character code as printed, not its decoded bytes. Port of SignetoSign Pairing.swift.
package dev.signeto.sign

data class QrPayload(
    val v: Int,
    val gatewayPublicKey: PublicJwk,
    val gatewayName: String,
    /** Relay base URL, or "" in the solo topology. */
    val relay: String,
    /** Secret pairing code (22 base64url characters). Never sent anywhere. */
    val code: String,
    val expiresAt: String,
) {
    val gatewayId: String get() = gatewayPublicKey.gatewayId
    val gatewayFingerprint: String get() = gatewayPublicKey.fingerprint
    val pairingId: String get() = Pairing.pairingId(code)

    val json: JsonValue
        get() = JsonValue.obj(
            "v" to JsonValue.of(v),
            "gateway_public_key" to gatewayPublicKey.json,
            "gateway_name" to JsonValue.of(gatewayName),
            "relay" to JsonValue.of(relay),
            "code" to JsonValue.of(code),
            "expires_at" to JsonValue.of(expiresAt),
        )

    /** `base64url(JCS(payload))`: the manual-entry string. */
    val manualString: String get() = Base64Url.encode(Jcs.canonicalBytes(json))
    val uri: String get() = Pairing.QR_SCHEME + "?d=" + manualString

    // The code is a secret: keep it out of logs and crash reports.
    override fun toString(): String = "QrPayload(gateway=$gatewayId, name=$gatewayName, relay=$relay, expiresAt=$expiresAt)"
}

enum class QrParseError(val code: String) {
    MALFORMED("qr_malformed"),
    VERSION_UNSUPPORTED("qr_version_unsupported"),
    EXPIRED("qr_expired"),
}

enum class ConfirmationError(val code: String) {
    /** The confirmation does not verify with the QR's gateway key (relay or network may be hostile). */
    CONFIRMATION_INVALID("pairing_confirmation_invalid"),

    /** The confirmation is for a different pairing or device. */
    PAIRING_MISMATCH("pairing_mismatch"),
}

/** What the device stores per gateway after a verified pairing (§5.3 point 6). */
data class PinnedGateway(
    val gatewayId: String,
    val gatewayName: String,
    /** From the QR, never from the relay. */
    val gatewayPublicKey: PublicJwk,
    val gatewayFingerprint: String,
    val deviceId: String,
    val deviceFingerprint: String,
    val pairingId: String,
    val pairedAt: String,
    val relay: String,
    /**
     * The approver this gateway pinned the device under (its `signeto.yml` name, not the relay account's id), covered
     * by the confirmation signature (§5.3 point 7). Every receipt for this gateway carries it. `null` only for a record
     * stored before confirmations named the approver: do not sign, ask to re-pair.
     */
    val approverId: String?,
    /** Covered by the gateway's confirmation signature (§5.4). */
    val templatesPinned: List<TemplatePin>,
) {
    val id: String get() = gatewayId

    /** A pin from before confirmations carried `approver_id`: receipts for this gateway cannot be signed. */
    val needsRepair: Boolean get() = approverId == null

    /** The storage form; the same member names as the Swift record's Codable form. */
    val json: JsonValue
        get() {
            val m = ArrayList<Pair<String, JsonValue>>()
            m += "gateway_id" to JsonValue.of(gatewayId)
            m += "gateway_name" to JsonValue.of(gatewayName)
            m += "gateway_public_key" to gatewayPublicKey.json
            m += "gateway_fingerprint" to JsonValue.of(gatewayFingerprint)
            m += "device_id" to JsonValue.of(deviceId)
            m += "device_fingerprint" to JsonValue.of(deviceFingerprint)
            m += "pairing_id" to JsonValue.of(pairingId)
            m += "paired_at" to JsonValue.of(pairedAt)
            m += "relay" to JsonValue.of(relay)
            approverId?.let { m += "approver_id" to JsonValue.of(it) }
            m += "templates_pinned" to JsonValue.of(templatesPinned.map { it.json })
            return JsonValue.Obj(JsonObject(m))
        }

    companion object {
        /** From the storage form; null when a member is missing or has the wrong type. */
        fun fromJson(v: JsonValue?): PinnedGateway? {
            val o = v?.objectValue ?: return null
            fun str(k: String) = o[k]?.stringValue
            val key = PublicJwk.parse(o["gateway_public_key"]) ?: return null
            val approverV = o["approver_id"]
            val approver = if (approverV == null || approverV.isNull) null else approverV.stringValue ?: return null
            val pins = (o["templates_pinned"]?.arrayValue ?: return null).map { p ->
                val po = p.objectValue ?: return null
                TemplatePin(
                    po["template_id"]?.stringValue ?: return null,
                    po["template_version"]?.intValue ?: return null,
                    po["sha256"]?.stringValue ?: return null,
                )
            }
            return PinnedGateway(
                str("gateway_id") ?: return null,
                str("gateway_name") ?: return null,
                key,
                str("gateway_fingerprint") ?: return null,
                str("device_id") ?: return null,
                str("device_fingerprint") ?: return null,
                str("pairing_id") ?: return null,
                str("paired_at") ?: return null,
                str("relay") ?: return null,
                approver,
                pins,
            )
        }
    }
}

data class Attestation(val format: String, val data: String) {
    val json: JsonValue get() = JsonValue.obj("format" to JsonValue.of(format), "data" to JsonValue.of(data))
}

object Pairing {
    /** 2^63: the first double a Long cannot hold (Swift's `Int(exactly:)` refuses it). */
    private const val TWO_63 = 9.223372036854775807E18

    const val QR_SCHEME = "signeto://pair"

    /** §5.2: the QR expires within 10 minutes. */
    const val QR_MAX_TTL_MS: Long = 600_000

    // QR

    /** Accepts the full `signeto://pair?d=…` URI or the bare manual-entry string. `nowMs` is the device clock. */
    fun parseQr(input: String, nowMs: Long): Outcome<QrPayload, QrParseError> {
        val malformed = Outcome.Err(QrParseError.MALFORMED)
        val trimmed = input.trim()
        var data = trimmed
        if (trimmed.startsWith(QR_SCHEME)) {
            val d = queryParameter(trimmed, "d")
            if (d.isNullOrEmpty()) return malformed
            data = d
        }
        val raw = Base64Url.decode(data) ?: return malformed
        val o = try {
            JsonParser.parse(raw).objectValue
        } catch (_: JsonParseException) {
            null
        } ?: return malformed
        if (o["v"] != JsonValue.Num(1.0)) return Outcome.Err(QrParseError.VERSION_UNSUPPORTED)
        // §5.1 (SIG-92 N1): a small-order gateway key would make every confirmation and request "verify".
        val key = PublicJwk.parse(o["gateway_public_key"]) ?: return malformed
        if (key.isWeak) return malformed
        val name = o["gateway_name"]?.stringValue
        if (name.isNullOrEmpty()) return malformed
        val relay = o["relay"]?.stringValue ?: return malformed
        val code = o["code"]?.stringValue
        if (code == null || !Chars.base64Url(code, 22)) return malformed
        val exp = o["expires_at"]?.stringValue ?: return malformed
        val expMs = Timestamp.parse(exp) ?: return malformed
        val known = setOf("v", "gateway_public_key", "gateway_name", "relay", "code", "expires_at")
        if (!o.keys.all { it in known }) return malformed
        if (nowMs > expMs) return Outcome.Err(QrParseError.EXPIRED)
        return Outcome.Ok(QrPayload(1, key, name, relay, code, exp))
    }

    /**
     * The first query parameter `name` of a URI (percent-decoded, `+` kept), as URLComponents.queryItems reads it: the
     * query is everything after the first `?` up to a `#`. Split by hand rather than with java.net.URI, which refuses
     * a whole URI over one junk character in another parameter. A `d` that does not percent-decode is malformed.
     */
    internal fun queryParameter(uri: String, name: String): String? {
        val q = uri.substringAfter('?', "").substringBefore('#')
        if (q.isEmpty()) return null
        for (part in q.split("&")) {
            val eq = part.indexOf('=')
            val k = percentDecode(if (eq < 0) part else part.substring(0, eq)) ?: continue
            if (k == name) return if (eq < 0) null else percentDecode(part.substring(eq + 1))
        }
        return null
    }

    private fun percentDecode(s: String): String? {
        if ('%' !in s) return s
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) return null
                val v = s.substring(i + 1, i + 3).toIntOrNull(16) ?: return null
                out.write(v)
                i += 3
            } else {
                out.write(c.toString().toByteArray(Charsets.UTF_8))
                i++
            }
        }
        return Utf8.decodeStrict(out.toByteArray())
    }

    // ids and proof

    /** §5.3: `pairing_id = base64url(SHA-256(code))[0:22]`. */
    fun pairingId(code: String): String = Base64Url.encode(Digest.sha256(code)).substring(0, 22)

    /** §7.3 `code_hash`: lowercase hex SHA-256 of the code text. */
    fun codeHash(code: String): String = Digest.sha256Hex(code)

    /** JCS of `{device_id, device_public_key, gateway_id}`. */
    fun proofSigningInput(gatewayId: String, deviceId: String, devicePublicKey: PublicJwk): String = Jcs.canonicalize(
        JsonValue.obj("device_id" to JsonValue.of(deviceId), "device_public_key" to devicePublicKey.json, "gateway_id" to JsonValue.of(gatewayId)),
    )

    /** `proof = HMAC-SHA256(key = code, msg = proofSigningInput)`, base64url without padding. Proof v1. */
    fun proof(code: String, gatewayId: String, deviceId: String, devicePublicKey: PublicJwk): String =
        hmac(code, proofSigningInput(gatewayId, deviceId, devicePublicKey))

    /** Lowercase hex SHA-256 of the JCS of `{data, format}`; null when there is no attestation. */
    fun attestationSha256(a: Attestation?): String? {
        if (a == null) return null
        return Digest.sha256Hex(Jcs.canonicalize(JsonValue.obj("data" to JsonValue.of(a.data), "format" to JsonValue.of(a.format))))
    }

    /**
     * Proof v2 input (§5.3): JCS of `{attestation_sha256, device_id, device_public_key, gateway_id, name, platform,
     * proof_version: 2}`, absent metadata as null. `proof_version` makes it never equal to a v1 input.
     */
    fun proofV2SigningInput(gatewayId: String, deviceId: String, devicePublicKey: PublicJwk, name: String?, platform: String?, attestation: Attestation?): String =
        Jcs.canonicalize(
            JsonValue.obj(
                "attestation_sha256" to JsonValue.ofNullable(attestationSha256(attestation)),
                "device_id" to JsonValue.of(deviceId),
                "device_public_key" to devicePublicKey.json,
                "gateway_id" to JsonValue.of(gatewayId),
                "name" to JsonValue.ofNullable(name),
                "platform" to JsonValue.ofNullable(platform),
                "proof_version" to JsonValue.of(2),
            ),
        )

    /**
     * Proof v2: `HMAC-SHA256(key = code, msg = proofV2SigningInput)`, base64url without padding. Sent as
     * `device.proof_v2` next to the v1 `proof`, so a relay cannot rename the device, change its platform or strip its
     * attestation without the gateway noticing; a gateway from before v2 ignores it.
     */
    fun proofV2(code: String, gatewayId: String, deviceId: String, devicePublicKey: PublicJwk, name: String?, platform: String?, attestation: Attestation?): String =
        hmac(code, proofV2SigningInput(gatewayId, deviceId, devicePublicKey, name, platform, attestation))

    private fun hmac(code: String, input: String): String =
        Base64Url.encode(Hmac.sha256(code.toByteArray(Charsets.UTF_8), input.toByteArray(Charsets.UTF_8)))

    // claim

    data class Claim(
        val pairingId: String,
        val gatewayId: String,
        val deviceId: String,
        /** `POST /v1/pairings/{pairing_id}/claim` body. */
        val body: JsonValue,
    )

    /**
     * Build the claim (§7.3) from the QR and the device's own public key. Re-checks expiry. The claim carries proof v1
     * and `device.proof_v2`; `proofV2 = false` leaves v2 out (what iOS build 7 sent; tests only).
     */
    fun claim(
        qr: QrPayload,
        devicePublicKey: PublicJwk,
        platform: String,
        name: String,
        attestation: Attestation?,
        software: Boolean,
        nowMs: Long,
        proofV2: Boolean = true,
    ): Outcome<Claim, QrParseError> {
        val exp = Timestamp.parse(qr.expiresAt)
        if (exp == null || nowMs > exp) return Outcome.Err(QrParseError.EXPIRED)
        val deviceId = devicePublicKey.deviceId
        val gatewayId = qr.gatewayId
        val device = ArrayList<Pair<String, JsonValue>>()
        device += "public_key" to devicePublicKey.json
        device += "platform" to JsonValue.of(platform)
        device += "name" to JsonValue.of(name)
        device += "attestation" to (attestation?.json ?: JsonValue.Null)
        device += "software" to JsonValue.of(software)
        if (proofV2) {
            device += "proof_v2" to JsonValue.of(proofV2(qr.code, gatewayId, deviceId, devicePublicKey, name, platform, attestation))
        }
        val body = JsonValue.obj(
            "device" to JsonValue.Obj(JsonObject(device)),
            "proof" to JsonValue.of(proof(qr.code, gatewayId, deviceId, devicePublicKey)),
        )
        return Outcome.Ok(Claim(qr.pairingId, gatewayId, deviceId, body))
    }

    // confirmation

    /** Shape check for a pin list received from the network (absent → []). null when it is not one. */
    fun parseTemplatesPinned(v: JsonValue?): List<TemplatePin>? {
        if (v == null) return emptyList()
        val arr = v.arrayValue ?: return null
        return arr.map { p ->
            val o = p.objectValue ?: return null
            if (o.size != 3) return null
            val id = o["template_id"]?.stringValue ?: return null
            if (id.length !in 1..128) return null
            val verD = o["template_version"]?.numberValue ?: return null
            if (!CanonicalActions.isJsInteger(verD) || verD < 1 || verD >= TWO_63) return null
            val sha = o["sha256"]?.stringValue ?: return null
            if (!Chars.hex64(sha)) return null
            TemplatePin(id, verD.toLong(), sha)
        }
    }

    /**
     * §5.3 point 7: a confirmation's `approver_id` is 1 to 64 characters (UTF-16 code units, as JavaScript counts
     * them, matching a receipt's bounds) with no control characters.
     */
    fun isValidApproverId(s: String): Boolean = s.length in 1..64 && s.none { it.code < 0x20 || it.code == 0x7F }

    /** `JCS{approver_id, device_id, gateway_id, paired_at, pairing_id, templates_pinned}`, pins in the order received. */
    fun confirmationSigningInput(gatewayId: String, deviceId: String, pairingId: String, pairedAt: String, approverId: String, templatesPinned: List<TemplatePin>): String =
        Jcs.canonicalize(
            JsonValue.obj(
                "approver_id" to JsonValue.of(approverId),
                "device_id" to JsonValue.of(deviceId),
                "gateway_id" to JsonValue.of(gatewayId),
                "paired_at" to JsonValue.of(pairedAt),
                "pairing_id" to JsonValue.of(pairingId),
                "templates_pinned" to JsonValue.of(templatesPinned.map { it.json }),
            ),
        )

    /**
     * §5.3 points 4 and 7, §5.4: verify the confirmation with the key from the QR (never one from the relay) over the
     * approver and the pin list as received, then produce the record to store. Nothing is pinned on failure. A
     * confirmation without a valid `approver_id` is invalid.
     */
    fun acceptConfirmation(
        qr: QrPayload,
        devicePublicKey: PublicJwk,
        pairingId: String,
        deviceId: String?,
        pairedAt: String,
        confirmation: String,
        approverId: JsonValue?,
        templatesPinned: JsonValue?,
    ): Outcome<PinnedGateway, ConfirmationError> {
        val gatewayId = qr.gatewayId
        val ownDeviceId = devicePublicKey.deviceId
        if (pairingId != qr.pairingId || (deviceId != null && deviceId != ownDeviceId)) return Outcome.Err(ConfirmationError.PAIRING_MISMATCH)
        val pins = parseTemplatesPinned(templatesPinned) ?: return Outcome.Err(ConfirmationError.CONFIRMATION_INVALID)
        val approver = approverId?.stringValue
        if (approver == null || !isValidApproverId(approver)) return Outcome.Err(ConfirmationError.CONFIRMATION_INVALID)
        val si = confirmationSigningInput(gatewayId, ownDeviceId, pairingId, pairedAt, approver, pins)
        if (!qr.gatewayPublicKey.verify(confirmation, si)) return Outcome.Err(ConfirmationError.CONFIRMATION_INVALID)
        return Outcome.Ok(
            PinnedGateway(
                gatewayId, qr.gatewayName, qr.gatewayPublicKey, qr.gatewayFingerprint, ownDeviceId, devicePublicKey.fingerprint,
                pairingId, pairedAt, qr.relay, approver, pins,
            ),
        )
    }

    /** `GET /v1/pairings/{id}` view → confirmation acceptance. Returns null while still open/claimed. */
    fun acceptConfirmation(qr: QrPayload, devicePublicKey: PublicJwk, view: JsonValue): Outcome<PinnedGateway, ConfirmationError>? {
        if (view["status"]?.stringValue != "confirmed") return null
        val pairedAt = view["paired_at"]?.stringValue
        val conf = view["confirmation"]?.stringValue
        if (pairedAt == null || conf == null) return Outcome.Err(ConfirmationError.CONFIRMATION_INVALID)
        // The pairing id is our own (derived from the QR code), as the CLI does; the relay's echo is not trusted.
        val pid = view["pairing_id"]?.stringValue
        if (pid != null && pid != qr.pairingId) return Outcome.Err(ConfirmationError.PAIRING_MISMATCH)
        return acceptConfirmation(qr, devicePublicKey, qr.pairingId, view["device_id"]?.stringValue, pairedAt, conf, view["approver_id"], view["templates_pinned"])
    }

    // Attestation formats

    /**
     * The `clientDataHash` SignetoSign (iOS) uses for App Attest: the 32-byte RFC 7638 thumbprint of the device public
     * key. Kept for completeness; an Android device attests with [ANDROID_KEY_ATTESTATION_FORMAT].
     */
    fun appAttestClientDataHash(devicePublicKey: PublicJwk): ByteArray = devicePublicKey.thumbprint
    const val APP_ATTEST_FORMAT = "apple-appattest"

    /**
     * Android Key Attestation (§5.3 point 3): data = base64url(JCS `{"x5c": [<b64url DER leaf>, …, <root>]}`), the
     * Keystore certificate chain of the device key. The binding is the leaf's public key, which must equal the
     * claim's `public_key`; the attestation challenge carries no meaning.
     */
    const val ANDROID_KEY_ATTESTATION_FORMAT = "android-key"

    /** The `data` of an `android-key` attestation for a certificate chain (DER, leaf first). */
    fun androidKeyAttestationData(chain: List<ByteArray>): String =
        Base64Url.encode(Jcs.canonicalBytes(JsonValue.obj("x5c" to JsonValue.of(chain.map { JsonValue.of(Base64Url.encode(it)) }))))
}
