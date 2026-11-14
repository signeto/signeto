// docs/protocol.md §5.6: gateway succession ("handoff"), device side. A gateway G1 that is being replaced names its
// successor G2 in a Tier 3 canonical action of the built-in tool `signeto.gateway_handoff`, signed like every
// approval request (`gateway_signature`, §7.5) and approved like every action (a receipt over the exact bytes).
// A device that pinned G1 pins G2, with the same approver binding and template pins, only when G1's signature
// verifies under its own pin and its OWN receipt approves those bytes. Mirrors `verifyHandoffForDevice` and
// `verifyHandoffCompletion` in src/handoff.ts; `vectors/handoff/` fixes both. Port of SignetoSign Handoff.swift.
package dev.signeto.sign

/** §5.6.5 failure codes; the checks run in the order of `Handoff.verifyForDevice` and the first failure is reported. */
enum class HandoffVerifyCode(val code: String) {
    HANDOFF_MALFORMED("handoff_malformed"),
    NOT_A_HANDOFF("not_a_handoff"),
    HANDOFF_UNSUPPORTED("handoff_unsupported"),
    SUCCESSOR_MISMATCH("successor_mismatch"),
    GATEWAY_NOT_PINNED("gateway_not_pinned"),
    GATEWAY_SIGNATURE_INVALID("gateway_signature_invalid"),
    RECEIPT_MALFORMED("receipt_malformed"),
    RECEIPT_NOT_OWN("receipt_not_own"),
    RECEIPT_MISMATCH("receipt_mismatch"),
    APPROVER_MISMATCH("approver_mismatch"),
    HANDOFF_NOT_APPROVED("handoff_not_approved"),
    HASH_MISMATCH("hash_mismatch"),
    INVALID_SIGNATURE("invalid_signature"),
    CLOCK_SKEW("clock_skew"),
    COMPLETION_INVALID("completion_invalid"),
}

/** The approved handoff as it travels: the §7.5 request's action id, canonical bytes and G1's `gateway_signature`. */
data class HandoffRequest(val actionId: String, val canonicalBytes: String, val gatewaySignature: String) {
    companion object {
        /** From `{action_id, canonical_bytes, gateway_signature}`. */
        fun fromJson(v: JsonValue): HandoffRequest? {
            val a = v["action_id"]?.stringValue ?: return null
            val b = v["canonical_bytes"]?.stringValue ?: return null
            val s = v["gateway_signature"]?.stringValue ?: return null
            return HandoffRequest(a, b, s)
        }
    }
}

/** What the device holds for the gateway it pinned (§5.3, §5.4). */
data class HandoffGatewayPin(val gatewayId: String, val publicKey: PublicJwk, val approverId: String, val templatesPinned: List<TemplatePin> = emptyList())

/** The pin a device stores for the successor: G2's key, G1's approver binding and template pins. */
data class SuccessorPin(
    val gatewayId: String,
    val publicKey: PublicJwk,
    /** For display (escape it): the successor's name as G1 signed it. */
    val name: String,
    val approverId: String,
    val templatesPinned: List<TemplatePin>,
    val predecessorGatewayId: String,
)

/** The arguments of a handoff action (§5.6.1). */
data class HandoffArgs(
    val successorGatewayId: String,
    val successorPublicKey: PublicJwk,
    val successorName: String,
    val ledgerSeq: Long,
    val ledgerHead: String,
    val policyHash: String,
)

data class VerifiedHandoff(
    val successor: SuccessorPin,
    val action: EncodedAction,
    val args: HandoffArgs,
    /** A completion was supplied and verified: G1 says it handed over and appends nothing more. */
    val completed: Boolean,
    /** The receipt was signed after the approval window, accepted because the completion names this device. */
    val late: Boolean,
)

object Handoff {
    const val TOOL = "signeto.gateway_handoff"
    const val TEMPLATE_VERSION = 1L
    /** `purpose` member of the completion's signing input: signed, never sent. */
    const val COMPLETE_PURPOSE = "gateway.handoff.complete"
    const val MAX_DEVICES = 64
    const val SUCCESSOR_NAME_MAX = 64
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991.0

    /** UTF-8 JCS of the completion object as received without `signature`, with `purpose` added (§5.6.3). */
    fun completionSigningInput(completion: JsonObject): String =
        Jcs.canonicalize(JsonValue.Obj(completion.without("signature").with("purpose", JsonValue.of(COMPLETE_PURPOSE))))

    // ---- arguments ---------------------------------------------------------------------------------------

    /** A public JWK with exactly its RFC 7638 required members, a valid point, and not a small-order Ed25519 key. */
    fun strictPublicJwk(v: JsonValue?): PublicJwk? {
        val k = PublicJwk.parse(v, allowExtraMembers = false) ?: return null
        if (k.isWeak) return null
        if (k is PublicJwk.P256) {
            val xb = Base64Url.decode(k.x) ?: return null
            val yb = Base64Url.decode(k.y) ?: return null
            P256.publicKey(xb, yb) ?: return null
        }
        return k
    }

    /** The successor's display name rule: 1–64 UTF-16 code units, no surrounding whitespace, display-safe. */
    fun isValidSuccessorName(s: String): Boolean = s.length in 1..SUCCESSOR_NAME_MAX && s.trim() == s && Display.isSafe(s)

    private fun isPositiveSafeInteger(d: Double?): Boolean = d != null && CanonicalActions.isJsInteger(d) && d >= 1 && d <= MAX_SAFE_INTEGER

    private val argKeys = setOf("ledger_head", "ledger_seq", "policy_hash", "successor_gateway_id", "successor_name", "successor_public_key")

    /** `handoffArgsError` in src/handoff.ts: the parsed arguments, or null when they are not a well-formed handoff. */
    internal fun parseArgs(o: JsonObject): HandoffArgs? {
        if (o.size != argKeys.size || !o.keys.all { it in argKeys }) return null
        val gw = o["successor_gateway_id"]?.stringValue?.takeIf { Identifiers.isGatewayId(it) } ?: return null
        val key = strictPublicJwk(o["successor_public_key"]) ?: return null
        val name = o["successor_name"]?.stringValue?.takeIf { isValidSuccessorName(it) } ?: return null
        val seq = o["ledger_seq"]?.numberValue
        if (!isPositiveSafeInteger(seq)) return null
        val head = o["ledger_head"]?.stringValue?.takeIf { Chars.hex64(it) } ?: return null
        val policy = o["policy_hash"]?.stringValue?.takeIf { Chars.hex64(it) } ?: return null
        return HandoffArgs(gw, key, name, seq!!.toLong(), head, policy)
    }

    /** §5.6.1: canonical bytes that are a handoff and nothing else. Signatures are not checked here. */
    fun parseAction(canonicalBytes: String): Outcome<Pair<EncodedAction, HandoffArgs>, HandoffVerifyCode> {
        val enc = CanonicalActions.parse(canonicalBytes).valueOrNull ?: return Outcome.Err(HandoffVerifyCode.HANDOFF_MALFORMED)
        val a = enc.action
        if (a.tool != TOOL || a.templateId != TOOL) return Outcome.Err(HandoffVerifyCode.NOT_A_HANDOFF)
        if (a.templateVersion != TEMPLATE_VERSION) return Outcome.Err(HandoffVerifyCode.HANDOFF_UNSUPPORTED)
        if (a.tier != 3 || a.mode != "enforce" || a.batchId != null || a.effectiveAt != null) return Outcome.Err(HandoffVerifyCode.HANDOFF_MALFORMED)
        val args = parseArgs(a.argsResolved) ?: return Outcome.Err(HandoffVerifyCode.HANDOFF_MALFORMED)
        if (args.successorPublicKey.gatewayId != args.successorGatewayId || args.successorGatewayId == a.requester.gatewayId) return Outcome.Err(HandoffVerifyCode.SUCCESSOR_MISMATCH)
        return Outcome.Ok(enc to args)
    }

    // ---- completion (§5.6.3) -----------------------------------------------------------------------------

    private val completionKeys = setOf("action_id", "canonical_bytes_sha256", "predecessor_gateway_id", "successor_gateway_id", "final_seq", "final_entry_hash", "completed_at", "devices", "receipts", "signature")
    private val deviceKeys = setOf("device_id", "public_key", "approver_id", "attested", "platform", "name", "attestation_sha256")

    private fun nullableString(v: JsonValue?, ok: (String) -> Boolean): Boolean {
        if (v == null) return false
        if (v.isNull) return true
        val s = v.stringValue ?: return false
        return ok(s)
    }

    /** `verifyHandoffCompletion`: the ids of the devices the completion lists, or null when it does not verify. */
    internal fun verifyCompletion(v: JsonValue, action: EncodedAction, args: HandoffArgs, actionId: String, predecessorKey: PublicJwk): Set<String>? {
        val c = v.objectValue ?: return null
        if (c.size != completionKeys.size || !c.keys.all { it in completionKeys }) return null
        val aid = c["action_id"]?.stringValue?.takeIf { Identifiers.isActionId(it) } ?: return null
        val hash = c["canonical_bytes_sha256"]?.stringValue?.takeIf { Chars.hex64(it) } ?: return null
        val pred = c["predecessor_gateway_id"]?.stringValue?.takeIf { Identifiers.isGatewayId(it) } ?: return null
        val succ = c["successor_gateway_id"]?.stringValue?.takeIf { Identifiers.isGatewayId(it) } ?: return null
        val finalSeq = c["final_seq"]?.numberValue
        if (!isPositiveSafeInteger(finalSeq)) return null
        c["final_entry_hash"]?.stringValue?.takeIf { Chars.hex64(it) } ?: return null
        c["completed_at"]?.stringValue?.takeIf { Timestamp.parse(it) != null } ?: return null
        val devs = c["devices"]?.arrayValue?.takeIf { it.size in 1..MAX_DEVICES } ?: return null
        val receipts = c["receipts"]?.arrayValue?.takeIf { it.size in 1..MAX_DEVICES } ?: return null
        val sig = c["signature"]?.stringValue?.takeIf { Chars.base64Url(it, 86) } ?: return null
        for (d in devs) {
            val o = d.objectValue ?: return null
            if (o.size != deviceKeys.size || !o.keys.all { it in deviceKeys }) return null
            if (o["device_id"]?.stringValue?.let { Identifiers.isDeviceId(it) } != true) return null
            if (o["approver_id"]?.stringValue?.let { it.length in 1..64 } != true) return null
            if (o["attested"]?.boolValue == null) return null
            if (!nullableString(o["platform"]) { it.length in 1..32 }) return null
            if (!nullableString(o["name"]) { it.length in 1..128 }) return null
            if (!nullableString(o["attestation_sha256"]) { Chars.hex64(it) }) return null
        }
        // Ids, hash and gateways name this handoff; signature by the predecessor.
        if (aid != actionId || hash != action.canonicalBytesSha256) return null
        if (pred != action.action.requester.gatewayId || succ != args.successorGatewayId) return null
        if (!predecessorKey.verify(sig, completionSigningInput(c))) return null
        if (finalSeq!!.toLong() <= args.ledgerSeq) return null
        // Devices: keys valid, ids their thumbprints, sorted and unique (device ids are ASCII: String order is byte order).
        val listed = LinkedHashMap<String, Pair<PublicJwk, String>>()
        var prev = ""
        for (d in devs) {
            val id = d["device_id"]!!.stringValue!!
            val key = strictPublicJwk(d["public_key"]) ?: return null
            if (key.deviceId != id || id <= prev) return null
            prev = id
            listed[id] = key to d["approver_id"]!!.stringValue!!
        }
        // Every receipt: an in-window approval of these bytes by a listed device under its approver.
        for (raw in receipts) {
            val r = Receipts.parse(raw).valueOrNull ?: return null
            val (key, approver) = listed[r.deviceId] ?: return null
            if (r.actionId != aid || r.approverId != approver || r.decision != Decision.APPROVE) return null
            Receipts.verify(raw, canonicalBytes = action.canonicalBytes, issuedAt = action.action.issuedAt, expiresAt = action.action.expiresAt, devicePublicKey = key).valueOrNull ?: return null
        }
        return listed.keys
    }

    // ---- device side (§5.6.5) ----------------------------------------------------------------------------

    /**
     * May this device pin the successor? Only if the handoff is signed by the gateway it pinned (G1's key from its own
     * pin, never from the network) and its own receipt approves exactly these bytes under the approver it was paired
     * as. A receipt signed after the approval window counts only with G1's completion naming this device.
     */
    fun verifyForDevice(handoff: HandoffRequest, pin: HandoffGatewayPin, devicePublicKey: PublicJwk, receipt: JsonValue, completion: JsonValue? = null): Outcome<VerifiedHandoff, HandoffVerifyCode> {
        // 1–3: G1's signature, under the pin.
        val enc0 = CanonicalActions.parse(handoff.canonicalBytes).valueOrNull ?: return Outcome.Err(HandoffVerifyCode.HANDOFF_MALFORMED)
        if (enc0.action.requester.gatewayId != pin.gatewayId) return Outcome.Err(HandoffVerifyCode.GATEWAY_NOT_PINNED)
        val f = if (Identifiers.isActionId(handoff.actionId)) ApprovalRequests.fields(handoff.actionId, handoff.canonicalBytes, enc0.action.expiresAt)?.first else null
        if (f == null || !pin.publicKey.verify(handoff.gatewaySignature, ApprovalRequests.signingInput(f))) return Outcome.Err(HandoffVerifyCode.GATEWAY_SIGNATURE_INVALID)
        // 4–7: a handoff, of a version this device implements, well formed.
        val (action, args) = when (val p = parseAction(handoff.canonicalBytes)) {
            is Outcome.Err -> return p
            is Outcome.Ok -> p.value
        }
        // 8–14: the device's own receipt approved exactly these bytes.
        val rc = Receipts.parse(receipt).valueOrNull
        if (rc == null || rc.webauthn != null) return Outcome.Err(HandoffVerifyCode.RECEIPT_MALFORMED)
        if (rc.deviceId != devicePublicKey.deviceId) return Outcome.Err(HandoffVerifyCode.RECEIPT_NOT_OWN)
        if (rc.actionId != handoff.actionId) return Outcome.Err(HandoffVerifyCode.RECEIPT_MISMATCH)
        if (rc.approverId != pin.approverId) return Outcome.Err(HandoffVerifyCode.APPROVER_MISMATCH)
        if (rc.decision != Decision.APPROVE) return Outcome.Err(HandoffVerifyCode.HANDOFF_NOT_APPROVED)
        if (rc.canonicalBytesSha256 != action.canonicalBytesSha256) return Outcome.Err(HandoffVerifyCode.HASH_MISMATCH)
        val si = Receipts.signingInput(action.canonicalBytesSha256, rc.decision, rc.reason, rc.signedAt)
        if (devicePublicKey.algorithm != rc.alg || !devicePublicKey.verify(rc.signature, si)) return Outcome.Err(HandoffVerifyCode.INVALID_SIGNATURE)
        // 15: the completion, when supplied, is G1's and names this device.
        var completed = false
        var listed = false
        if (completion != null) {
            val ids = verifyCompletion(completion, action, args, handoff.actionId, pin.publicKey) ?: return Outcome.Err(HandoffVerifyCode.COMPLETION_INVALID)
            completed = true
            listed = rc.deviceId in ids
        }
        // 16: inside the approval window, or later with the completion naming this device.
        val at = Timestamp.parse(rc.signedAt)
        val issued = Timestamp.parse(action.action.issuedAt)
        val expires = Timestamp.parse(action.action.expiresAt)
        if (at == null || issued == null || expires == null) return Outcome.Err(HandoffVerifyCode.CLOCK_SKEW)
        val inWindow = at >= issued - Timestamp.CLOCK_SKEW_MS && at <= expires + Timestamp.CLOCK_SKEW_MS
        val late = !inWindow && listed && at > expires
        if (!inWindow && !late) return Outcome.Err(HandoffVerifyCode.CLOCK_SKEW)
        val successor = SuccessorPin(args.successorGatewayId, args.successorPublicKey, args.successorName, pin.approverId, pin.templatesPinned, pin.gatewayId)
        return Outcome.Ok(VerifiedHandoff(successor, action, args, completed, late))
    }
}
