// docs/protocol.md §2: the canonical action, receiver side. Mirrors src/action.ts
// `parseCanonicalAction`: parse the bytes as received, validate the 1.x schema, refuse bytes whose JCS
// re-serialization differs (`not_canonical`), check the idempotency key, and hash the received bytes.
// Port of SignetoSign CanonicalAction.swift.
package dev.signeto.sign

data class Requester(
    val agent: String,
    val sessionId: String,
    val host: String,
    val gatewayId: String,
)

data class CanonicalAction(
    /** The parsed object, members in source (JCS) order. */
    val obj: JsonObject,
    val protocolVersion: String,
    val tool: String,
    val templateId: String,
    val templateVersion: Long,
    val argsResolved: JsonObject,
    val requester: Requester,
    val nonce: String,
    val idempotencyKey: String,
    val issuedAt: String,
    val expiresAt: String,
    val originHash: String,
    val tier: Int,
    val mode: String,
    val batchId: String?,
    val batchIndex: Long?,
    val atomic: Boolean?,
    val effectiveAt: String?,
) {
    val isAdvisory: Boolean get() = mode == "advisory"
}

/** Canonical bytes as received plus what was derived from them. */
data class EncodedAction(
    val action: CanonicalAction,
    /** The JCS text exactly as received. Hash and sign these bytes, never a re-serialization. */
    val canonicalBytes: String,
    /** Lowercase hex SHA-256 of `canonicalBytes` (UTF-8). */
    val canonicalBytesSha256: String,
)

enum class ParseActionError(val code: String) {
    ACTION_MALFORMED("action_malformed"),
    NOT_CANONICAL("not_canonical"),
    PROTOCOL_VERSION_UNSUPPORTED("protocol_version_unsupported"),
    IDEMPOTENCY_KEY_MISMATCH("idempotency_key_mismatch"),
}

/** A success or a typed failure (Swift's `Result<T, E>` with a non-Throwable error). */
sealed class Outcome<out T, out E> {
    data class Ok<T>(val value: T) : Outcome<T, Nothing>()
    data class Err<E>(val error: E) : Outcome<Nothing, E>()

    val valueOrNull: T? get() = (this as? Ok)?.value
    val errorOrNull: E? get() = (this as? Err)?.error
}

object CanonicalActions {
    const val PROTOCOL_MAJOR: Int = 1

    /** 2^63: the first double a Long cannot hold. */
    private const val TWO_63 = 9.223372036854775807E18

    /**
     * §2.4: SHA-256 of the JCS of the action minus nonce, idempotency_key, issued_at, expires_at, effective_at and
     * origin_hash.
     */
    fun idempotencyKey(obj: JsonObject): String =
        Digest.sha256Hex(Jcs.canonicalize(JsonValue.Obj(obj.without("nonce", "idempotency_key", "issued_at", "expires_at", "effective_at", "origin_hash"))))

    fun parse(bytes: String): Outcome<EncodedAction, ParseActionError> {
        val raw = try {
            JsonParser.parse(bytes)
        } catch (_: JsonParseException) {
            return Outcome.Err(ParseActionError.ACTION_MALFORMED)
        }
        val pv = raw.objectValue?.get("protocol_version")?.stringValue
        if (pv != null) {
            // Number(split(".")[0]) !== 1
            val major = pv.split(".", limit = 2).first()
            if (jsNumber(major) != PROTOCOL_MAJOR.toDouble()) return Outcome.Err(ParseActionError.PROTOCOL_VERSION_UNSUPPORTED)
        }
        val o = raw.objectValue ?: return Outcome.Err(ParseActionError.ACTION_MALFORMED)
        val action = validate(o) ?: return Outcome.Err(ParseActionError.ACTION_MALFORMED)
        val again = try {
            Jcs.canonicalize(raw)
        } catch (_: JcsException) {
            null
        }
        if (again != bytes) return Outcome.Err(ParseActionError.NOT_CANONICAL)
        val key = try {
            idempotencyKey(o)
        } catch (_: JcsException) {
            null
        }
        if (key != action.idempotencyKey) return Outcome.Err(ParseActionError.IDEMPOTENCY_KEY_MISMATCH)
        return Outcome.Ok(EncodedAction(action, bytes, Digest.sha256Hex(bytes)))
    }

    private val allowed = setOf(
        "protocol_version", "tool", "template_id", "template_version", "args_resolved", "requester", "nonce", "idempotency_key",
        "issued_at", "expires_at", "origin_hash", "tier", "mode", "batch_id", "batch_index", "atomic", "effective_at",
    )

    /** The 1.x schema (§2.2), strict: unknown members are malformed. */
    internal fun validate(o: JsonObject): CanonicalAction? {
        for (k in o.keys) if (k !in allowed) return null

        val pv = o["protocol_version"]?.stringValue ?: return null
        if (!isMinorVersion(pv, "1")) return null
        val tool = o["tool"]?.stringValue ?: return null
        if (!isToolName(tool)) return null
        val tid = o["template_id"]?.stringValue ?: return null
        if (tid.length !in 1..128) return null
        val tver = o["template_version"]?.numberValue ?: return null
        if (!isJsInteger(tver) || tver < 1) return null
        val args = o["args_resolved"]?.objectValue ?: return null
        val req = o["requester"]?.objectValue ?: return null
        val requester = parseRequester(req) ?: return null
        val nonce = o["nonce"]?.stringValue ?: return null
        if (!Identifiers.isNonce(nonce)) return null
        val ikey = o["idempotency_key"]?.stringValue ?: return null
        if (!Chars.hex64(ikey)) return null
        val issued = o["issued_at"]?.stringValue ?: return null
        val issuedMs = Timestamp.parse(issued) ?: return null
        val expires = o["expires_at"]?.stringValue ?: return null
        val expiresMs = Timestamp.parse(expires) ?: return null
        val origin = o["origin_hash"]?.stringValue ?: return null
        if (!Chars.hex64(origin)) return null
        val tier = o["tier"]?.intValue ?: return null
        if (tier !in 1L..3L) return null
        val mode = o["mode"]?.stringValue ?: return null
        if (mode != "enforce" && mode != "advisory") return null

        var batchId: String? = null
        var batchIndex: Long? = null
        var atomic: Boolean? = null
        var effectiveAt: String? = null
        o["batch_id"]?.let { v ->
            val s = v.stringValue ?: return null
            if (!Identifiers.isNonce(s)) return null
            batchId = s
        }
        o["batch_index"]?.let { v ->
            val d = v.numberValue ?: return null
            if (!isJsInteger(d) || d < 0) return null
            batchIndex = if (d < TWO_63) d.toLong() else Long.MAX_VALUE
        }
        o["atomic"]?.let { v ->
            atomic = v.boolValue ?: return null
        }
        o["effective_at"]?.let { v ->
            val s = v.stringValue ?: return null
            if (Timestamp.parse(s) == null) return null
            effectiveAt = s
        }
        if (batchId != null) {
            if (batchIndex == null || atomic == null) return null
        } else {
            if (batchIndex != null || atomic != null) return null
        }
        if (!(expiresMs > issuedMs && expiresMs - issuedMs <= Timestamp.MAX_EXPIRY_MS)) return null
        effectiveAt?.let { e ->
            val eff = Timestamp.parse(e) ?: return null
            if (eff <= issuedMs) return null
        }

        val templateVersion = if (tver < TWO_63) tver.toLong() else -1L
        return CanonicalAction(
            o, pv, tool, tid, templateVersion, args, requester, nonce, ikey, issued, expires, origin, tier.toInt(), mode,
            batchId, batchIndex, atomic, effectiveAt,
        )
    }

    internal fun parseRequester(o: JsonObject): Requester? {
        if (o.size != 4) return null
        val agent = o["agent"]?.stringValue ?: return null
        if (agent.length !in 1..128) return null
        val sid = o["session_id"]?.stringValue ?: return null
        if (sid.length !in 1..256) return null
        val host = o["host"]?.stringValue ?: return null
        if (host.length !in 1..253) return null
        val gw = o["gateway_id"]?.stringValue ?: return null
        if (!Identifiers.isGatewayId(gw)) return null
        return Requester(agent, sid, host, gw)
    }

    /** `^<major>\.(0|[1-9][0-9]*)$` */
    internal fun isMinorVersion(s: String, major: String): Boolean {
        val prefix = "$major."
        if (!s.startsWith(prefix)) return false
        return Chars.isCanonicalUInt(s.substring(prefix.length))
    }

    /** `^[a-z0-9_]+(\.[a-z0-9_]+)+$` */
    internal fun isToolName(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size < 2) return false
        return parts.all { p -> p.isNotEmpty() && p.all { it in 'a'..'z' || it in '0'..'9' || it == '_' } }
    }

    /** `Number.isInteger` (any magnitude). */
    fun isJsInteger(d: Double): Boolean = d.isFinite() && JsonValue.truncate(d) == d

    /** JS `Number(s)` for what a version prefix can hold (decimal, exponent, 0x/0o/0b); NaN otherwise. */
    internal fun jsNumber(s: String): Double {
        val t = s.trim()
        if (t.isEmpty()) return 0.0
        val lower = t.lowercase()
        for ((prefix, radix) in listOf("0x" to 16, "0o" to 8, "0b" to 2)) {
            if (lower.startsWith(prefix)) {
                val digits = lower.substring(2)
                if (digits.isEmpty() || !digits.all { Character.digit(it, radix) >= 0 }) return Double.NaN
                return digits.toBigInteger(radix).toDouble()
            }
        }
        if (!t.all { it in '0'..'9' || it == '.' || it == 'e' || it == 'E' || it == '+' || it == '-' }) return Double.NaN
        return t.toDoubleOrNull() ?: Double.NaN
    }
}
