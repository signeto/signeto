// docs/protocol.md §5.1: public keys as JWK, RFC 7638 thumbprints, gw_/dev_ identifiers, human
// fingerprints; and signature verification for the two algorithms the protocol allows (ADR-0002).
// Mirrors src/ids.ts and src/signing.ts. Port of SignetoSign Keys.swift.
package dev.signeto.sign

enum class SignatureAlgorithm(val wire: String) {
    ES256("ES256"),
    ED25519("Ed25519");

    companion object {
        fun fromWire(s: String): SignatureAlgorithm? = entries.firstOrNull { it.wire == s }
    }
}

/** A public JWK, reduced to the RFC 7638 required members. */
sealed class PublicJwk {
    /** `{"kty":"EC","crv":"P-256","x":…,"y":…}` */
    data class P256(val x: String, val y: String) : PublicJwk()

    /** `{"kty":"OKP","crv":"Ed25519","x":…}` */
    data class Ed25519(val x: String) : PublicJwk()

    val algorithm: SignatureAlgorithm
        get() = when (this) {
            is P256 -> SignatureAlgorithm.ES256
            is Ed25519 -> SignatureAlgorithm.ED25519
        }

    /** The required members as a JSON object (what is serialised on the wire and thumbprinted). */
    val json: JsonValue
        get() = when (this) {
            is P256 -> JsonValue.obj("kty" to JsonValue.of("EC"), "crv" to JsonValue.of("P-256"), "x" to JsonValue.of(x), "y" to JsonValue.of(y))
            is Ed25519 -> JsonValue.obj("kty" to JsonValue.of("OKP"), "crv" to JsonValue.of("Ed25519"), "x" to JsonValue.of(x))
        }

    /** RFC 7638 thumbprint: SHA-256 over the JCS of the required members. */
    val thumbprint: ByteArray get() = Digest.sha256(Jcs.canonicalize(json))

    val gatewayId: String get() = "gw_" + Base64Url.encode(thumbprint)
    val deviceId: String get() = "dev_" + Base64Url.encode(thumbprint)

    /** First 16 hex characters of the thumbprint in groups of four: `3fa9 1c02 b77e d410`. */
    val fingerprint: String
        get() {
            val h = Hex.encode(thumbprint).substring(0, 16)
            return h.chunked(4).joinToString(" ")
        }

    /**
     * Verify `signature` over `data` in this key's algorithm. ES256: ECDSA P-256 over SHA-256(data), raw r||s.
     * Ed25519: PureEdDSA over data. Any malformed input is `false`, never a throw.
     */
    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        if (signature.size != 64) return false
        return when (this) {
            is P256 -> {
                val xb = Base64Url.decode(x) ?: return false
                val yb = Base64Url.decode(y) ?: return false
                dev.signeto.sign.P256.verify(xb, yb, signature, data)
            }
            is Ed25519 -> {
                // §5.1 (SIG-92 N1): nothing verifies under a small-order key.
                val xb = Base64Url.decode(x) ?: return false
                if (xb.size != 32 || Ed25519Keys.isSmallOrder(xb)) return false
                dev.signeto.sign.Ed25519.verify(xb, signature, data)
            }
        }
    }

    /** Verify a base64url signature over the UTF-8 bytes of `input`. */
    fun verify(base64UrlSignature: String, input: String): Boolean {
        val s = Base64Url.decode(base64UrlSignature) ?: return false
        return verify(s, input.toByteArray(Charsets.UTF_8))
    }

    /**
     * §5.1: an Ed25519 key that is a small-order point (or not 32 bytes), refused wherever a key is pinned or parsed.
     * EC P-256 keys are never weak in this sense.
     */
    val isWeak: Boolean
        get() {
            if (this !is Ed25519) return false
            val xb = Base64Url.decode(x) ?: return true
            return Ed25519Keys.isSmallOrder(xb)
        }

    companion object {
        /**
         * Strict parse of a public JWK: exactly the required members, 32-byte coordinates. `allowExtraMembers`
         * accepts (and drops) other members except a private `d`.
         */
        fun parse(json: JsonValue?, allowExtraMembers: Boolean = false): PublicJwk? {
            val o = json?.objectValue ?: return null
            if (o.contains("d")) return null
            val kty = o["kty"]?.stringValue ?: return null
            val crv = o["crv"]?.stringValue ?: return null
            val x = o["x"]?.stringValue ?: return null
            fun coord(s: String) = Chars.base64Url(s, 43) && Base64Url.decode(s)?.size == 32
            val y = o["y"]?.stringValue
            return if (kty == "EC" && crv == "P-256" && y != null) {
                if (!coord(x) || !coord(y) || !(allowExtraMembers || o.size == 4)) null else P256(x, y)
            } else if (kty == "OKP" && crv == "Ed25519" && o["y"] == null) {
                if (!coord(x) || !(allowExtraMembers || o.size == 3)) null else Ed25519(x)
            } else {
                null
            }
        }

        /** From raw 32-byte P-256 coordinates. */
        fun p256(x: ByteArray, y: ByteArray): PublicJwk = P256(Base64Url.encode(x), Base64Url.encode(y))

        /** From a JCA EC public key (software or Android Keystore). */
        fun p256(key: java.security.interfaces.ECPublicKey): PublicJwk =
            p256(dev.signeto.sign.P256.fixed32(key.w.affineX), dev.signeto.sign.P256.fixed32(key.w.affineY))

        /** From a raw 32-byte Ed25519 public key. */
        fun ed25519(raw: ByteArray): PublicJwk = Ed25519(Base64Url.encode(raw))
    }
}

object Identifiers {
    /** `^gw_[A-Za-z0-9_-]{43}$` */
    fun isGatewayId(s: String): Boolean = Chars.prefixedId(s, "gw_")

    /** `^dev_[A-Za-z0-9_-]{43}$` */
    fun isDeviceId(s: String): Boolean = Chars.prefixedId(s, "dev_")

    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** `^act_[0-9A-HJKMNP-TV-Z]{26}$` (ULID, Crockford base32) */
    fun isActionId(s: String): Boolean {
        if (!s.startsWith("act_")) return false
        val rest = s.substring(4)
        return rest.length == 26 && rest.all { CROCKFORD.indexOf(it) >= 0 }
    }

    /** `^[A-Za-z0-9_-]{22}$` */
    fun isNonce(s: String): Boolean = Chars.base64Url(s, 22)
}

/**
 * protocol.md §5.1 (SIG-92 N1): small-order Ed25519 public keys. Such a key (the identity, say) makes the signature
 * R = identity, S = 0 valid for every message. The list is libsodium's: the 8-torsion points by y coordinate,
 * including the non-canonical y = p and p + 1, compared with the sign bit ignored. Mirrors `isSmallOrderEd25519` in
 * `@signeto/protocol`; `vectors/weak-keys/` fixes both.
 */
object Ed25519Keys {
    private val smallOrder: List<ByteArray> = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ).map { Hex.decode(it)!! }

    /** True when `raw` (the 32-byte encoding) is a small-order point. Any other length: true. */
    fun isSmallOrder(raw: ByteArray): Boolean {
        if (raw.size != 32) return true
        return smallOrder.any { blocked ->
            var diff = 0
            for (i in 0 until 31) diff = diff or (raw[i].toInt() xor blocked[i].toInt())
            diff = diff or ((raw[31].toInt() and 0x7F) xor blocked[31].toInt())
            (diff and 0xFF) == 0
        }
    }
}
