// Byte encodings used on the wire: base64url without padding, lowercase hex, SHA-256.
// Mirrors `@signeto/protocol` src/encoding.ts. Port of SignetoSign Encoding.swift.
//
// Kotlin `String ==` already compares UTF-16 code units exactly (no Unicode normalisation), so the Swift
// `exactlyEqual` helper is plain `==` here.
package dev.signeto.sign

import java.security.MessageDigest

object Base64Url {
    /** base64url without padding (RFC 4648 §5). */
    fun encode(bytes: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /**
     * Decodes base64url without padding. Rejects any character outside `[A-Za-z0-9_-]` (the TS decoder does the
     * same) and lengths that cannot be base64.
     */
    fun decode(s: String): ByteArray? {
        for (c in s) if (!Chars.isBase64Url(c.code)) return null
        if (s.length % 4 == 1) return null
        return try {
            java.util.Base64.getUrlDecoder().decode(s)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}

object Hex {
    private val digits = "0123456789abcdef".toCharArray()

    /** Lowercase hex. */
    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for ((i, b) in bytes.withIndex()) {
            val v = b.toInt() and 0xFF
            out[2 * i] = digits[v shr 4]
            out[2 * i + 1] = digits[v and 0x0F]
        }
        return String(out)
    }

    /** Lowercase hex only, even length. */
    fun decode(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        fun nib(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            else -> -1
        }
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = nib(s[2 * i])
            val lo = nib(s[2 * i + 1])
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}

object Digest {
    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /** SHA-256 of the UTF-8 bytes of `s`. */
    fun sha256(s: String): ByteArray = sha256(s.toByteArray(Charsets.UTF_8))

    /** Lowercase hex SHA-256 of the UTF-8 bytes of `s`. */
    fun sha256Hex(s: String): String = Hex.encode(sha256(s))
    fun sha256Hex(bytes: ByteArray): String = Hex.encode(sha256(bytes))
}

/** Constant-time comparison of two strings' UTF-8 bytes (length leaks, content does not). */
fun timingSafeEqual(a: String, b: String): Boolean {
    val x = Utf8.encodeStrict(a) ?: return false
    val y = Utf8.encodeStrict(b) ?: return false
    return MessageDigest.isEqual(x, y)
}

/** Character-class checks used instead of regular expressions. */
internal object Chars {
    fun isBase64Url(u: Int): Boolean =
        (u in 0x41..0x5A) || (u in 0x61..0x7A) || (u in 0x30..0x39) || u == 0x2D || u == 0x5F
    fun isLowerHex(u: Int): Boolean = (u in 0x30..0x39) || (u in 0x61..0x66)
    fun isDigit(u: Int): Boolean = u in 0x30..0x39

    /** `^[A-Za-z0-9_-]{n}$` */
    fun base64Url(s: String, count: Int): Boolean = s.length == count && s.all { isBase64Url(it.code) }

    /** `^[0-9a-f]{64}$` */
    fun hex64(s: String): Boolean = s.length == 64 && s.all { isLowerHex(it.code) }

    /** `^<prefix>[A-Za-z0-9_-]{43}$` */
    fun prefixedId(s: String, prefix: String): Boolean =
        s.startsWith(prefix) && base64Url(s.substring(prefix.length), 43)

    /** `^(0|[1-9][0-9]*)$` */
    fun isCanonicalUInt(s: String): Boolean {
        if (s.isEmpty() || !s.all { isDigit(it.code) }) return false
        return s[0] != '0' || s.length == 1
    }

    fun isAscii(s: String): Boolean = s.all { it.code < 0x80 }

    /** A high surrogate not followed by a low one, or a low surrogate not preceded by a high one. */
    fun hasLoneSurrogate(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) return true
                i += 2
                continue
            }
            if (Character.isLowSurrogate(c)) return true
            i++
        }
        return false
    }
}
