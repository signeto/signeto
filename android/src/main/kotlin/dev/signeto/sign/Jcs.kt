// RFC 8785 JSON Canonicalization Scheme (docs/protocol.md §2.3), byte-identical to
// `@signeto/protocol` src/jcs.ts:
//   - members sorted by UTF-16 code units of their names;
//   - numbers per ECMAScript Number.prototype.toString (shortest round-trip digits, Shortest.kt);
//   - strings escaped as JSON.stringify does (RFC 8785 §3.2.2.2); a lone surrogate is an error, as in TS;
//   - no whitespace.
// Port of SignetoSign JCS.swift.
package dev.signeto.sign

class JcsException(message: String) : Exception(message)

object Jcs {
    /** The JCS text of a value. Throws [JcsException] on a non-finite number or a lone surrogate. */
    fun canonicalize(value: JsonValue): String {
        val out = StringBuilder()
        write(value, out)
        return out.toString()
    }

    /** The JCS bytes (UTF-8) of a value. */
    fun canonicalBytes(value: JsonValue): ByteArray = canonicalize(value).toByteArray(Charsets.UTF_8)

    /** True when `text` is already the JCS serialization of the value it parses to. */
    fun isCanonical(text: String): Boolean = try {
        canonicalize(JsonParser.parse(text)) == text
    } catch (_: Exception) {
        false
    }

    private fun write(v: JsonValue, out: StringBuilder) {
        when (v) {
            JsonValue.Null -> out.append("null")
            is JsonValue.Bool -> out.append(if (v.value) "true" else "false")
            is JsonValue.Num -> out.append(formatNumber(v.value))
            is JsonValue.Str -> writeString(v.value, out)
            is JsonValue.Arr -> {
                out.append('[')
                v.items.forEachIndexed { i, e ->
                    if (i > 0) out.append(',')
                    write(e, out)
                }
                out.append(']')
            }
            is JsonValue.Obj -> {
                out.append('{')
                // Member order: UTF-16 code unit comparison (what JS `Array.prototype.sort` does on strings);
                // Kotlin's String.compareTo is exactly that.
                v.obj.entries.sortedWith { a, b -> a.first.compareTo(b.first) }.forEachIndexed { i, e ->
                    if (i > 0) out.append(',')
                    writeString(e.first, out)
                    out.append(':')
                    write(e.second, out)
                }
                out.append('}')
            }
        }
    }

    private val hexDigits = "0123456789abcdef".toCharArray()

    /**
     * JSON.stringify string escaping: `"` and `\` escaped, \b \f \n \r \t short forms, every other control character
     * below U+0020 as lowercase `\u00xx`, everything else verbatim.
     */
    fun writeString(s: String, out: StringBuilder) {
        if (Chars.hasLoneSurrogate(s)) throw JcsException("lone surrogate in string")
        out.append('"')
        for (c in s) {
            when (val u = c.code) {
                0x22 -> out.append("\\\"")
                0x5C -> out.append("\\\\")
                0x08 -> out.append("\\b")
                0x0C -> out.append("\\f")
                0x0A -> out.append("\\n")
                0x0D -> out.append("\\r")
                0x09 -> out.append("\\t")
                in 0x00 until 0x20 -> out.append("\\u00").append(hexDigits[u shr 4]).append(hexDigits[u and 0xF])
                else -> out.append(c)
            }
        }
        out.append('"')
    }

    /** ECMAScript Number::toString(x) for finite x (ECMA-262 §6.1.6.1.20), as JSON.stringify emits it. */
    fun formatNumber(x: Double): String {
        if (!x.isFinite()) throw JcsException("non-finite number")
        if (x == 0.0) return "0" // +0 and -0
        if (x < 0) return "-" + formatNumber(-x)

        // value = 0.d1d2…dk × 10^n, i.e. s × 10^(n−k)
        val (s, n) = Shortest.digits(x)
        val k = s.length

        if (k <= n && n <= 21) return s + "0".repeat(n - k)
        if (0 < n && n <= 21) return s.substring(0, n) + "." + s.substring(n)
        if (-6 < n && n <= 0) return "0." + "0".repeat(-n) + s
        val e = n - 1
        val expPart = "e" + (if (e >= 0) "+" else "-") + Math.abs(e)
        if (k == 1) return s + expPart
        return s.substring(0, 1) + "." + s.substring(1) + expPart
    }
}
