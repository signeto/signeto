// A JSON value model and a strict RFC 8259 parser with the semantics of ECMAScript `JSON.parse`,
// which is what `@signeto/protocol` uses on the receiving side:
//   - numbers are IEEE 754 doubles;
//   - a duplicate member name keeps its first position and takes the last value;
//   - member names are compared by exact code units (never Unicode-normalised).
// Differences, both fail-closed: lone UTF-16 surrogates in `\u` escapes and numbers that overflow to
// infinity are parse errors here (RFC 8785 §3.2.2.2 / I-JSON forbid them; JS would accept the first and
// fail later on the second). Port of SignetoSign JSON.swift.
package dev.signeto.sign

/** A JSON value. Objects keep member order (source order when parsed). */
sealed class JsonValue {
    object Null : JsonValue() {
        override fun toString(): String = "null"
    }

    data class Bool(val value: Boolean) : JsonValue()

    /** A number. Equality is numeric (`-0 == 0`), as in JavaScript and Swift. */
    class Num(val value: Double) : JsonValue() {
        override fun equals(other: Any?): Boolean = other is Num && other.value == value
        override fun hashCode(): Int = if (value == 0.0) 0 else value.hashCode()
        override fun toString(): String = "Num($value)"
    }

    data class Str(val value: String) : JsonValue()
    data class Arr(val items: List<JsonValue>) : JsonValue()
    data class Obj(val obj: JsonObject) : JsonValue()

    val stringValue: String? get() = (this as? Str)?.value
    val numberValue: Double? get() = (this as? Num)?.value
    val boolValue: Boolean? get() = (this as? Bool)?.value
    val arrayValue: List<JsonValue>? get() = (this as? Arr)?.items
    val objectValue: JsonObject? get() = (this as? Obj)?.obj
    val isNull: Boolean get() = this === Null

    /** An integer-valued number, as `Number.isInteger` would accept it, within the safe range. */
    val intValue: Long?
        get() {
            val d = numberValue ?: return null
            if (!d.isFinite() || truncate(d) != d || Math.abs(d) > 9_007_199_254_740_991.0) return null
            return d.toLong()
        }

    operator fun get(key: String): JsonValue? = objectValue?.get(key)

    companion object {
        fun of(s: String): JsonValue = Str(s)
        fun of(b: Boolean): JsonValue = Bool(b)
        fun of(n: Double): JsonValue = Num(n)
        fun of(n: Int): JsonValue = Num(n.toDouble())
        fun of(n: Long): JsonValue = Num(n.toDouble())
        fun of(items: List<JsonValue>): JsonValue = Arr(items)
        fun of(o: JsonObject): JsonValue = Obj(o)
        fun ofNullable(s: String?): JsonValue = if (s == null) Null else Str(s)

        /** An object from pairs, in order (a repeated name keeps its first position and takes the last value). */
        fun obj(vararg pairs: Pair<String, JsonValue>): JsonValue = Obj(JsonObject(pairs.toList()))

        internal fun truncate(d: Double): Double = if (d < 0) Math.ceil(d) else Math.floor(d)
    }
}

/** An ordered JSON object. Member order is insertion order (source order when parsed). Immutable. */
class JsonObject internal constructor(private val map: LinkedHashMap<String, JsonValue>) {
    constructor() : this(LinkedHashMap())

    /** From pairs, in order (a repeated name keeps its first position and takes the last value). */
    constructor(pairs: List<Pair<String, JsonValue>>) : this(LinkedHashMap<String, JsonValue>().also { m -> pairs.forEach { m[it.first] = it.second } })

    val keys: List<String> get() = map.keys.toList()
    val entries: List<Pair<String, JsonValue>> get() = map.entries.map { it.key to it.value }
    val size: Int get() = map.size
    fun isEmpty(): Boolean = map.isEmpty()
    fun contains(key: String): Boolean = map.containsKey(key)
    operator fun get(key: String): JsonValue? = map[key]

    /** A copy with `key` set to `value` (kept in place when present), or removed when `value` is null. */
    fun with(key: String, value: JsonValue?): JsonObject {
        val m = LinkedHashMap(map)
        if (value == null) m.remove(key) else m[key] = value
        return JsonObject(m)
    }

    /** A copy without these keys. */
    fun without(vararg keys: String): JsonObject {
        val m = LinkedHashMap(map)
        keys.forEach { m.remove(it) }
        return JsonObject(m)
    }

    /**
     * Keys in ECMAScript `Object.keys` order: canonical array-index keys ("0", "1", … up to 2^32 − 2) first in
     * ascending numeric order, then every other key in insertion order. The TS renderer walks `args_resolved` in this
     * order, so the first unreferenced key and the `hidden` list depend on it.
     */
    val ecmaScriptKeyOrder: List<String>
        get() {
            val indices = ArrayList<Pair<Long, String>>()
            val others = ArrayList<String>()
            for (k in map.keys) {
                if (k.length <= 10 && Chars.isCanonicalUInt(k)) {
                    val n = k.toLong()
                    if (n <= 4_294_967_294L) {
                        indices.add(n to k)
                        continue
                    }
                }
                others.add(k)
            }
            return indices.sortedBy { it.first }.map { it.second } + others
        }

    /** Same members and values; order does not matter. */
    override fun equals(other: Any?): Boolean = other is JsonObject && other.map == map
    override fun hashCode(): Int = map.hashCode()
    override fun toString(): String = map.toString()
}

class JsonParseException(message: String, val offset: Int) : Exception("JSON parse error at byte $offset: $message")

object JsonParser {
    /** Parses a complete JSON text (whitespace allowed around the value, nothing else). */
    fun parse(text: String): JsonValue {
        val bytes = Utf8.encodeStrict(text) ?: throw JsonParseException("lone surrogate in text", 0)
        return parseValid(bytes)
    }

    /** Parses UTF-8 bytes from the network: invalid UTF-8 is an error, never repaired. */
    fun parse(bytes: ByteArray): JsonValue {
        if (Utf8.decodeStrict(bytes) == null) throw JsonParseException("invalid UTF-8", 0)
        return parseValid(bytes)
    }

    private fun parseValid(bytes: ByteArray): JsonValue {
        val p = Parser(bytes)
        p.skipWS()
        val v = p.value(0)
        p.skipWS()
        if (p.i != bytes.size) throw p.error("unexpected trailing characters")
        return v
    }

    private class Parser(val b: ByteArray) {
        var i = 0

        fun error(m: String) = JsonParseException(m, i)
        fun at(j: Int): Int = b[j].toInt() and 0xFF

        fun skipWS() {
            while (i < b.size) {
                val c = at(i)
                if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) i++ else break
            }
        }

        fun value(depth: Int): JsonValue {
            if (depth >= MAX_DEPTH) throw error("nesting too deep")
            if (i >= b.size) throw error("unexpected end")
            return when (at(i)) {
                0x7B -> obj(depth)
                0x5B -> arr(depth)
                0x22 -> JsonValue.Str(string())
                0x74 -> { literal("true"); JsonValue.Bool(true) }
                0x66 -> { literal("false"); JsonValue.Bool(false) }
                0x6E -> { literal("null"); JsonValue.Null }
                0x2D, in 0x30..0x39 -> JsonValue.Num(number())
                else -> throw error("unexpected character")
            }
        }

        fun literal(s: String) {
            if (i + s.length > b.size) throw error("invalid literal")
            for (k in s.indices) if (at(i + k) != s[k].code) throw error("invalid literal")
            i += s.length
        }

        fun obj(depth: Int): JsonValue {
            i++
            val m = LinkedHashMap<String, JsonValue>()
            skipWS()
            if (i < b.size && at(i) == 0x7D) { i++; return JsonValue.Obj(JsonObject(m)) }
            while (true) {
                skipWS()
                if (i >= b.size || at(i) != 0x22) throw error("expected member name")
                val k = string()
                skipWS()
                if (i >= b.size || at(i) != 0x3A) throw error("expected ':'")
                i++
                skipWS()
                val v = value(depth + 1)
                m[k] = v // duplicate: first position, last value (JSON.parse semantics)
                skipWS()
                if (i >= b.size) throw error("unexpected end in object")
                if (at(i) == 0x2C) { i++; continue }
                if (at(i) == 0x7D) { i++; return JsonValue.Obj(JsonObject(m)) }
                throw error("expected ',' or '}'")
            }
        }

        fun arr(depth: Int): JsonValue {
            i++
            val a = ArrayList<JsonValue>()
            skipWS()
            if (i < b.size && at(i) == 0x5D) { i++; return JsonValue.Arr(a) }
            while (true) {
                skipWS()
                a.add(value(depth + 1))
                skipWS()
                if (i >= b.size) throw error("unexpected end in array")
                if (at(i) == 0x2C) { i++; continue }
                if (at(i) == 0x5D) { i++; return JsonValue.Arr(a) }
                throw error("expected ',' or ']'")
            }
        }

        fun hex4(): Int {
            if (i + 4 > b.size) throw error("short \\u escape")
            var v = 0
            repeat(4) {
                val c = at(i)
                val d = when (c) {
                    in 0x30..0x39 -> c - 0x30
                    in 0x41..0x46 -> c - 0x41 + 10
                    in 0x61..0x66 -> c - 0x61 + 10
                    else -> throw error("bad hex digit in \\u escape")
                }
                v = (v shl 4) or d
                i++
            }
            return v
        }

        fun string(): String {
            i++ // opening quote
            val out = java.io.ByteArrayOutputStream()
            while (true) {
                if (i >= b.size) throw error("unterminated string")
                val c = at(i)
                if (c == 0x22) { i++; break }
                if (c < 0x20) throw error("control character in string")
                if (c != 0x5C) { out.write(c); i++; continue }
                i++
                if (i >= b.size) throw error("unterminated escape")
                val e = at(i)
                i++
                when (e) {
                    0x22 -> out.write(0x22)
                    0x5C -> out.write(0x5C)
                    0x2F -> out.write(0x2F)
                    0x62 -> out.write(0x08)
                    0x66 -> out.write(0x0C)
                    0x6E -> out.write(0x0A)
                    0x72 -> out.write(0x0D)
                    0x74 -> out.write(0x09)
                    0x75 -> {
                        val hi = hex4()
                        val scalar: Int
                        if (hi in 0xD800..0xDBFF) {
                            if (!(i + 6 <= b.size && at(i) == 0x5C && at(i + 1) == 0x75)) throw error("lone surrogate")
                            i += 2
                            val lo = hex4()
                            if (lo !in 0xDC00..0xDFFF) throw error("lone surrogate")
                            scalar = 0x10000 + ((hi - 0xD800) shl 10) + (lo - 0xDC00)
                        } else if (hi in 0xDC00..0xDFFF) {
                            throw error("lone surrogate")
                        } else {
                            scalar = hi
                        }
                        Utf8.appendScalar(out, scalar)
                    }
                    else -> throw error("invalid escape")
                }
            }
            return Utf8.decodeStrict(out.toByteArray()) ?: throw error("invalid UTF-8 in string")
        }

        fun number(): Double {
            val start = i
            if (at(i) == 0x2D) i++
            if (i >= b.size || !Chars.isDigit(at(i))) throw error("bad number")
            if (at(i) == 0x30) {
                i++
            } else {
                while (i < b.size && Chars.isDigit(at(i))) i++
            }
            if (i < b.size && at(i) == 0x2E) {
                i++
                if (i >= b.size || !Chars.isDigit(at(i))) throw error("bad fraction")
                while (i < b.size && Chars.isDigit(at(i))) i++
            }
            if (i < b.size && (at(i) == 0x65 || at(i) == 0x45)) {
                i++
                if (i < b.size && (at(i) == 0x2B || at(i) == 0x2D)) i++
                if (i >= b.size || !Chars.isDigit(at(i))) throw error("bad exponent")
                while (i < b.size && Chars.isDigit(at(i))) i++
            }
            // The grammar above admits only what Double.parseDouble reads exactly (correctly rounded).
            val d = String(b, start, i - start, Charsets.US_ASCII).toDouble()
            if (!d.isFinite()) throw error("number out of range")
            return d
        }

        companion object {
            const val MAX_DEPTH = 512
        }
    }
}

/** Strict UTF-8: no repair, no surrogates, no overlong forms. (Platform decoders differ; this one does not.) */
object Utf8 {
    /** The string, or null when `bytes` is not valid UTF-8. */
    fun decodeStrict(bytes: ByteArray): String? {
        val sb = StringBuilder(bytes.size)
        var i = 0
        val n = bytes.size
        while (i < n) {
            val b0 = bytes[i].toInt() and 0xFF
            if (b0 < 0x80) { sb.append(b0.toChar()); i++; continue }
            val len: Int
            var cp: Int
            val min: Int
            when {
                b0 in 0xC2..0xDF -> { len = 2; cp = b0 and 0x1F; min = 0x80 }
                b0 in 0xE0..0xEF -> { len = 3; cp = b0 and 0x0F; min = 0x800 }
                b0 in 0xF0..0xF4 -> { len = 4; cp = b0 and 0x07; min = 0x10000 }
                else -> return null
            }
            if (i + len > n) return null
            for (k in 1 until len) {
                val bk = bytes[i + k].toInt() and 0xFF
                if (bk and 0xC0 != 0x80) return null
                cp = (cp shl 6) or (bk and 0x3F)
            }
            if (cp < min || cp > 0x10FFFF || cp in 0xD800..0xDFFF) return null
            sb.appendCodePoint(cp)
            i += len
        }
        return sb.toString()
    }

    /** UTF-8 bytes, or null when `s` holds a lone surrogate (which has no UTF-8 form). */
    fun encodeStrict(s: String): ByteArray? {
        if (Chars.hasLoneSurrogate(s)) return null
        return s.toByteArray(Charsets.UTF_8)
    }

    /** UTF-8 byte length of a string without lone surrogates (a lone surrogate counts 3, as WTF-8 would). */
    fun length(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            n += when {
                cp < 0x80 -> 1
                cp < 0x800 -> 2
                cp < 0x10000 -> 3
                else -> 4
            }
            i += Character.charCount(cp)
        }
        return n
    }

    internal fun appendScalar(out: java.io.ByteArrayOutputStream, cp: Int) {
        when {
            cp < 0x80 -> out.write(cp)
            cp < 0x800 -> { out.write(0xC0 or (cp shr 6)); out.write(0x80 or (cp and 0x3F)) }
            cp < 0x10000 -> { out.write(0xE0 or (cp shr 12)); out.write(0x80 or ((cp shr 6) and 0x3F)); out.write(0x80 or (cp and 0x3F)) }
            else -> {
                out.write(0xF0 or (cp shr 18)); out.write(0x80 or ((cp shr 12) and 0x3F))
                out.write(0x80 or ((cp shr 6) and 0x3F)); out.write(0x80 or (cp and 0x3F))
            }
        }
    }
}
