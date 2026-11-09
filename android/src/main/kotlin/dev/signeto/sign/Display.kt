// docs/protocol.md §3.6: the display escape rule, byte for byte the same as `@signeto/protocol` displayEscape and
// fixed by the shared vectors in public/packages/protocol/vectors/display-escape/. Every string a card, list or
// notification shows from a request, a relay or a pairing goes through `Display.escape` first.
// Port of SignetoSign Display.swift. Unlike a Swift String, a Kotlin String can hold a lone surrogate; it is escaped
// as the TypeScript rule does.
package dev.signeto.sign

object Display {
    /**
     * True for a code point shown as an escape instead of itself (§3.6): C0 U+0000–U+001F (TAB, LF, CR included),
     * DEL U+007F, C1 U+0080–U+009F, U+061C, U+200B–U+200F, U+2028–U+202E, U+2060–U+2069, U+FEFF and lone surrogates
     * U+D800–U+DFFF.
     */
    fun isEscaped(v: Int): Boolean =
        v <= 0x1F || (v in 0x7F..0x9F) || v == 0x061C || (v in 0x200B..0x200F) ||
            (v in 0x2028..0x202E) || (v in 0x2060..0x2069) || v == 0xFEFF || (v in 0xD800..0xDFFF)

    /**
     * `s` with every escaped code point replaced by `\n`, `\r`, `\t` or `\u{XX}` (uppercase hex, at least two
     * digits); nothing else changes, a backslash included. Display only: never for bytes that are hashed or signed.
     */
    fun escape(s: String): String {
        if (isSafe(s)) return s
        val out = StringBuilder(s.length + 8)
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i) // a lone surrogate comes back as itself
            val w = Character.charCount(cp)
            if (!isEscaped(cp)) {
                out.appendCodePoint(cp)
            } else {
                when (cp) {
                    0x0A -> out.append("\\n")
                    0x0D -> out.append("\\r")
                    0x09 -> out.append("\\t")
                    else -> out.append("\\u{").append(Integer.toHexString(cp).uppercase().padStart(2, '0')).append('}')
                }
            }
            i += w
        }
        return out.toString()
    }

    /** True when `escape(s) == s`. */
    fun isSafe(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (isEscaped(cp)) return false
            i += Character.charCount(cp)
        }
        return true
    }

    /** A value as a surface shows it outside the template line: `Templates.renderValue`, then `escape`. */
    fun value(v: JsonValue): String = escape(Templates.renderValue(v))
}
