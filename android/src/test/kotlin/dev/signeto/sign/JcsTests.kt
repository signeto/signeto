package dev.signeto.sign

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JcsTests {
    /** Fixtures/numbers.json: ~3,500 doubles → ECMAScript Number::toString, as produced by the TS canonicalize. */
    @Test
    fun numberFormattingMatchesEcmaScript() {
        val cases = fixture("numbers.json")("cases").arrayValue!!
        assertTrue(cases.size > 3000)
        val failures = ArrayList<String>()
        for (c in cases) {
            val bits = java.lang.Long.parseUnsignedLong(c("bits").s, 16)
            val x = java.lang.Double.longBitsToDouble(bits)
            val got = Jcs.formatNumber(x)
            if (got != c("text").s) failures += "$x [${c("bits").s}]: got $got, want ${c("text").s}"
            // and the text parses back to the same double
            assertEquals(JsonValue.Num(if (x == 0.0) 0.0 else x), JsonParser.parse(got))
        }
        assertEquals(emptyList<String>(), failures.take(10))
    }

    /** Boundaries the fixture may not reach: extremes, powers of two, layout switch points. */
    @Test
    fun numberFormattingEdges() {
        val want = mapOf(
            Double.MIN_VALUE to "5e-324",
            Double.MAX_VALUE to "1.7976931348623157e+308",
            java.lang.Double.MIN_NORMAL to "2.2250738585072014e-308",
            1e21 to "1e+21",
            1e20 to "100000000000000000000",
            123456789012345680000.0 to "123456789012345680000",
            1e-6 to "0.000001",
            1e-7 to "1e-7",
            0.1 + 0.2 to "0.30000000000000004",
            9007199254740993.0 to "9007199254740992",
            5e-324 * 3 to "1.5e-323",
            -1.5 to "-1.5",
            100.0 to "100",
            1.0 / 3 to "0.3333333333333333",
        )
        for ((x, s) in want) assertEquals(s, Jcs.formatNumber(x), "$x")
    }

    @Test
    fun stringEscapingMatchesJsonStringify() {
        for (c in fixture("strings.json")("cases").arrayValue!!) {
            assertEquals(c("jcs").s, Jcs.canonicalize(c("input")))
        }
    }

    @Test
    fun objectsSortByUtf16CodeUnits() {
        for (c in fixture("objects.json")("cases").arrayValue!!) {
            val parsed = JsonParser.parse(c("input").s)
            val out = Jcs.canonicalize(parsed)
            assertEquals(c("jcs").s, out)
            assertTrue(Jcs.isCanonical(out))
            assertFalse(Jcs.isCanonical(c("input").s))
        }
    }

    @Test
    fun canonicalEquivalentKeysStayDistinct() {
        // "é" (U+00E9) and "e\u0301" are canonically equivalent Unicode but distinct JSON member names.
        val v = JsonParser.parse("{\"\u00e9\":1,\"e\u0301\":2}")
        assertEquals(2, v.objectValue?.size)
        assertEquals("{\"e\u0301\":2,\"\u00e9\":1}", Jcs.canonicalize(v))
    }

    @Test
    fun duplicateMembersKeepFirstPositionLastValue() {
        val v = JsonParser.parse("{\"b\":1,\"a\":2,\"b\":3}")
        assertEquals(listOf("b", "a"), v.objectValue?.keys)
        assertEquals(JsonValue.Num(3.0), v["b"])
        assertFalse(Jcs.isCanonical("{\"a\":2,\"b\":1,\"b\":3}"))
    }

    @Test
    fun parserRejectsInvalidJson() {
        for (bad in listOf("", "{", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "+1", "\"\\x\"", "\"a\u0001\"", "nul", "1e400", "\"\\ud800\"", "\"\\udc00\"", "{} x", "NaN", "[1 2]", "\"\ud800\"")) {
            assertThrows(JsonParseException::class.java, { JsonParser.parse(bad) }, "should reject $bad")
        }
    }

    @Test
    fun parserRejectsInvalidUtf8() {
        assertThrows(JsonParseException::class.java) { JsonParser.parse(byteArrayOf(0x22, 0xC3.toByte(), 0x28, 0x22)) }
        assertThrows(JsonParseException::class.java) { JsonParser.parse(byteArrayOf(0x22, 0xED.toByte(), 0xA0.toByte(), 0x80.toByte(), 0x22)) } // encoded surrogate
        assertThrows(JsonParseException::class.java) { JsonParser.parse(byteArrayOf(0x22, 0xC0.toByte(), 0xAF.toByte(), 0x22)) } // overlong '/'
        assertThrows(JsonParseException::class.java) { JsonParser.parse(byteArrayOf(0x22, 0xF4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte(), 0x22)) } // > U+10FFFF
        assertEquals(str("\uD83D\uDE00"), JsonParser.parse(byteArrayOf(0x22, 0xF0.toByte(), 0x9F.toByte(), 0x98.toByte(), 0x80.toByte(), 0x22)))
        assertEquals(str("\uD83D\uDE00"), JsonParser.parse("\"\\ud83d\\ude00\""))
    }

    @Test
    fun nonFiniteNumbersAndLoneSurrogatesThrow() {
        assertThrows(JcsException::class.java) { Jcs.formatNumber(Double.POSITIVE_INFINITY) }
        assertThrows(JcsException::class.java) { Jcs.formatNumber(Double.NaN) }
        assertThrows(JcsException::class.java) { Jcs.canonicalize(str("a\uD800b")) }
        assertThrows(JcsException::class.java) { Jcs.canonicalize(JsonValue.obj("\uDC00" to JsonValue.Null)) }
    }

    @Test
    fun base64UrlAndHex() {
        val bytes = ByteArray(256) { it.toByte() }
        val enc = Base64Url.encode(bytes)
        assertFalse(enc.contains("=") || enc.contains("+") || enc.contains("/"))
        assertArrayEquals(bytes, Base64Url.decode(enc))
        assertNull(Base64Url.decode("ab+c"))
        assertNull(Base64Url.decode("abc="))
        assertNull(Base64Url.decode("abcde"))
        assertArrayEquals(bytes, Hex.decode(Hex.encode(bytes)))
        assertNull(Hex.decode("AB"))
        assertNull(Hex.decode("abc"))
        assertEquals(RelayAuth.EMPTY_BODY_SHA256, Digest.sha256Hex(ByteArray(0)))
        assertTrue(timingSafeEqual("abc", "abc"))
        assertFalse(timingSafeEqual("abc", "abd"))
        assertFalse(timingSafeEqual("abc", "abcd"))
    }

    @Test
    fun timestamps() {
        assertEquals(0L, Timestamp.parse("1970-01-01T00:00:00.000Z"))
        assertEquals(1_793_901_849_123L, Timestamp.parse("2026-11-05T18:04:09.123Z"))
        assertEquals("2026-11-05T18:04:09.123Z", Timestamp.format(1_793_901_849_123L))
        assertEquals("2024-02-29T23:59:59.999Z", Timestamp.parse("2024-02-29T23:59:59.999Z")?.let { Timestamp.format(it) })
        for (bad in listOf(
            "2026-02-29T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-11-05T24:00:00.000Z", "2026-11-05T23:59:60.000Z",
            "2026-11-05T18:04:09Z", "2026-11-05T18:04:09.123+00:00", "2026-11-05 18:04:09.123Z", "2026-11-05T18:04:09.123z",
        )) {
            assertNull(Timestamp.parse(bad), bad)
        }
        // round trip across a range of instants
        var ms = -62_135_596_800_000L // 0001-01-01
        while (ms < 253_402_300_799_000L) { // 9999-12-31
            assertEquals(ms, Timestamp.parse(Timestamp.format(ms)))
            ms += 86_400_000L * 997 + 12_345
        }
    }

    @Test
    fun ecmaScriptKeyOrder() {
        val o = JsonParser.parse("{\"b\":1,\"10\":2,\"a\":3,\"2\":4,\"01\":5,\"4294967295\":6,\"4294967294\":7}").objectValue!!
        assertEquals(listOf("2", "10", "4294967294", "b", "a", "01", "4294967295"), o.ecmaScriptKeyOrder)
    }
}
