import Foundation
import XCTest
@testable import SignetoSign

final class JCSTests: XCTestCase {
    /// Fixtures/numbers.json: ~3,500 doubles → ECMAScript Number::toString, as produced by the TS canonicalize.
    func testNumberFormattingMatchesECMAScript() throws {
        let f = try fixture("numbers.json")
        let cases = f["cases"]!.arrayValue!
        XCTAssertGreaterThan(cases.count, 3000)
        var failures = 0
        for c in cases {
            let bits = UInt64(c["bits"]!.s, radix: 16)!
            let x = Double(bitPattern: bits)
            let got = try JCS.formatNumber(x)
            if got != c["text"]!.s {
                failures += 1
                if failures < 10 { XCTFail("\(x) [\(c["bits"]!.s)]: got \(got), want \(c["text"]!.s)") }
            }
            // and the text parses back to the same double
            XCTAssertEqual(try JSONParser.parse(got), .number(x == 0 ? 0 : x))
        }
        XCTAssertEqual(failures, 0)
    }

    func testStringEscapingMatchesJSONStringify() throws {
        let f = try fixture("strings.json")
        for c in f["cases"]!.arrayValue! {
            XCTAssertEqual(try JCS.canonicalize(c["input"]!), c["jcs"]!.s, "input \(Array(c["input"]!.s.unicodeScalars).map { String($0.value, radix: 16) })")
        }
    }

    func testObjectsSortByUTF16CodeUnits() throws {
        let f = try fixture("objects.json")
        for c in f["cases"]!.arrayValue! {
            let parsed = try JSONParser.parse(c["input"]!.s)
            let out = try JCS.canonicalize(parsed)
            XCTAssertEqual(out, c["jcs"]!.s)
            XCTAssertTrue(exactlyEqual(out, c["jcs"]!.s))
            XCTAssertTrue(JCS.isCanonical(out))
            XCTAssertFalse(JCS.isCanonical(c["input"]!.s))
        }
    }

    func testCanonicalEquivalentKeysStayDistinct() throws {
        // "é" (U+00E9) and "e\u{301}" are canonically equivalent in Swift but distinct JSON member names.
        let v = try JSONParser.parse("{\"\u{e9}\":1,\"e\u{301}\":2}")
        XCTAssertEqual(v.objectValue?.count, 2)
        XCTAssertEqual(try JCS.canonicalize(v), "{\"e\u{301}\":2,\"\u{e9}\":1}")
    }

    func testDuplicateMembersKeepFirstPositionLastValue() throws {
        let v = try JSONParser.parse("{\"b\":1,\"a\":2,\"b\":3}")
        XCTAssertEqual(v.objectValue?.keys, ["b", "a"])
        XCTAssertEqual(v["b"], .number(3))
        XCTAssertFalse(JCS.isCanonical("{\"a\":2,\"b\":1,\"b\":3}"))
    }

    func testParserRejectsInvalidJSON() {
        for bad in ["", "{", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "+1", "\"\\x\"", "\"a\u{01}\"", "nul", "1e400", "\"\\ud800\"", "\"\\udc00\"", "{} x", "NaN", "[1 2]"] {
            XCTAssertThrowsError(try JSONParser.parse(bad), "should reject \(bad.debugDescription)")
        }
    }

    func testParserRejectsInvalidUTF8() {
        XCTAssertThrowsError(try JSONParser.parse(data: Data([0x22, 0xC3, 0x28, 0x22])))
        XCTAssertThrowsError(try JSONParser.parse(data: Data([0x22, 0xED, 0xA0, 0x80, 0x22]))) // encoded surrogate
    }

    func testNonFiniteNumbersThrow() {
        XCTAssertThrowsError(try JCS.formatNumber(.infinity))
        XCTAssertThrowsError(try JCS.formatNumber(.nan))
    }

    func testBase64URLAndHex() {
        let bytes = Data((0...255).map(UInt8.init))
        let enc = Base64URL.encode(bytes)
        XCTAssertFalse(enc.contains("=") || enc.contains("+") || enc.contains("/"))
        XCTAssertEqual(Base64URL.decode(enc), bytes)
        XCTAssertNil(Base64URL.decode("ab+c"))
        XCTAssertNil(Base64URL.decode("abc="))
        XCTAssertEqual(Hex.decode(Hex.encode(bytes)), bytes)
        XCTAssertNil(Hex.decode("AB"))
        XCTAssertNil(Hex.decode("abc"))
        XCTAssertEqual(RelayAuth.emptyBodySHA256, Digest.sha256Hex(Data()))
    }

    func testTimestamps() {
        XCTAssertEqual(Timestamp.parse("1970-01-01T00:00:00.000Z"), 0)
        XCTAssertEqual(Timestamp.parse("2026-11-05T18:04:09.123Z"), 1_793_901_849_123)
        XCTAssertEqual(Timestamp.format(ms: 1_793_901_849_123), "2026-11-05T18:04:09.123Z")
        XCTAssertEqual(Timestamp.parse("2024-02-29T23:59:59.999Z").map { Timestamp.format(ms: $0) }, "2024-02-29T23:59:59.999Z")
        for bad in ["2026-02-29T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-11-05T24:00:00.000Z", "2026-11-05T23:59:60.000Z", "2026-11-05T18:04:09Z", "2026-11-05T18:04:09.123+00:00", "2026-11-05 18:04:09.123Z", "2026-11-05T18:04:09.123z"] {
            XCTAssertNil(Timestamp.parse(bad), bad)
        }
        // round trip across a range of instants
        var ms: Int64 = -62_135_596_800_000 // 0001-01-01
        while ms < 253_402_300_799_000 { // 9999-12-31
            XCTAssertEqual(Timestamp.parse(Timestamp.format(ms: ms)), ms)
            ms += 86_400_000 * 997 + 12_345
        }
    }
}
