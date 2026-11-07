// RFC 8785 JSON Canonicalization Scheme (docs/protocol.md §2.3), byte-identical to
// `@signeto/protocol` src/jcs.ts:
//   - members sorted by UTF-16 code units of their names;
//   - numbers per ECMAScript Number.prototype.toString (shortest round-trip digits);
//   - strings escaped as JSON.stringify does (RFC 8785 §3.2.2.2);
//   - no whitespace.
import Foundation

public enum JCSError: Error, Equatable {
    case nonFiniteNumber
}

public enum JCS {
    /// The JCS text of a value.
    public static func canonicalize(_ value: JSONValue) throws -> String {
        var out = ""
        try write(value, into: &out)
        return out
    }

    /// The JCS bytes (UTF-8) of a value.
    public static func canonicalData(_ value: JSONValue) throws -> Data {
        Data(try canonicalize(value).utf8)
    }

    /// True when `text` is already the JCS serialization of the value it parses to.
    public static func isCanonical(_ text: String) -> Bool {
        guard let v = try? JSONParser.parse(text), let c = try? canonicalize(v) else { return false }
        return exactlyEqual(c, text)
    }

    static func write(_ v: JSONValue, into out: inout String) throws {
        switch v {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .number(let d): out += try formatNumber(d)
        case .string(let s): writeString(s, into: &out)
        case .array(let a):
            out += "["
            for (i, e) in a.enumerated() {
                if i > 0 { out += "," }
                try write(e, into: &out)
            }
            out += "]"
        case .object(let o):
            out += "{"
            let sorted = o.entries.sorted { lessUTF16($0.key, $1.key) }
            for (i, e) in sorted.enumerated() {
                if i > 0 { out += "," }
                writeString(e.key, into: &out)
                out += ":"
                try write(e.value, into: &out)
            }
            out += "}"
        }
    }

    /// Member order: UTF-16 code unit comparison (what JS `Array.prototype.sort` does on strings).
    public static func lessUTF16(_ a: String, _ b: String) -> Bool {
        a.utf16.lexicographicallyPrecedes(b.utf16)
    }

    private static let hexDigits = Array("0123456789abcdef")

    /// JSON.stringify string escaping: `"` and `\` escaped, \b \f \n \r \t short forms, every other
    /// control character below U+0020 as lowercase `\u00xx`, everything else verbatim.
    public static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for u in s.unicodeScalars {
            switch u.value {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x0C: out += "\\f"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x00..<0x20:
                out += "\\u00"
                out.append(hexDigits[Int(u.value >> 4)])
                out.append(hexDigits[Int(u.value & 0xF)])
            default:
                out.unicodeScalars.append(u)
            }
        }
        out += "\""
    }

    /// ECMAScript Number::toString(x) for finite x (ECMA-262 §6.1.6.1.20), as JSON.stringify emits it.
    public static func formatNumber(_ x: Double) throws -> String {
        guard x.isFinite else { throw JCSError.nonFiniteNumber }
        if x == 0 { return "0" } // +0 and -0
        if x < 0 { return "-" + (try formatNumber(-x)) }

        // Shortest round-trip decimal digits. Swift's description is shortest-round-trip (and picks the
        // closest candidate on ties, as ECMAScript requires); only its layout differs, so re-layout it.
        let desc = "\(x)"
        var mantissa = Substring(desc)
        var exp = 0
        if let e = desc.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mantissa = desc[..<e]
            exp = Int(desc[desc.index(after: e)...])!
        }
        var digits: [Character]
        var pointPos: Int
        if let dot = mantissa.firstIndex(of: ".") {
            let intPart = mantissa[..<dot]
            let fracPart = mantissa[mantissa.index(after: dot)...]
            digits = Array(intPart) + Array(fracPart)
            pointPos = intPart.count
        } else {
            digits = Array(mantissa)
            pointPos = digits.count
        }
        while let f = digits.first, f == "0" { digits.removeFirst(); pointPos -= 1 }
        while let l = digits.last, l == "0" { digits.removeLast() }
        // value = 0.d1d2…dk × 10^n, i.e. s × 10^(n−k)
        let k = digits.count
        let n = pointPos + exp
        let s = String(digits)

        if k <= n && n <= 21 {
            return s + String(repeating: "0", count: n - k)
        }
        if 0 < n && n <= 21 {
            return String(digits[0..<n]) + "." + String(digits[n...])
        }
        if -6 < n && n <= 0 {
            return "0." + String(repeating: "0", count: -n) + s
        }
        let e = n - 1
        let expPart = "e" + (e >= 0 ? "+" : "-") + String(abs(e))
        if k == 1 { return s + expPart }
        return String(digits[0]) + "." + String(digits[1...]) + expPart
    }
}
