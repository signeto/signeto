// A JSON value model and a strict RFC 8259 parser with the semantics of ECMAScript `JSON.parse`,
// which is what `@signeto/protocol` uses on the receiving side:
//   - numbers are IEEE 754 doubles;
//   - a duplicate member name keeps its first position and takes the last value;
//   - member names are compared by exact code units (never Unicode-normalised).
// Differences, both fail-closed: lone UTF-16 surrogates in `\u` escapes and numbers that overflow to
// infinity are parse errors here (RFC 8785 §3.2.2.2 / I-JSON forbid them; JS would accept the first and
// fail later on the second).
import Foundation

public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object(JSONObject)

    public var stringValue: String? { if case .string(let s) = self { return s } else { return nil } }
    public var numberValue: Double? { if case .number(let n) = self { return n } else { return nil } }
    public var boolValue: Bool? { if case .bool(let b) = self { return b } else { return nil } }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a } else { return nil } }
    public var objectValue: JSONObject? { if case .object(let o) = self { return o } else { return nil } }
    public var isNull: Bool { if case .null = self { return true } else { return false } }

    /// An integer-valued number, as `Number.isInteger` would accept it, within the safe range.
    public var intValue: Int? {
        guard case .number(let d) = self, d.isFinite, d.rounded(.towardZero) == d, abs(d) <= 9_007_199_254_740_991 else { return nil }
        return Int(d)
    }

    public subscript(key: String) -> JSONValue? { objectValue?[key] }

    public static func == (a: JSONValue, b: JSONValue) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case (.bool(let x), .bool(let y)): return x == y
        case (.number(let x), .number(let y)): return x == y
        case (.string(let x), .string(let y)): return exactlyEqual(x, y)
        case (.array(let x), .array(let y)): return x == y
        case (.object(let x), .object(let y)): return x == y
        default: return false
        }
    }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral, ExpressibleByNilLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        var o = JSONObject()
        for (k, v) in elements { o[k] = v }
        self = .object(o)
    }
    public init(nilLiteral: ()) { self = .null }
}

/// Exact-code-unit key for hashing (Swift `String` hashing is normalisation-insensitive).
struct ExactKey: Hashable {
    let bytes: [UInt8]
    init(_ s: String) { bytes = Array(s.utf8) }
}

/// An ordered JSON object. Member order is insertion order (source order when parsed).
public struct JSONObject: Equatable, Sendable {
    public private(set) var entries: [(key: String, value: JSONValue)] = []
    private var index: [ExactKey: Int] = [:]

    public init() {}
    public init(_ pairs: [(String, JSONValue)]) { for (k, v) in pairs { self[k] = v } }

    public var keys: [String] { entries.map(\.key) }
    public var count: Int { entries.count }
    public var isEmpty: Bool { entries.isEmpty }

    public func contains(_ key: String) -> Bool { index[ExactKey(key)] != nil }

    public subscript(key: String) -> JSONValue? {
        get { index[ExactKey(key)].map { entries[$0].value } }
        set {
            let k = ExactKey(key)
            if let i = index[k] {
                if let v = newValue {
                    entries[i].value = v
                } else {
                    entries.remove(at: i)
                    index = [:]
                    for (j, e) in entries.enumerated() { index[ExactKey(e.key)] = j }
                }
            } else if let v = newValue {
                index[k] = entries.count
                entries.append((key, v))
            }
        }
    }

    /// Keys in ECMAScript `Object.keys` order: canonical array-index keys ("0", "1", … up to 2^32 − 2)
    /// first in ascending numeric order, then every other key in insertion order. The TS renderer walks
    /// `args_resolved` in this order, so the first unreferenced key and the `hidden` list depend on it.
    public var ecmaScriptKeyOrder: [String] {
        var indices: [(UInt64, String)] = []
        var others: [String] = []
        for k in keys {
            let u = Array(k.utf8)
            if Chars.isCanonicalUInt(u), u.count <= 10, let n = UInt64(k), n <= 4_294_967_294 {
                indices.append((n, k))
            } else {
                others.append(k)
            }
        }
        return indices.sorted { $0.0 < $1.0 }.map(\.1) + others
    }

    public static func == (a: JSONObject, b: JSONObject) -> Bool {
        guard a.entries.count == b.entries.count else { return false }
        for (k, v) in a.entries {
            guard let w = b[k], w == v else { return false }
        }
        return true
    }
}

public struct JSONParseError: Error, CustomStringConvertible, Equatable {
    public let message: String
    public let offset: Int
    public var description: String { "JSON parse error at byte \(offset): \(message)" }
}

public enum JSONParser {
    /// Parses a complete JSON text (whitespace allowed around the value, nothing else).
    public static func parse(_ text: String) throws -> JSONValue {
        try parse(Array(text.utf8))
    }

    public static func parse<D: DataProtocol>(data: D) throws -> JSONValue {
        let bytes = Array(data)
        // Data from the network must be valid UTF-8; String(decoding:) would silently repair it.
        guard validUTF8(bytes) != nil else { throw JSONParseError(message: "invalid UTF-8", offset: 0) }
        return try parse(bytes)
    }

    static func parse(_ bytes: [UInt8]) throws -> JSONValue {
        var p = Parser(b: bytes)
        p.skipWS()
        let v = try p.value(depth: 0)
        p.skipWS()
        guard p.i == bytes.count else { throw p.error("unexpected trailing characters") }
        return v
    }

    private struct Parser {
        let b: [UInt8]
        var i = 0
        static let maxDepth = 512

        func error(_ m: String) -> JSONParseError { JSONParseError(message: m, offset: i) }

        mutating func skipWS() {
            while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth < Self.maxDepth else { throw error("nesting too deep") }
            guard i < b.count else { throw error("unexpected end") }
            switch b[i] {
            case 0x7B: return try object(depth: depth)
            case 0x5B: return try array(depth: depth)
            case 0x22: return .string(try string())
            case 0x74: try literal("true"); return .bool(true)
            case 0x66: try literal("false"); return .bool(false)
            case 0x6E: try literal("null"); return .null
            case 0x2D, 0x30...0x39: return .number(try number())
            default: throw error("unexpected character")
            }
        }

        mutating func literal(_ s: StaticString) throws {
            let u = Array(UnsafeBufferPointer(start: s.utf8Start, count: s.utf8CodeUnitCount))
            guard i + u.count <= b.count, Array(b[i..<(i + u.count)]) == u else { throw error("invalid literal") }
            i += u.count
        }

        mutating func object(depth: Int) throws -> JSONValue {
            i += 1
            var o = JSONObject()
            skipWS()
            if i < b.count, b[i] == 0x7D { i += 1; return .object(o) }
            while true {
                skipWS()
                guard i < b.count, b[i] == 0x22 else { throw error("expected member name") }
                let k = try string()
                skipWS()
                guard i < b.count, b[i] == 0x3A else { throw error("expected ':'") }
                i += 1
                skipWS()
                let v = try value(depth: depth + 1)
                o[k] = v // duplicate: first position, last value (JSON.parse semantics)
                skipWS()
                guard i < b.count else { throw error("unexpected end in object") }
                if b[i] == 0x2C { i += 1; continue }
                if b[i] == 0x7D { i += 1; return .object(o) }
                throw error("expected ',' or '}'")
            }
        }

        mutating func array(depth: Int) throws -> JSONValue {
            i += 1
            var a: [JSONValue] = []
            skipWS()
            if i < b.count, b[i] == 0x5D { i += 1; return .array(a) }
            while true {
                skipWS()
                a.append(try value(depth: depth + 1))
                skipWS()
                guard i < b.count else { throw error("unexpected end in array") }
                if b[i] == 0x2C { i += 1; continue }
                if b[i] == 0x5D { i += 1; return .array(a) }
                throw error("expected ',' or ']'")
            }
        }

        mutating func hex4() throws -> UInt16 {
            guard i + 4 <= b.count else { throw error("short \\u escape") }
            var v: UInt16 = 0
            for _ in 0..<4 {
                let c = b[i]
                let d: UInt16
                switch c {
                case 0x30...0x39: d = UInt16(c - 0x30)
                case 0x41...0x46: d = UInt16(c - 0x41 + 10)
                case 0x61...0x66: d = UInt16(c - 0x61 + 10)
                default: throw error("bad hex digit in \\u escape")
                }
                v = v << 4 | d
                i += 1
            }
            return v
        }

        mutating func string() throws -> String {
            i += 1 // opening quote
            var out = [UInt8]()
            while true {
                guard i < b.count else { throw error("unterminated string") }
                let c = b[i]
                if c == 0x22 { i += 1; break }
                if c < 0x20 { throw error("control character in string") }
                if c != 0x5C { out.append(c); i += 1; continue }
                i += 1
                guard i < b.count else { throw error("unterminated escape") }
                let e = b[i]
                i += 1
                switch e {
                case 0x22: out.append(0x22)
                case 0x5C: out.append(0x5C)
                case 0x2F: out.append(0x2F)
                case 0x62: out.append(0x08)
                case 0x66: out.append(0x0C)
                case 0x6E: out.append(0x0A)
                case 0x72: out.append(0x0D)
                case 0x74: out.append(0x09)
                case 0x75:
                    let hi = try hex4()
                    var scalar: UInt32
                    if hi >= 0xD800 && hi <= 0xDBFF {
                        guard i + 6 <= b.count, b[i] == 0x5C, b[i + 1] == 0x75 else { throw error("lone surrogate") }
                        i += 2
                        let lo = try hex4()
                        guard lo >= 0xDC00 && lo <= 0xDFFF else { throw error("lone surrogate") }
                        scalar = 0x10000 + ((UInt32(hi) - 0xD800) << 10) + (UInt32(lo) - 0xDC00)
                    } else if hi >= 0xDC00 && hi <= 0xDFFF {
                        throw error("lone surrogate")
                    } else {
                        scalar = UInt32(hi)
                    }
                    guard let us = Unicode.Scalar(scalar) else { throw error("invalid scalar") }
                    out.append(contentsOf: Array(String(Character(us)).utf8))
                default:
                    throw error("invalid escape")
                }
            }
            guard let s = validUTF8(out) else { throw error("invalid UTF-8 in string") }
            return s
        }

        mutating func number() throws -> Double {
            let start = i
            if b[i] == 0x2D { i += 1 }
            guard i < b.count, Chars.isDigit(b[i]) else { throw error("bad number") }
            if b[i] == 0x30 {
                i += 1
            } else {
                while i < b.count, Chars.isDigit(b[i]) { i += 1 }
            }
            if i < b.count, b[i] == 0x2E {
                i += 1
                guard i < b.count, Chars.isDigit(b[i]) else { throw error("bad fraction") }
                while i < b.count, Chars.isDigit(b[i]) { i += 1 }
            }
            if i < b.count, b[i] == 0x65 || b[i] == 0x45 {
                i += 1
                if i < b.count, b[i] == 0x2B || b[i] == 0x2D { i += 1 }
                guard i < b.count, Chars.isDigit(b[i]) else { throw error("bad exponent") }
                while i < b.count, Chars.isDigit(b[i]) { i += 1 }
            }
            let text = String(decoding: b[start..<i], as: UTF8.self)
            guard let d = Double(text), d.isFinite else { throw error("number out of range") }
            return d
        }
    }
}

/// Strict UTF-8 validation (no BOM stripping, no repair), then decode.
func validUTF8(_ bytes: [UInt8]) -> String? {
    var it = bytes.makeIterator()
    var dec = UTF8()
    loop: while true {
        switch dec.decode(&it) {
        case .scalarValue: continue
        case .emptyInput: break loop
        case .error: return nil
        }
    }
    return String(decoding: bytes, as: UTF8.self)
}
