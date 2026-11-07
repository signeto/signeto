// Byte encodings used on the wire: base64url without padding, lowercase hex, SHA-256.
// Mirrors `@signeto/protocol` src/encoding.ts.
import CryptoKit
import Foundation

public enum Base64URL {
    /// base64url without padding (RFC 4648 §5).
    public static func encode<D: DataProtocol>(_ bytes: D) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes base64url with or without padding characters absent. Rejects any character outside
    /// `[A-Za-z0-9_-]` (the TS decoder does the same) and lengths that cannot be base64.
    public static func decode(_ s: String) -> Data? {
        for u in s.utf8 {
            let ok = (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A) || (u >= 0x30 && u <= 0x39) || u == 0x2D || u == 0x5F
            if !ok { return nil }
        }
        if s.utf8.count % 4 == 1 { return nil }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.utf8.count % 4 != 0 { b64.append("=") }
        return Data(base64Encoded: b64)
    }
}

public enum Hex {
    private static let digits = Array("0123456789abcdef".utf8)

    /// Lowercase hex.
    public static func encode<D: DataProtocol>(_ bytes: D) -> String {
        var out = [UInt8]()
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Lowercase hex only, even length.
    public static func decode(_ s: String) -> Data? {
        let u = Array(s.utf8)
        guard u.count % 2 == 0 else { return nil }
        var out = Data(capacity: u.count / 2)
        func nib(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        var i = 0
        while i < u.count {
            guard let hi = nib(u[i]), let lo = nib(u[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }
}

public enum Digest {
    public static func sha256<D: DataProtocol>(_ bytes: D) -> Data { Data(SHA256.hash(data: Data(bytes))) }
    public static func sha256(_ s: String) -> Data { sha256(Data(s.utf8)) }
    /// Lowercase hex SHA-256 of the UTF-8 bytes of `s`.
    public static func sha256Hex(_ s: String) -> String { Hex.encode(sha256(s)) }
    public static func sha256Hex<D: DataProtocol>(_ bytes: D) -> String { Hex.encode(sha256(bytes)) }
}

/// Exact string comparison by UTF-8 code units. Swift's `==` on `String` uses Unicode canonical
/// equivalence ("é" == "e\u{301}"), which is wrong for protocol identifiers and hashes.
@inline(__always)
public func exactlyEqual(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }

/// Constant-time comparison of two strings' UTF-8 bytes (length leaks, content does not).
public func timingSafeEqual(_ a: String, _ b: String) -> Bool {
    let x = Array(a.utf8), y = Array(b.utf8)
    guard x.count == y.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<x.count { diff |= x[i] ^ y[i] }
    return diff == 0
}

/// Character-class checks used instead of regular expressions (ICU's `$` also matches before a
/// trailing newline, which JS's does not).
enum Chars {
    static func isBase64URL(_ u: UInt8) -> Bool {
        (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A) || (u >= 0x30 && u <= 0x39) || u == 0x2D || u == 0x5F
    }
    static func isLowerHex(_ u: UInt8) -> Bool { (u >= 0x30 && u <= 0x39) || (u >= 0x61 && u <= 0x66) }
    static func isDigit(_ u: UInt8) -> Bool { u >= 0x30 && u <= 0x39 }

    /// `^[A-Za-z0-9_-]{n}$`
    static func base64URL(_ s: String, count n: Int) -> Bool {
        let u = Array(s.utf8)
        return u.count == n && u.allSatisfy(isBase64URL)
    }
    /// `^[0-9a-f]{64}$`
    static func hex64(_ s: String) -> Bool {
        let u = Array(s.utf8)
        return u.count == 64 && u.allSatisfy(isLowerHex)
    }
    /// `^<prefix>[A-Za-z0-9_-]{43}$`
    static func prefixedId(_ s: String, prefix: String) -> Bool {
        guard s.hasPrefix(prefix) else { return false }
        let rest = Array(s.utf8.dropFirst(prefix.utf8.count))
        return rest.count == 43 && rest.allSatisfy(isBase64URL)
    }
    /// `^(0|[1-9][0-9]*)$` applied to a byte slice.
    static func isCanonicalUInt<C: Collection>(_ u: C) -> Bool where C.Element == UInt8 {
        guard let f = u.first, u.allSatisfy(isDigit) else { return false }
        return f != 0x30 || u.count == 1
    }
}
