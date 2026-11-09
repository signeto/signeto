// docs/protocol.md §5.1: public keys as JWK, RFC 7638 thumbprints, gw_/dev_ identifiers, human
// fingerprints; and signature verification for the two algorithms the protocol allows (ADR-0002).
// Mirrors src/ids.ts and src/signing.ts.
import CryptoKit
import Foundation

public enum SignatureAlgorithm: String, Codable, Sendable {
    case es256 = "ES256"
    case ed25519 = "Ed25519"
}

/// A public JWK, reduced to the RFC 7638 required members.
public enum PublicJWK: Equatable, Hashable, Sendable {
    /// `{"kty":"EC","crv":"P-256","x":…,"y":…}`
    case p256(x: String, y: String)
    /// `{"kty":"OKP","crv":"Ed25519","x":…}`
    case ed25519(x: String)

    public var algorithm: SignatureAlgorithm {
        switch self {
        case .p256: return .es256
        case .ed25519: return .ed25519
        }
    }

    /// The required members as a JSON object (what is serialised on the wire and thumbprinted).
    public var json: JSONValue {
        switch self {
        case .p256(let x, let y): return ["kty": "EC", "crv": "P-256", "x": .string(x), "y": .string(y)]
        case .ed25519(let x): return ["kty": "OKP", "crv": "Ed25519", "x": .string(x)]
        }
    }

    /// Strict parse of a public JWK: exactly the required members, 32-byte coordinates.
    /// `allowExtraMembers` accepts (and drops) other members except a private `d`.
    public init?(json: JSONValue, allowExtraMembers: Bool = false) {
        guard let o = json.objectValue, !o.contains("d"), let kty = o["kty"]?.stringValue, let crv = o["crv"]?.stringValue, let x = o["x"]?.stringValue else { return nil }
        func coord(_ s: String) -> Bool { Chars.base64URL(s, count: 43) && Base64URL.decode(s)?.count == 32 }
        if kty == "EC", crv == "P-256", let y = o["y"]?.stringValue {
            guard coord(x), coord(y), allowExtraMembers || o.count == 4 else { return nil }
            self = .p256(x: x, y: y)
        } else if kty == "OKP", crv == "Ed25519", o["y"] == nil {
            guard coord(x), allowExtraMembers || o.count == 3 else { return nil }
            self = .ed25519(x: x)
        } else {
            return nil
        }
    }

    public init(p256 key: P256.Signing.PublicKey) {
        let raw = key.rawRepresentation // x || y
        self = .p256(x: Base64URL.encode(raw.prefix(32)), y: Base64URL.encode(raw.suffix(32)))
    }

    public init(ed25519 key: Curve25519.Signing.PublicKey) {
        self = .ed25519(x: Base64URL.encode(key.rawRepresentation))
    }

    /// RFC 7638 thumbprint: SHA-256 over the JCS of the required members.
    public var thumbprint: Data {
        // The required members are ASCII strings: canonicalisation cannot fail.
        Digest.sha256(try! JCS.canonicalize(json))
    }

    public var gatewayId: String { "gw_" + Base64URL.encode(thumbprint) }
    public var deviceId: String { "dev_" + Base64URL.encode(thumbprint) }

    /// First 16 hex characters of the thumbprint in groups of four: `3fa9 1c02 b77e d410`.
    public var fingerprint: String {
        let h = Array(Hex.encode(thumbprint).prefix(16))
        return stride(from: 0, to: 16, by: 4).map { String(h[$0..<($0 + 4)]) }.joined(separator: " ")
    }

    /// Verify `signature` over `data` in this key's algorithm. ES256: ECDSA P-256 over SHA-256(data),
    /// raw r||s. Ed25519: PureEdDSA over data. Any malformed input is `false`, never a throw.
    public func verify(signature: Data, over data: Data) -> Bool {
        guard signature.count == 64 else { return false }
        switch self {
        case .p256(let x, let y):
            guard let xb = Base64URL.decode(x), let yb = Base64URL.decode(y), xb.count == 32, yb.count == 32,
                  let pk = try? P256.Signing.PublicKey(rawRepresentation: xb + yb),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return pk.isValidSignature(sig, for: data)
        case .ed25519(let x):
            // §5.1 (SIG-92 N1): nothing verifies under a small-order key.
            guard let xb = Base64URL.decode(x), xb.count == 32, !Ed25519Keys.isSmallOrder(xb), let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: xb) else { return false }
            return pk.isValidSignature(signature, for: data)
        }
    }

    /// §5.1: an Ed25519 key that is a small-order point (or not 32 bytes), refused wherever a key is pinned or
    /// parsed. EC P-256 keys are never weak in this sense.
    public var isWeak: Bool {
        guard case .ed25519(let x) = self else { return false }
        guard let xb = Base64URL.decode(x) else { return true }
        return Ed25519Keys.isSmallOrder(xb)
    }

    /// Verify a base64url signature over the UTF-8 bytes of `input`.
    public func verify(base64URLSignature sig: String, over input: String) -> Bool {
        guard let s = Base64URL.decode(sig) else { return false }
        return verify(signature: s, over: Data(input.utf8))
    }
}

extension PublicJWK: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let d = try c.decode([String: String].self)
        var o = JSONObject()
        for k in d.keys.sorted() { o[k] = .string(d[k]!) }
        guard let k = PublicJWK(json: .object(o)) else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "not an EC P-256 or OKP Ed25519 public JWK") }
        self = k
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .p256(let x, let y): try c.encode(["kty": "EC", "crv": "P-256", "x": x, "y": y])
        case .ed25519(let x): try c.encode(["kty": "OKP", "crv": "Ed25519", "x": x])
        }
    }
}

public enum Identifiers {
    /// `^gw_[A-Za-z0-9_-]{43}$`
    public static func isGatewayId(_ s: String) -> Bool { Chars.prefixedId(s, prefix: "gw_") }
    /// `^dev_[A-Za-z0-9_-]{43}$`
    public static func isDeviceId(_ s: String) -> Bool { Chars.prefixedId(s, prefix: "dev_") }
    /// `^act_[0-9A-HJKMNP-TV-Z]{26}$` (ULID, Crockford base32)
    public static func isActionId(_ s: String) -> Bool {
        guard s.hasPrefix("act_") else { return false }
        let rest = Array(s.utf8.dropFirst(4))
        let crockford = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)
        return rest.count == 26 && rest.allSatisfy { crockford.contains($0) }
    }
    /// `^[A-Za-z0-9_-]{22}$`
    public static func isNonce(_ s: String) -> Bool { Chars.base64URL(s, count: 22) }
}

/// protocol.md §5.1 (SIG-92 N1): small-order Ed25519 public keys. Such a key (the identity, say) makes the signature
/// R = identity, S = 0 valid for every message. The list is libsodium's: the 8-torsion points by y coordinate,
/// including the non-canonical y = p and p + 1, compared with the sign bit ignored. Mirrors `isSmallOrderEd25519` in
/// `@signeto/protocol`; `vectors/weak-keys/` fixes both.
public enum Ed25519Keys {
    static let smallOrder: [[UInt8]] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ].map { h in stride(from: 0, to: 64, by: 2).map { i in UInt8(h[h.index(h.startIndex, offsetBy: i)..<h.index(h.startIndex, offsetBy: i + 2)], radix: 16)! } }

    /// True when `raw` (the 32-byte encoding) is a small-order point. Any other length: true.
    public static func isSmallOrder(_ raw: Data) -> Bool {
        let b = [UInt8](raw)
        guard b.count == 32 else { return true }
        return smallOrder.contains { blocked in
            var diff: UInt8 = 0
            for i in 0..<31 { diff |= b[i] ^ blocked[i] }
            diff |= (b[31] & 0x7F) ^ blocked[31]
            return diff == 0
        }
    }
}
