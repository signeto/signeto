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
            guard let xb = Base64URL.decode(x), xb.count == 32, let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: xb) else { return false }
            return pk.isValidSignature(signature, for: data)
        }
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
