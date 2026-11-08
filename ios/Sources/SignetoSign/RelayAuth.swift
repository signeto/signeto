// docs/protocol.md §7.1: request authentication to a relay.
//   Authorization: Signeto-Device <device_id>.<ts>.<sig>
// `sig` is base64url (86 chars) of the device key's signature over the UTF-8 JCS of
// `{body_sha256, method, path, ts}`. Mirrors src/relay-auth.ts.
import Foundation

public enum RelayAuthScheme: String, Sendable, CaseIterable {
    case gateway = "Signeto-Gateway"
    case device = "Signeto-Device"
}

public enum RelayAuthError: String, Error, Equatable, Sendable {
    case authMalformed = "auth_malformed"
    case schemeNotAllowed = "scheme_not_allowed"
    case keyMismatch = "key_mismatch"
    case clockSkew = "clock_skew"
    case invalidSignature = "invalid_signature"
}

public struct ParsedRelayAuth: Equatable, Sendable {
    public let scheme: RelayAuthScheme
    public let keyId: String
    public let ts: String
    public let signature: String
}

public enum RelayAuth {
    public static let windowMs: Int64 = Timestamp.clockSkewMs
    /// SHA-256 of the empty string.
    public static let emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    /// Hex SHA-256 of the raw body bytes as sent; nil and empty both hash the empty string.
    public static func bodySHA256(_ body: Data?) -> String {
        guard let body else { return emptyBodySHA256 }
        return Digest.sha256Hex(body)
    }

    /// JCS of `{body_sha256, method, path, ts}`. Throws `auth_malformed` on a malformed field.
    public static func signingInput(method: String, path: String, ts: String, bodySHA256: String) throws -> String {
        let m = Array(method.utf8)
        guard !m.isEmpty, m.allSatisfy({ $0 >= 0x41 && $0 <= 0x5A }) else { throw RelayAuthError.authMalformed }
        // origin-form request-target: starts with "/", no whitespace, no fragment
        guard path.hasPrefix("/"), !path.unicodeScalars.contains(where: { $0 == "#" || $0.properties.isWhitespace || isJSWhitespace($0) }) else { throw RelayAuthError.authMalformed }
        guard Timestamp.parse(ts) != nil else { throw RelayAuthError.authMalformed }
        guard Chars.hex64(bodySHA256) else { throw RelayAuthError.authMalformed }
        return try JCS.canonicalize(["body_sha256": .string(bodySHA256), "method": .string(method), "path": .string(path), "ts": .string(ts)])
    }

    /// JS `\s`: WhiteSpace and LineTerminator code points.
    static func isJSWhitespace(_ u: Unicode.Scalar) -> Bool {
        switch u.value {
        case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF: return true
        default: return false
        }
    }

    /// The `Authorization` header value for one request, signed with `signer` (device scheme). For software
    /// keys; a key that needs a biometric per signature uses the relay's device session instead (§7.1).
    /// `path` is the request-target exactly as it will be sent (base path + path + query).
    public static func deviceHeader(method: String, path: String, body: Data?, ts: String, signer: DeviceSigner) throws -> String {
        let si = try signingInput(method: method, path: path, ts: ts, bodySHA256: bodySHA256(body))
        let sig = try signer.signBase64URL(si)
        return "\(RelayAuthScheme.device.rawValue) \(signer.deviceId).\(ts).\(sig)"
    }

    public static func parseHeader(_ value: String?) -> Result<ParsedRelayAuth, RelayAuthError> {
        guard let value else { return .failure(.authMalformed) }
        // ^([A-Za-z-]+) +([^\s]+)$
        let scalars = Array(value.unicodeScalars)
        var i = 0
        while i < scalars.count, (scalars[i].isASCII && (scalars[i].properties.isAlphabetic || scalars[i] == "-")) { i += 1 }
        guard i > 0, i < scalars.count, scalars[i] == " " else { return .failure(.authMalformed) }
        let schemeName = String(String.UnicodeScalarView(scalars[0..<i]))
        while i < scalars.count, scalars[i] == " " { i += 1 }
        let credScalars = scalars[i...]
        guard !credScalars.isEmpty, !credScalars.contains(where: { isJSWhitespace($0) || $0.properties.isWhitespace }) else { return .failure(.authMalformed) }
        guard let scheme = RelayAuthScheme.allCases.first(where: { $0.rawValue.lowercased() == schemeName.lowercased() }) else { return .failure(.authMalformed) }
        let cred = String(String.UnicodeScalarView(credScalars))
        guard let first = cred.firstIndex(of: "."), let last = cred.lastIndex(of: "."), first != cred.startIndex, first != last else { return .failure(.authMalformed) }
        let keyId = String(cred[..<first])
        let ts = String(cred[cred.index(after: first)..<last])
        let sig = String(cred[cred.index(after: last)...])
        let idOK = scheme == .gateway ? Identifiers.isGatewayId(keyId) : Identifiers.isDeviceId(keyId)
        guard idOK, Timestamp.parse(ts) != nil, Chars.base64URL(sig, count: 86) else { return .failure(.authMalformed) }
        return .success(ParsedRelayAuth(scheme: scheme, keyId: keyId, ts: ts, signature: sig))
    }

    /// Relay-side check, in §7.1 order (shape, scheme, key id = thumbprint, ±60 s, signature).
    /// Included for conformance tests; a device never needs it.
    public static func verify(header: String?, method: String, path: String, body: Data?, publicKey: PublicJWK, nowMs: Int64, schemes: [RelayAuthScheme]? = nil) -> Result<ParsedRelayAuth, RelayAuthError> {
        let p: ParsedRelayAuth
        switch parseHeader(header) {
        case .failure(let e): return .failure(e)
        case .success(let x): p = x
        }
        if let schemes, !schemes.contains(p.scheme) { return .failure(.schemeNotAllowed) }
        let expected = p.scheme == .gateway ? publicKey.gatewayId : publicKey.deviceId
        guard expected == p.keyId else { return .failure(.keyMismatch) }
        guard let ts = Timestamp.parse(p.ts), abs(nowMs - ts) <= windowMs else { return .failure(.clockSkew) }
        guard let si = try? signingInput(method: method, path: path, ts: p.ts, bodySHA256: bodySHA256(body)) else { return .failure(.authMalformed) }
        guard publicKey.verify(base64URLSignature: p.signature, over: si) else { return .failure(.invalidSignature) }
        return .success(p)
    }
}
