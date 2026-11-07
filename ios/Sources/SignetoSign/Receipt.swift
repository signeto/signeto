// docs/protocol.md §4: receipts. Building and signing (device side) and standalone verification
// (§4.5 steps 1, 2, 6, 9, 10, 11, 12 and the WebAuthn procedure of §4.4). Mirrors src/receipt.ts.
import Foundation

public enum Decision: String, Codable, Sendable {
    case approve
    case deny
}

public struct WebAuthnBlock: Equatable, Codable, Sendable {
    public let authenticatorData: String
    public let clientDataJSON: String
    enum CodingKeys: String, CodingKey { case authenticatorData = "authenticator_data", clientDataJSON = "client_data_json" }
}

public struct Receipt: Equatable, Sendable {
    public var receiptVersion: String
    public var actionId: String
    public var decision: Decision
    public var reason: String?
    public var approverId: String
    public var deviceId: String
    public var alg: SignatureAlgorithm
    public var signature: String
    public var signedAt: String
    public var canonicalBytesSHA256: String
    public var webauthn: WebAuthnBlock?
    public var relayId: String?

    /// The receipt object as sent to the relay (§7.7: without `relay_id` unless the relay added it).
    public var json: JSONValue {
        var o = JSONObject()
        o["receipt_version"] = .string(receiptVersion)
        o["action_id"] = .string(actionId)
        o["decision"] = .string(decision.rawValue)
        if let reason { o["reason"] = .string(reason) }
        o["approver_id"] = .string(approverId)
        o["device_id"] = .string(deviceId)
        o["alg"] = .string(alg.rawValue)
        o["signature"] = .string(signature)
        o["signed_at"] = .string(signedAt)
        o["canonical_bytes_sha256"] = .string(canonicalBytesSHA256)
        if let w = webauthn { o["webauthn"] = ["authenticator_data": .string(w.authenticatorData), "client_data_json": .string(w.clientDataJSON)] }
        if let relayId { o["relay_id"] = .string(relayId) }
        return .object(o)
    }

    /// JCS bytes of `json`: the exact request body for `POST /v1/approvals/{id}/receipt`.
    public func body() throws -> Data { try JCS.canonicalData(json) }
}

public enum ReceiptVerifyCode: String, Error, Equatable, Sendable {
    case receiptMalformed = "receipt_malformed"
    case receiptVersionUnsupported = "receipt_version_unsupported"
    case algNotAllowed = "alg_not_allowed"
    case hashMismatch = "hash_mismatch"
    case clockSkew = "clock_skew"
    case invalidSignature = "invalid_signature"
    case webauthnType = "webauthn_type"
    case webauthnChallenge = "webauthn_challenge"
    case webauthnOrigin = "webauthn_origin"
    case webauthnRpId = "webauthn_rp_id"
    case webauthnUserFlags = "webauthn_user_flags"
}

public struct WebAuthnPolicy: Sendable {
    public var allowedOrigins: [String]
    public var rpId: String
    public var requireUserVerified: Bool
    public init(allowedOrigins: [String], rpId: String, requireUserVerified: Bool) {
        self.allowedOrigins = allowedOrigins
        self.rpId = rpId
        self.requireUserVerified = requireUserVerified
    }
}

public enum Receipts {
    public static let receiptVersion = "1.0"
    public static let receiptMajor = 1
    public static let maxReasonUTF8Bytes = 512

    /// §4.2: UTF-8 JCS of `{canonical_bytes_sha256, decision, reason?, signed_at}`; `reason` omitted when absent.
    public static func signingInput(canonicalBytesSHA256: String, decision: Decision, reason: String?, signedAt: String) -> String {
        var o = JSONObject()
        o["canonical_bytes_sha256"] = .string(canonicalBytesSHA256)
        o["decision"] = .string(decision.rawValue)
        if let reason { o["reason"] = .string(reason) }
        o["signed_at"] = .string(signedAt)
        return try! JCS.canonicalize(.object(o)) // strings only: cannot fail
    }

    /// §4.4: the WebAuthn challenge is the 32-byte SHA-256 of the signing input.
    public static func webauthnChallenge(_ signingInput: String) -> Data { Digest.sha256(signingInput) }

    public enum BuildError: Error, Equatable {
        case reasonTooLong
        case malformed(String)
        case signerAlgorithm
    }

    /// Build and sign a receipt over canonical bytes the caller rendered. The hash is computed here from
    /// those bytes, never accepted from the network (§4.2, "what you see is what you sign").
    public static func sign(actionId: String, canonicalBytes: String, decision: Decision, reason: String?, approverId: String, signedAt: String, signer: DeviceSigner) throws -> Receipt {
        try sign(actionId: actionId, canonicalBytesSHA256: Digest.sha256Hex(canonicalBytes), decision: decision, reason: reason, approverId: approverId, signedAt: signedAt, signer: signer)
    }

    public static func sign(actionId: String, canonicalBytesSHA256: String, decision: Decision, reason: String?, approverId: String, signedAt: String, signer: DeviceSigner) throws -> Receipt {
        if let reason, reason.utf8.count > maxReasonUTF8Bytes { throw BuildError.reasonTooLong }
        let si = signingInput(canonicalBytesSHA256: canonicalBytesSHA256, decision: decision, reason: reason, signedAt: signedAt)
        let sig = try signer.signBase64URL(si)
        let r = Receipt(receiptVersion: receiptVersion, actionId: actionId, decision: decision, reason: reason, approverId: approverId, deviceId: signer.deviceId, alg: signer.algorithm, signature: sig, signedAt: signedAt, canonicalBytesSHA256: canonicalBytesSHA256, webauthn: nil, relayId: nil)
        if let problem = schemaProblem(r.json) { throw BuildError.malformed(problem) }
        return r
    }

    /// Trim a free-text reason to at most 512 UTF-8 bytes without splitting a character.
    public static func clampReason(_ s: String) -> String {
        var out = ""
        var n = 0
        for ch in s {
            let w = String(ch).utf8.count
            if n + w > maxReasonUTF8Bytes { break }
            out.append(ch)
            n += w
        }
        return out
    }

    /// §4.3 schema check, strict. nil when valid, else a description.
    public static func schemaProblem(_ v: JSONValue) -> String? {
        parse(v).failureDescription
    }

    static func parse(_ v: JSONValue) -> ParseOutcome {
        guard let o = v.objectValue else { return .bad("not an object") }
        let allowed: Set<String> = ["receipt_version", "action_id", "decision", "reason", "approver_id", "device_id", "alg", "signature", "signed_at", "canonical_bytes_sha256", "webauthn", "relay_id"]
        for k in o.keys where !allowed.contains(k) || !k.unicodeScalars.allSatisfy(\.isASCII) { return .bad("unknown member \(k)") }
        guard let rv = o["receipt_version"]?.stringValue, isVersion(rv) else { return .bad("receipt_version") }
        guard let aid = o["action_id"]?.stringValue, Identifiers.isActionId(aid) else { return .bad("action_id") }
        guard let ds = o["decision"]?.stringValue, let decision = Decision(rawValue: ds) else { return .bad("decision") }
        var reason: String?
        if let rvv = o["reason"] {
            guard let s = rvv.stringValue, s.utf16.count <= 512, s.utf8.count <= maxReasonUTF8Bytes else { return .bad("reason") }
            reason = s
        }
        guard let ap = o["approver_id"]?.stringValue, (1...64).contains(ap.utf16.count) else { return .bad("approver_id") }
        guard let dev = o["device_id"]?.stringValue, Identifiers.isDeviceId(dev) else { return .bad("device_id") }
        guard let algS = o["alg"]?.stringValue, let alg = SignatureAlgorithm(rawValue: algS) else { return .bad("alg") }
        guard let sig = o["signature"]?.stringValue, Chars.base64URL(sig, count: 86) else { return .bad("signature") }
        guard let sat = o["signed_at"]?.stringValue, isTimestampShape(sat) else { return .bad("signed_at") }
        guard let h = o["canonical_bytes_sha256"]?.stringValue, Chars.hex64(h) else { return .bad("canonical_bytes_sha256") }
        var webauthn: WebAuthnBlock?
        if let w = o["webauthn"] {
            guard let wo = w.objectValue, wo.count == 2, let ad = wo["authenticator_data"]?.stringValue, let cd = wo["client_data_json"]?.stringValue else { return .bad("webauthn") }
            webauthn = WebAuthnBlock(authenticatorData: ad, clientDataJSON: cd)
            if alg != .es256 { return .bad("webauthn receipts must use ES256") }
        }
        var relayId: String?
        if let r = o["relay_id"] {
            guard let s = r.stringValue, s.utf16.count <= 128 else { return .bad("relay_id") }
            relayId = s
        }
        return .ok(Receipt(receiptVersion: rv, actionId: aid, decision: decision, reason: reason, approverId: ap, deviceId: dev, alg: alg, signature: sig, signedAt: sat, canonicalBytesSHA256: h, webauthn: webauthn, relayId: relayId))
    }

    enum ParseOutcome {
        case ok(Receipt)
        case bad(String)
        var failureDescription: String? { if case .bad(let s) = self { return s } else { return nil } }
    }

    /// `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`
    static func isVersion(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 2 && parts.allSatisfy { Chars.isCanonicalUInt(Array($0.utf8)) }
    }

    /// The §2.5 regex alone (the TS schema checks the shape; verify parses the instant later).
    static func isTimestampShape(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard u.count == 24 else { return false }
        let digitPositions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22]
        return digitPositions.allSatisfy { Chars.isDigit(u[$0]) } && u[4] == 0x2D && u[7] == 0x2D && u[10] == 0x54 && u[13] == 0x3A && u[16] == 0x3A && u[19] == 0x2E && u[23] == 0x5A
    }

    public struct Verified: Equatable, Sendable {
        public let receipt: Receipt
        public let signingInput: String
    }

    /// Standalone verification against a pinned device key, in §4.5 order.
    /// Pass either the canonical bytes or their SHA-256 (a gateway hashes its own stored bytes).
    public static func verify(receipt: JSONValue, canonicalBytes: String? = nil, canonicalBytesSHA256: String? = nil, issuedAt: String, expiresAt: String, devicePublicKey: PublicJWK, webauthn policy: WebAuthnPolicy? = nil) -> Result<Verified, ReceiptVerifyCode> {
        let r: Receipt
        switch parse(receipt) {
        case .bad: return .failure(.receiptMalformed)
        case .ok(let x): r = x
        }
        let major = r.receiptVersion.split(separator: ".").first.flatMap { Int($0) }
        guard major == receiptMajor else { return .failure(.receiptVersionUnsupported) }
        guard devicePublicKey.algorithm == r.alg else { return .failure(.algNotAllowed) }

        guard let ownHash = canonicalBytesSHA256 ?? canonicalBytes.map({ Digest.sha256Hex($0) }) else { return .failure(.hashMismatch) }
        guard timingSafeEqual(ownHash, r.canonicalBytesSHA256) else { return .failure(.hashMismatch) }

        guard let signedAt = Timestamp.parse(r.signedAt), let issued = Timestamp.parse(issuedAt), let expires = Timestamp.parse(expiresAt) else { return .failure(.receiptMalformed) }
        if signedAt < issued - Timestamp.clockSkewMs || signedAt > expires + Timestamp.clockSkewMs { return .failure(.clockSkew) }

        let si = signingInput(canonicalBytesSHA256: ownHash, decision: r.decision, reason: r.reason, signedAt: r.signedAt)
        guard let sig = Base64URL.decode(r.signature) else { return .failure(.receiptMalformed) }

        if let wa = r.webauthn {
            if let failure = verifyWebAuthn(wa, signingInput: si, signature: sig, policy: policy, key: devicePublicKey) { return .failure(failure) }
            return .success(Verified(receipt: r, signingInput: si))
        }
        guard devicePublicKey.verify(signature: sig, over: Data(si.utf8)) else { return .failure(.invalidSignature) }
        return .success(Verified(receipt: r, signingInput: si))
    }

    static func verifyWebAuthn(_ wa: WebAuthnBlock, signingInput: String, signature: Data, policy: WebAuthnPolicy?, key: PublicJWK) -> ReceiptVerifyCode? {
        guard let authData = Base64URL.decode(wa.authenticatorData), let cdjBytes = Base64URL.decode(wa.clientDataJSON),
              let cdjText = validUTF8(Array(cdjBytes)), let cdj = try? JSONParser.parse(cdjText) else { return .receiptMalformed }
        // §4.4 order: type → challenge → origin → rpIdHash/flags → signature.
        guard cdj["type"]?.stringValue == "webauthn.get" else { return .webauthnType }
        let expected = Base64URL.encode(webauthnChallenge(signingInput))
        guard let ch = cdj["challenge"]?.stringValue, timingSafeEqual(ch, expected) else { return .webauthnChallenge }
        guard let policy, !policy.allowedOrigins.isEmpty, let origin = cdj["origin"]?.stringValue, policy.allowedOrigins.contains(where: { exactlyEqual($0, origin) }) else { return .webauthnOrigin }
        guard authData.count >= 37 else { return .receiptMalformed }
        guard timingSafeEqual(Hex.encode(authData.prefix(32)), Digest.sha256Hex(policy.rpId)) else { return .webauthnRpId }
        let flags = authData[authData.startIndex + 32]
        let up = flags & 0x01 != 0, uv = flags & 0x04 != 0
        guard up, !policy.requireUserVerified || uv else { return .webauthnUserFlags }
        guard key.algorithm == .es256, key.verify(signature: signature, over: authData + Digest.sha256(cdjBytes)) else { return .invalidSignature }
        return nil
    }
}
