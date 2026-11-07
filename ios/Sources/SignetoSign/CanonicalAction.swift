// docs/protocol.md §2: the canonical action, receiver side. Mirrors src/action.ts
// `parseCanonicalAction`: parse the bytes as received, validate the 1.x schema, refuse bytes whose JCS
// re-serialization differs (`not_canonical`), check the idempotency key, and hash the received bytes.
import Foundation

public struct Requester: Equatable, Sendable {
    public let agent: String
    public let sessionId: String
    public let host: String
    public let gatewayId: String
}

public struct CanonicalAction: Equatable, Sendable {
    /// The parsed object, members in source (JCS) order.
    public let object: JSONObject
    public let protocolVersion: String
    public let tool: String
    public let templateId: String
    public let templateVersion: Int
    public let argsResolved: JSONObject
    public let requester: Requester
    public let nonce: String
    public let idempotencyKey: String
    public let issuedAt: String
    public let expiresAt: String
    public let originHash: String
    public let tier: Int
    public let mode: String
    public let batchId: String?
    public let batchIndex: Int?
    public let atomic: Bool?
    public let effectiveAt: String?

    public var isAdvisory: Bool { mode == "advisory" }
}

/// Canonical bytes as received plus what was derived from them.
public struct EncodedAction: Equatable, Sendable {
    public let action: CanonicalAction
    /// The JCS text exactly as received. Hash and sign these bytes, never a re-serialization.
    public let canonicalBytes: String
    /// Lowercase hex SHA-256 of `canonicalBytes` (UTF-8).
    public let canonicalBytesSHA256: String
}

public enum ParseActionError: String, Error, Equatable, Sendable {
    case actionMalformed = "action_malformed"
    case notCanonical = "not_canonical"
    case protocolVersionUnsupported = "protocol_version_unsupported"
    case idempotencyKeyMismatch = "idempotency_key_mismatch"
}

public enum CanonicalActions {
    public static let protocolMajor = 1

    /// §2.4: SHA-256 of the JCS of the action minus nonce, idempotency_key, issued_at, expires_at,
    /// effective_at and origin_hash.
    public static func idempotencyKey(_ object: JSONObject) throws -> String {
        var o = object
        for k in ["nonce", "idempotency_key", "issued_at", "expires_at", "effective_at", "origin_hash"] { o[k] = nil }
        return Digest.sha256Hex(try JCS.canonicalize(.object(o)))
    }

    public static func parse(_ bytes: String) -> Result<EncodedAction, ParseActionError> {
        guard let raw = try? JSONParser.parse(bytes) else { return .failure(.actionMalformed) }
        if let o = raw.objectValue, let pv = o["protocol_version"]?.stringValue {
            // Number(split(".")[0]) !== 1
            let major = pv.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            if jsNumber(major) != Double(protocolMajor) { return .failure(.protocolVersionUnsupported) }
        }
        guard let o = raw.objectValue, let action = validate(o) else { return .failure(.actionMalformed) }
        guard let again = try? JCS.canonicalize(raw), exactlyEqual(again, bytes) else { return .failure(.notCanonical) }
        guard let key = try? idempotencyKey(o), exactlyEqual(key, action.idempotencyKey) else { return .failure(.idempotencyKeyMismatch) }
        return .success(EncodedAction(action: action, canonicalBytes: bytes, canonicalBytesSHA256: Digest.sha256Hex(bytes)))
    }

    /// The 1.x schema (§2.2), strict: unknown members are malformed.
    static func validate(_ o: JSONObject) -> CanonicalAction? {
        let allowed: Set<String> = ["protocol_version", "tool", "template_id", "template_version", "args_resolved", "requester", "nonce", "idempotency_key", "issued_at", "expires_at", "origin_hash", "tier", "mode", "batch_id", "batch_index", "atomic", "effective_at"]
        for k in o.keys where !allowed.contains(k) || !k.unicodeScalars.allSatisfy(\.isASCII) { return nil }

        guard let pv = o["protocol_version"]?.stringValue, isMinorVersion(pv, major: "1"),
              let tool = o["tool"]?.stringValue, isToolName(tool),
              let tid = o["template_id"]?.stringValue, (1...128).contains(tid.utf16.count),
              let tverD = o["template_version"]?.numberValue, isJSInteger(tverD), tverD >= 1,
              let args = o["args_resolved"]?.objectValue,
              let req = o["requester"]?.objectValue, let requester = parseRequester(req),
              let nonce = o["nonce"]?.stringValue, Identifiers.isNonce(nonce),
              let ikey = o["idempotency_key"]?.stringValue, Chars.hex64(ikey),
              let issued = o["issued_at"]?.stringValue, let issuedMs = Timestamp.parse(issued),
              let expires = o["expires_at"]?.stringValue, let expiresMs = Timestamp.parse(expires),
              let origin = o["origin_hash"]?.stringValue, Chars.hex64(origin),
              let tier = o["tier"]?.intValue, (1...3).contains(tier),
              let mode = o["mode"]?.stringValue, mode == "enforce" || mode == "advisory"
        else { return nil }

        var batchId: String?, batchIndex: Int?, atomic: Bool?, effectiveAt: String?
        if let v = o["batch_id"] {
            guard let s = v.stringValue, Identifiers.isNonce(s) else { return nil }
            batchId = s
        }
        if let v = o["batch_index"] {
            guard let d = v.numberValue, isJSInteger(d), d >= 0 else { return nil }
            batchIndex = Int(exactly: d) ?? Int.max
        }
        if let v = o["atomic"] {
            guard let b = v.boolValue else { return nil }
            atomic = b
        }
        if let v = o["effective_at"] {
            guard let s = v.stringValue, Timestamp.parse(s) != nil else { return nil }
            effectiveAt = s
        }
        if batchId != nil {
            guard batchIndex != nil, atomic != nil else { return nil }
        } else {
            guard batchIndex == nil, atomic == nil else { return nil }
        }
        guard expiresMs > issuedMs, expiresMs - issuedMs <= Timestamp.maxExpiryMs else { return nil }
        if let e = effectiveAt { guard let eff = Timestamp.parse(e), eff > issuedMs else { return nil } }

        return CanonicalAction(object: o, protocolVersion: pv, tool: tool, templateId: tid, templateVersion: Int(exactly: tverD) ?? -1, argsResolved: args, requester: requester, nonce: nonce, idempotencyKey: ikey, issuedAt: issued, expiresAt: expires, originHash: origin, tier: tier, mode: mode, batchId: batchId, batchIndex: batchIndex, atomic: atomic, effectiveAt: effectiveAt)
    }

    static func parseRequester(_ o: JSONObject) -> Requester? {
        guard o.count == 4,
              let agent = o["agent"]?.stringValue, (1...128).contains(agent.utf16.count),
              let sid = o["session_id"]?.stringValue, (1...256).contains(sid.utf16.count),
              let host = o["host"]?.stringValue, (1...253).contains(host.utf16.count),
              let gw = o["gateway_id"]?.stringValue, Identifiers.isGatewayId(gw) else { return nil }
        return Requester(agent: agent, sessionId: sid, host: host, gatewayId: gw)
    }

    /// `^<major>\.(0|[1-9][0-9]*)$`
    static func isMinorVersion(_ s: String, major: String) -> Bool {
        let prefix = major + "."
        guard s.hasPrefix(prefix) else { return false }
        return Chars.isCanonicalUInt(Array(s.utf8.dropFirst(prefix.utf8.count)))
    }

    /// `^[a-z0-9_]+(\.[a-z0-9_]+)+$`
    static func isToolName(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return false }
        return parts.allSatisfy { p in !p.isEmpty && p.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || Chars.isDigit($0) || $0 == 0x5F } }
    }

    /// `Number.isInteger` (any magnitude).
    static func isJSInteger(_ d: Double) -> Bool { d.isFinite && d.rounded(.towardZero) == d }

    /// JS `Number(s)` for what a version prefix can hold (decimal, exponent, 0x/0o/0b); NaN otherwise.
    static func jsNumber(_ s: String) -> Double {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return 0 }
        let lower = t.lowercased()
        for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] where lower.hasPrefix(prefix) {
            return UInt64(lower.dropFirst(2), radix: radix).map(Double.init) ?? .nan
        }
        guard t.utf8.allSatisfy({ Chars.isDigit($0) || $0 == 0x2E || $0 == 0x65 || $0 == 0x45 || $0 == 0x2B || $0 == 0x2D }) else { return .nan }
        return Double(t) ?? .nan
    }
}
