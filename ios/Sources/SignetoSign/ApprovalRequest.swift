// docs/protocol.md §7.5: `gateway_signature` on every approval request. The device rebuilds the signing
// input from the request as received (nonce and gateway_id from inside the canonical bytes), looks up the
// gateway key pinned at pairing for that gateway_id, and verifies before anything is rendered.
// Mirrors src/request.ts.
import Foundation

public struct ApprovalRequestSigningFields: Equatable, Sendable {
    public let actionId: String
    public let canonicalBytesSHA256: String
    public let expiresAt: String
    public let gatewayId: String
    public let nonce: String

    public init(actionId: String, canonicalBytesSHA256: String, expiresAt: String, gatewayId: String, nonce: String) {
        self.actionId = actionId
        self.canonicalBytesSHA256 = canonicalBytesSHA256
        self.expiresAt = expiresAt
        self.gatewayId = gatewayId
        self.nonce = nonce
    }
}

public enum ApprovalRequestVerifyCode: String, Error, Equatable, Sendable {
    case gatewaySignatureInvalid = "gateway_signature_invalid"
    case gatewayNotPinned = "gateway_not_pinned"
    case requestMalformed = "request_malformed"
}

/// A request that passed `gateway_signature` verification. Only this type reaches the renderer.
public struct VerifiedApprovalRequest: Equatable, Sendable {
    public let actionId: String
    public let gatewayId: String
    /// Parsed from the verified canonical bytes; `encoded.canonicalBytes` is what is shown and hashed.
    public let encoded: EncodedAction
}

public enum ApprovalRequests {
    public static func signingInput(_ f: ApprovalRequestSigningFields) -> String {
        let o: JSONValue = [
            "action_id": .string(f.actionId),
            "canonical_bytes_sha256": .string(f.canonicalBytesSHA256),
            "expires_at": .string(f.expiresAt),
            "gateway_id": .string(f.gatewayId),
            "nonce": .string(f.nonce),
        ]
        return try! JCS.canonicalize(o)
    }

    /// The signing fields derived from the request body itself; nil when the bytes are not a valid canonical
    /// action or the request's `expires_at` differs from the one inside the bytes.
    public static func fields(actionId: String, canonicalBytes: String, expiresAt: String) -> (ApprovalRequestSigningFields, EncodedAction)? {
        guard case .success(let enc) = CanonicalActions.parse(canonicalBytes) else { return nil }
        let a = enc.action
        guard exactlyEqual(a.expiresAt, expiresAt) else { return nil }
        let f = ApprovalRequestSigningFields(actionId: actionId, canonicalBytesSHA256: enc.canonicalBytesSHA256, expiresAt: a.expiresAt, gatewayId: a.requester.gatewayId, nonce: a.nonce)
        return (f, enc)
    }

    /// Device side, before rendering. `pinned` maps gateway_id → the public key taken from that gateway's QR.
    public static func verify(actionId: String, canonicalBytes: String, expiresAt: String, gatewaySignature: String, pinned: [String: PublicJWK]) -> Result<VerifiedApprovalRequest, ApprovalRequestVerifyCode> {
        guard let (f, enc) = fields(actionId: actionId, canonicalBytes: canonicalBytes, expiresAt: expiresAt) else { return .failure(.requestMalformed) }
        guard let key = pinned[f.gatewayId] else { return .failure(.gatewayNotPinned) }
        guard key.verify(base64URLSignature: gatewaySignature, over: signingInput(f)) else { return .failure(.gatewaySignatureInvalid) }
        return .success(VerifiedApprovalRequest(actionId: actionId, gatewayId: f.gatewayId, encoded: enc))
    }
}
