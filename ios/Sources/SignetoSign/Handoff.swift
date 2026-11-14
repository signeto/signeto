// docs/protocol.md §5.6: gateway succession ("handoff"), device side. A gateway G1 that is being replaced names its
// successor G2 in a Tier 3 canonical action of the built-in tool `signeto.gateway_handoff`, signed like every
// approval request (`gateway_signature`, §7.5) and approved like every action (a receipt over the exact bytes).
// A device that pinned G1 pins G2, with the same approver binding and template pins, only when G1's signature
// verifies under its own pin and its OWN receipt approves those bytes. Mirrors `verifyHandoffForDevice` and
// `verifyHandoffCompletion` in src/handoff.ts; `vectors/handoff/` fixes both.
import CryptoKit
import Foundation

/// §5.6.5 failure codes, in the order the checks run (the first failure is reported).
public enum HandoffVerifyCode: String, Error, Equatable, Sendable {
    case handoffMalformed = "handoff_malformed"
    case notAHandoff = "not_a_handoff"
    case handoffUnsupported = "handoff_unsupported"
    case successorMismatch = "successor_mismatch"
    case gatewayNotPinned = "gateway_not_pinned"
    case gatewaySignatureInvalid = "gateway_signature_invalid"
    case receiptMalformed = "receipt_malformed"
    case receiptNotOwn = "receipt_not_own"
    case receiptMismatch = "receipt_mismatch"
    case approverMismatch = "approver_mismatch"
    case handoffNotApproved = "handoff_not_approved"
    case hashMismatch = "hash_mismatch"
    case invalidSignature = "invalid_signature"
    case clockSkew = "clock_skew"
    case completionInvalid = "completion_invalid"
}

/// The approved handoff as it travels: the §7.5 request's action id, canonical bytes and G1's `gateway_signature`.
public struct HandoffRequest: Equatable, Sendable {
    public let actionId: String
    public let canonicalBytes: String
    public let gatewaySignature: String

    public init(actionId: String, canonicalBytes: String, gatewaySignature: String) {
        self.actionId = actionId
        self.canonicalBytes = canonicalBytes
        self.gatewaySignature = gatewaySignature
    }

    /// From `{action_id, canonical_bytes, gateway_signature}`.
    public init?(json: JSONValue) {
        guard let a = json["action_id"]?.stringValue, let b = json["canonical_bytes"]?.stringValue, let s = json["gateway_signature"]?.stringValue else { return nil }
        self.init(actionId: a, canonicalBytes: b, gatewaySignature: s)
    }
}

/// What the device holds for the gateway it pinned (§5.3, §5.4).
public struct HandoffGatewayPin: Equatable, Sendable {
    public let gatewayId: String
    public let publicKey: PublicJWK
    public let approverId: String
    public let templatesPinned: [TemplatePin]

    public init(gatewayId: String, publicKey: PublicJWK, approverId: String, templatesPinned: [TemplatePin] = []) {
        self.gatewayId = gatewayId
        self.publicKey = publicKey
        self.approverId = approverId
        self.templatesPinned = templatesPinned
    }
}

/// The pin a device stores for the successor: G2's key, G1's approver binding and template pins.
public struct SuccessorPin: Equatable, Sendable {
    public let gatewayId: String
    public let publicKey: PublicJWK
    /// For display (escape it): the successor's name as G1 signed it.
    public let name: String
    public let approverId: String
    public let templatesPinned: [TemplatePin]
    public let predecessorGatewayId: String
}

/// The arguments of a handoff action (§5.6.1).
public struct HandoffArgs: Equatable, Sendable {
    public let successorGatewayId: String
    public let successorPublicKey: PublicJWK
    public let successorName: String
    public let ledgerSeq: Int
    public let ledgerHead: String
    public let policyHash: String
}

public struct VerifiedHandoff: Equatable, Sendable {
    public let successor: SuccessorPin
    public let action: EncodedAction
    public let args: HandoffArgs
    /// A completion was supplied and verified: G1 says it handed over and appends nothing more.
    public let completed: Bool
    /// The receipt was signed after the approval window, accepted because the completion names this device.
    public let late: Bool
}

public enum Handoff {
    public static let tool = "signeto.gateway_handoff"
    public static let templateVersion = 1
    /// `purpose` member of the completion's signing input: signed, never sent.
    public static let completePurpose = "gateway.handoff.complete"
    public static let maxDevices = 64
    public static let successorNameMax = 64
    static let maxSafeInteger: Double = 9_007_199_254_740_991

    /// UTF-8 JCS of the completion object as received without `signature`, with `purpose` added (§5.6.3).
    public static func completionSigningInput(_ completion: JSONObject) throws -> String {
        var o = completion
        o["signature"] = nil
        o["purpose"] = .string(completePurpose)
        return try JCS.canonicalize(.object(o))
    }

    // ---- arguments ---------------------------------------------------------------------------------------

    /// A public JWK with exactly its RFC 7638 required members, a valid point, and not a small-order Ed25519 key.
    public static func strictPublicJWK(_ v: JSONValue?) -> PublicJWK? {
        guard let v, let k = PublicJWK(json: v, allowExtraMembers: false), !k.isWeak else { return nil }
        switch k {
        case .p256(let x, let y):
            guard let xb = Base64URL.decode(x), let yb = Base64URL.decode(y), (try? P256.Signing.PublicKey(rawRepresentation: xb + yb)) != nil else { return nil }
        case .ed25519(let x):
            guard let xb = Base64URL.decode(x), (try? Curve25519.Signing.PublicKey(rawRepresentation: xb)) != nil else { return nil }
        }
        return k
    }

    /// The successor's display name rule: 1–64 UTF-16 code units, no surrounding whitespace, display-safe.
    public static func isValidSuccessorName(_ s: String) -> Bool {
        (1...successorNameMax).contains(s.utf16.count) && exactlyEqual(s.trimmingCharacters(in: .whitespacesAndNewlines), s) && Display.isSafe(s)
    }

    /// `handoffArgsError` in src/handoff.ts: the parsed arguments, or nil when they are not a well-formed handoff.
    static func parseArgs(_ o: JSONObject) -> HandoffArgs? {
        let keys: Set<String> = ["ledger_head", "ledger_seq", "policy_hash", "successor_gateway_id", "successor_name", "successor_public_key"]
        guard o.count == keys.count, o.keys.allSatisfy({ keys.contains($0) && $0.unicodeScalars.allSatisfy(\.isASCII) }) else { return nil }
        guard let gw = o["successor_gateway_id"]?.stringValue, Identifiers.isGatewayId(gw),
              let key = strictPublicJWK(o["successor_public_key"]),
              let name = o["successor_name"]?.stringValue, isValidSuccessorName(name),
              let seqD = o["ledger_seq"]?.numberValue, seqD.isFinite, seqD.rounded(.towardZero) == seqD, seqD >= 1, seqD <= maxSafeInteger,
              let head = o["ledger_head"]?.stringValue, Chars.hex64(head),
              let policy = o["policy_hash"]?.stringValue, Chars.hex64(policy) else { return nil }
        return HandoffArgs(successorGatewayId: gw, successorPublicKey: key, successorName: name, ledgerSeq: Int(seqD), ledgerHead: head, policyHash: policy)
    }

    /// §5.6.1: canonical bytes that are a handoff and nothing else. Signatures are not checked here.
    public static func parseAction(_ canonicalBytes: String) -> Result<(EncodedAction, HandoffArgs), HandoffVerifyCode> {
        guard case .success(let enc) = CanonicalActions.parse(canonicalBytes) else { return .failure(.handoffMalformed) }
        let a = enc.action
        guard exactlyEqual(a.tool, tool), exactlyEqual(a.templateId, tool) else { return .failure(.notAHandoff) }
        guard a.templateVersion == templateVersion else { return .failure(.handoffUnsupported) }
        guard a.tier == 3, a.mode == "enforce", a.batchId == nil, a.effectiveAt == nil, let args = parseArgs(a.argsResolved) else { return .failure(.handoffMalformed) }
        guard exactlyEqual(args.successorPublicKey.gatewayId, args.successorGatewayId), !exactlyEqual(args.successorGatewayId, a.requester.gatewayId) else { return .failure(.successorMismatch) }
        return .success((enc, args))
    }

    // ---- completion (§5.6.3) -----------------------------------------------------------------------------

    /// `verifyHandoffCompletion`: the ids of the devices the completion lists, or nil when it does not verify.
    static func verifyCompletion(_ v: JSONValue, action: EncodedAction, args: HandoffArgs, actionId: String, predecessorKey: PublicJWK) -> Set<String>? {
        guard let c = v.objectValue else { return nil }
        let keys: Set<String> = ["action_id", "canonical_bytes_sha256", "predecessor_gateway_id", "successor_gateway_id", "final_seq", "final_entry_hash", "completed_at", "devices", "receipts", "signature"]
        guard c.count == keys.count, c.keys.allSatisfy({ keys.contains($0) && $0.unicodeScalars.allSatisfy(\.isASCII) }) else { return nil }
        guard let aid = c["action_id"]?.stringValue, Identifiers.isActionId(aid),
              let hash = c["canonical_bytes_sha256"]?.stringValue, Chars.hex64(hash),
              let pred = c["predecessor_gateway_id"]?.stringValue, Identifiers.isGatewayId(pred),
              let succ = c["successor_gateway_id"]?.stringValue, Identifiers.isGatewayId(succ),
              let finalSeq = c["final_seq"]?.numberValue, finalSeq.isFinite, finalSeq.rounded(.towardZero) == finalSeq, finalSeq >= 1, finalSeq <= maxSafeInteger,
              let fh = c["final_entry_hash"]?.stringValue, Chars.hex64(fh),
              let at = c["completed_at"]?.stringValue, Timestamp.parse(at) != nil,
              let devs = c["devices"]?.arrayValue, (1...maxDevices).contains(devs.count),
              let receipts = c["receipts"]?.arrayValue, (1...maxDevices).contains(receipts.count),
              let sig = c["signature"]?.stringValue, Chars.base64URL(sig, count: 86) else { return nil }
        let deviceKeys: Set<String> = ["device_id", "public_key", "approver_id", "attested", "platform", "name", "attestation_sha256"]
        for d in devs {
            guard let o = d.objectValue, o.count == deviceKeys.count, o.keys.allSatisfy({ deviceKeys.contains($0) && $0.unicodeScalars.allSatisfy(\.isASCII) }),
                  let id = o["device_id"]?.stringValue, Identifiers.isDeviceId(id),
                  let ap = o["approver_id"]?.stringValue, (1...64).contains(ap.utf16.count),
                  o["attested"]?.boolValue != nil,
                  nullableString(o["platform"], { (1...32).contains($0.utf16.count) }),
                  nullableString(o["name"], { (1...128).contains($0.utf16.count) }),
                  nullableString(o["attestation_sha256"], Chars.hex64) else { return nil }
        }
        // Ids, hash and gateways name this handoff; signature by the predecessor.
        guard exactlyEqual(aid, actionId), exactlyEqual(hash, action.canonicalBytesSHA256) else { return nil }
        guard exactlyEqual(pred, action.action.requester.gatewayId), exactlyEqual(succ, args.successorGatewayId) else { return nil }
        guard let si = try? completionSigningInput(c), predecessorKey.verify(base64URLSignature: sig, over: si) else { return nil }
        guard Int(finalSeq) > args.ledgerSeq else { return nil }
        // Devices: keys valid, ids their thumbprints, sorted and unique.
        var listed: [String: (key: PublicJWK, approver: String)] = [:]
        var prev: [UInt8] = []
        for d in devs {
            guard let id = d["device_id"]?.stringValue, let ap = d["approver_id"]?.stringValue, let key = strictPublicJWK(d["public_key"]), exactlyEqual(key.deviceId, id) else { return nil }
            let idBytes = Array(id.utf8)
            guard idBytes.lexicographicallyPrecedes(prev) == false, idBytes != prev else { return nil }
            prev = idBytes
            listed[id] = (key, ap)
        }
        // Every receipt: an in-window approval of these bytes by a listed device under its approver.
        for raw in receipts {
            guard case .ok(let r) = Receipts.parse(raw), let dev = listed[r.deviceId] else { return nil }
            guard exactlyEqual(r.actionId, aid), exactlyEqual(r.approverId, dev.approver), r.decision == .approve else { return nil }
            guard case .success = Receipts.verify(receipt: raw, canonicalBytes: action.canonicalBytes, issuedAt: action.action.issuedAt, expiresAt: action.action.expiresAt, devicePublicKey: dev.key) else { return nil }
        }
        return Set(listed.keys)
    }

    private static func nullableString(_ v: JSONValue?, _ ok: (String) -> Bool) -> Bool {
        guard let v else { return false }
        if v.isNull { return true }
        guard let s = v.stringValue else { return false }
        return ok(s)
    }

    // ---- device side (§5.6.5) ----------------------------------------------------------------------------

    /// May this device pin the successor? Only if the handoff is signed by the gateway it pinned (G1's key from its
    /// own pin, never from the network) and its own receipt approves exactly these bytes under the approver it was
    /// paired as. A receipt signed after the approval window counts only with G1's completion naming this device.
    public static func verifyForDevice(handoff h: HandoffRequest, pin: HandoffGatewayPin, devicePublicKey: PublicJWK, receipt: JSONValue, completion: JSONValue? = nil) -> Result<VerifiedHandoff, HandoffVerifyCode> {
        // 1–3: G1's signature, under the pin.
        guard case .success(let enc) = CanonicalActions.parse(h.canonicalBytes) else { return .failure(.handoffMalformed) }
        guard exactlyEqual(enc.action.requester.gatewayId, pin.gatewayId) else { return .failure(.gatewayNotPinned) }
        guard Identifiers.isActionId(h.actionId),
              let (f, _) = ApprovalRequests.fields(actionId: h.actionId, canonicalBytes: h.canonicalBytes, expiresAt: enc.action.expiresAt),
              pin.publicKey.verify(base64URLSignature: h.gatewaySignature, over: ApprovalRequests.signingInput(f)) else { return .failure(.gatewaySignatureInvalid) }
        // 4–7: a handoff, of a version this device implements, well formed.
        let action: EncodedAction, args: HandoffArgs
        switch parseAction(h.canonicalBytes) {
        case .failure(let e): return .failure(e)
        case .success(let x): (action, args) = x
        }
        // 8–14: the device's own receipt approved exactly these bytes.
        guard case .ok(let rc) = Receipts.parse(receipt), rc.webauthn == nil else { return .failure(.receiptMalformed) }
        guard exactlyEqual(rc.deviceId, devicePublicKey.deviceId) else { return .failure(.receiptNotOwn) }
        guard exactlyEqual(rc.actionId, h.actionId) else { return .failure(.receiptMismatch) }
        guard exactlyEqual(rc.approverId, pin.approverId) else { return .failure(.approverMismatch) }
        guard rc.decision == .approve else { return .failure(.handoffNotApproved) }
        guard exactlyEqual(rc.canonicalBytesSHA256, action.canonicalBytesSHA256) else { return .failure(.hashMismatch) }
        let si = Receipts.signingInput(canonicalBytesSHA256: action.canonicalBytesSHA256, decision: rc.decision, reason: rc.reason, signedAt: rc.signedAt)
        guard devicePublicKey.algorithm == rc.alg, devicePublicKey.verify(base64URLSignature: rc.signature, over: si) else { return .failure(.invalidSignature) }
        // 15: the completion, when supplied, is G1's and names this device.
        var completed = false, listed = false
        if let completion {
            guard let ids = verifyCompletion(completion, action: action, args: args, actionId: h.actionId, predecessorKey: pin.publicKey) else { return .failure(.completionInvalid) }
            completed = true
            listed = ids.contains(rc.deviceId)
        }
        // 16: inside the approval window, or later with the completion naming this device.
        guard let at = Timestamp.parse(rc.signedAt), let issued = Timestamp.parse(action.action.issuedAt), let expires = Timestamp.parse(action.action.expiresAt) else { return .failure(.clockSkew) }
        let inWindow = at >= issued - Timestamp.clockSkewMs && at <= expires + Timestamp.clockSkewMs
        let late = !inWindow && listed && at > expires
        guard inWindow || late else { return .failure(.clockSkew) }
        let successor = SuccessorPin(gatewayId: args.successorGatewayId, publicKey: args.successorPublicKey, name: args.successorName, approverId: pin.approverId, templatesPinned: pin.templatesPinned, predecessorGatewayId: pin.gatewayId)
        return .success(VerifiedHandoff(successor: successor, action: action, args: args, completed: completed, late: late))
    }
}
