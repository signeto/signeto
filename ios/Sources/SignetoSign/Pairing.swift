// docs/protocol.md §5: the pairing handshake, device side.
//   parse QR (gateway key comes from here and nowhere else, §5.3 point 1)
//   → claim body with HMAC proofs v1 and v2 (§5.3 point 2; v2 also covers name, platform and attestation)
//   → verify the gateway's confirmation with the QR's key, including approver_id and templates_pinned
//     (§5.3 points 4 and 7, §5.4)
//   → PinnedGateway record, whose approverId every receipt for that gateway carries.
// Mirrors packages/gateway/src/pairing/{qr,handshake}.ts. As there: SHA-256(code) and the HMAC key are
// over the UTF-8 text of the 22-character code as printed, not its decoded bytes.
import CryptoKit
import Foundation

public struct QRPayload: Equatable, Sendable {
    public let v: Int
    public let gatewayPublicKey: PublicJWK
    public let gatewayName: String
    /// Relay base URL, or "" in the solo topology.
    public let relay: String
    /// Secret pairing code (22 base64url characters). Never sent anywhere.
    public let code: String
    public let expiresAt: String

    public var gatewayId: String { gatewayPublicKey.gatewayId }
    public var gatewayFingerprint: String { gatewayPublicKey.fingerprint }
    public var pairingId: String { Pairing.pairingId(code: code) }

    public var json: JSONValue {
        ["v": .number(Double(v)), "gateway_public_key": gatewayPublicKey.json, "gateway_name": .string(gatewayName), "relay": .string(relay), "code": .string(code), "expires_at": .string(expiresAt)]
    }

    /// `base64url(JCS(payload))`: the manual-entry string.
    public var manualString: String { Base64URL.encode(try! JCS.canonicalData(json)) }
    public var uri: String { Pairing.qrScheme + "?d=" + manualString }
}

public enum QRParseError: String, Error, Equatable, Sendable {
    case malformed = "qr_malformed"
    case versionUnsupported = "qr_version_unsupported"
    case expired = "qr_expired"
}

/// `{template_id, template_version, sha256}` list, or the reason it was rejected.
public enum ConfirmationError: String, Error, Equatable, Sendable {
    /// The confirmation does not verify with the QR's gateway key (relay or network may be hostile).
    case confirmationInvalid = "pairing_confirmation_invalid"
    /// The confirmation is for a different pairing or device.
    case pairingMismatch = "pairing_mismatch"
}

/// What the device stores per gateway after a verified pairing (§5.3 point 6).
public struct PinnedGateway: Equatable, Codable, Sendable, Identifiable {
    public var id: String { gatewayId }
    public let gatewayId: String
    public let gatewayName: String
    /// From the QR, never from the relay.
    public let gatewayPublicKey: PublicJWK
    public let gatewayFingerprint: String
    public let deviceId: String
    public let deviceFingerprint: String
    public let pairingId: String
    public let pairedAt: String
    public let relay: String
    /// The approver this gateway pinned the device under (its `signeto.yml` name, not the relay account's id),
    /// covered by the confirmation signature (§5.3 point 7). Every receipt for this gateway carries it.
    /// `nil` only for a record stored before confirmations named the approver: do not sign, ask to re-pair.
    public let approverId: String?
    /// Covered by the gateway's confirmation signature (§5.4).
    public let templatesPinned: [TemplatePin]

    /// A pin from before confirmations carried `approver_id`: receipts for this gateway cannot be signed.
    public var needsRepair: Bool { approverId == nil }

    public init(gatewayId: String, gatewayName: String, gatewayPublicKey: PublicJWK, gatewayFingerprint: String, deviceId: String, deviceFingerprint: String, pairingId: String, pairedAt: String, relay: String, approverId: String?, templatesPinned: [TemplatePin]) {
        self.gatewayId = gatewayId
        self.gatewayName = gatewayName
        self.gatewayPublicKey = gatewayPublicKey
        self.gatewayFingerprint = gatewayFingerprint
        self.deviceId = deviceId
        self.deviceFingerprint = deviceFingerprint
        self.pairingId = pairingId
        self.pairedAt = pairedAt
        self.relay = relay
        self.approverId = approverId
        self.templatesPinned = templatesPinned
    }

    enum CodingKeys: String, CodingKey {
        case gatewayId = "gateway_id", gatewayName = "gateway_name", gatewayPublicKey = "gateway_public_key", gatewayFingerprint = "gateway_fingerprint"
        case deviceId = "device_id", deviceFingerprint = "device_fingerprint", pairingId = "pairing_id", pairedAt = "paired_at", relay
        case approverId = "approver_id", templatesPinned = "templates_pinned"
    }
}

public struct Attestation: Equatable, Sendable {
    public let format: String
    public let data: String
    public init(format: String, data: String) {
        self.format = format
        self.data = data
    }
    public var json: JSONValue { ["format": .string(format), "data": .string(data)] }
}

public enum Pairing {
    public static let qrScheme = "signeto://pair"
    /// §5.2: the QR expires within 10 minutes.
    public static let qrMaxTTLMs: Int64 = 600_000

    // MARK: QR

    /// Accepts the full `signeto://pair?d=…` URI or the bare manual-entry string. `nowMs` is the device clock.
    public static func parseQR(_ input: String, nowMs: Int64) -> Result<QRPayload, QRParseError> {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var data = trimmed
        if trimmed.hasPrefix(qrScheme) {
            guard let comps = URLComponents(string: trimmed), let d = comps.queryItems?.first(where: { $0.name == "d" })?.value, !d.isEmpty else { return .failure(.malformed) }
            data = d
        }
        guard let raw = Base64URL.decode(data), let text = validUTF8(Array(raw)), let json = try? JSONParser.parse(text), let o = json.objectValue else { return .failure(.malformed) }
        guard o["v"] == .number(1) else { return .failure(.versionUnsupported) }
        // §5.1 (SIG-92 N1): a small-order gateway key would make every confirmation and request "verify".
        guard let keyJSON = o["gateway_public_key"], let key = PublicJWK(json: keyJSON), !key.isWeak else { return .failure(.malformed) }
        guard let name = o["gateway_name"]?.stringValue, !name.isEmpty else { return .failure(.malformed) }
        guard let relay = o["relay"]?.stringValue else { return .failure(.malformed) }
        guard let code = o["code"]?.stringValue, Chars.base64URL(code, count: 22) else { return .failure(.malformed) }
        guard let exp = o["expires_at"]?.stringValue, let expMs = Timestamp.parse(exp) else { return .failure(.malformed) }
        let known: Set<String> = ["v", "gateway_public_key", "gateway_name", "relay", "code", "expires_at"]
        guard o.keys.allSatisfy({ known.contains($0) && $0.unicodeScalars.allSatisfy(\.isASCII) }) else { return .failure(.malformed) }
        if nowMs > expMs { return .failure(.expired) }
        return .success(QRPayload(v: 1, gatewayPublicKey: key, gatewayName: name, relay: relay, code: code, expiresAt: exp))
    }

    // MARK: ids and proof

    /// §5.3: `pairing_id = base64url(SHA-256(code))[0:22]`.
    public static func pairingId(code: String) -> String { String(Base64URL.encode(Digest.sha256(code)).prefix(22)) }

    /// §7.3 `code_hash`: lowercase hex SHA-256 of the code text.
    public static func codeHash(code: String) -> String { Digest.sha256Hex(code) }

    /// JCS of `{device_id, device_public_key, gateway_id}`.
    public static func proofSigningInput(gatewayId: String, deviceId: String, devicePublicKey: PublicJWK) -> String {
        try! JCS.canonicalize(["device_id": .string(deviceId), "device_public_key": devicePublicKey.json, "gateway_id": .string(gatewayId)])
    }

    /// `proof = HMAC-SHA256(key = code, msg = proofSigningInput)`, base64url without padding. Proof v1.
    public static func proof(code: String, gatewayId: String, deviceId: String, devicePublicKey: PublicJWK) -> String {
        hmac(code: code, proofSigningInput(gatewayId: gatewayId, deviceId: deviceId, devicePublicKey: devicePublicKey))
    }

    /// Lowercase hex SHA-256 of the JCS of `{data, format}`; nil when there is no attestation.
    public static func attestationSHA256(_ a: Attestation?) -> String? {
        guard let a else { return nil }
        return Digest.sha256Hex(try! JCS.canonicalize(["data": .string(a.data), "format": .string(a.format)]))
    }

    /// Proof v2 input (§5.3): JCS of `{attestation_sha256, device_id, device_public_key, gateway_id, name, platform,
    /// proof_version: 2}`, absent metadata as null. `proof_version` makes it never equal to a v1 input.
    public static func proofV2SigningInput(gatewayId: String, deviceId: String, devicePublicKey: PublicJWK, name: String?, platform: String?, attestation: Attestation?) -> String {
        try! JCS.canonicalize([
            "attestation_sha256": attestationSHA256(attestation).map(JSONValue.string) ?? .null,
            "device_id": .string(deviceId),
            "device_public_key": devicePublicKey.json,
            "gateway_id": .string(gatewayId),
            "name": name.map(JSONValue.string) ?? .null,
            "platform": platform.map(JSONValue.string) ?? .null,
            "proof_version": .number(2),
        ])
    }

    /// Proof v2: `HMAC-SHA256(key = code, msg = proofV2SigningInput)`, base64url without padding. Sent as
    /// `device.proof_v2` next to the v1 `proof`, so a relay cannot rename the device, change its platform or strip
    /// its attestation without the gateway noticing; a gateway from before v2 ignores it.
    public static func proofV2(code: String, gatewayId: String, deviceId: String, devicePublicKey: PublicJWK, name: String?, platform: String?, attestation: Attestation?) -> String {
        hmac(code: code, proofV2SigningInput(gatewayId: gatewayId, deviceId: deviceId, devicePublicKey: devicePublicKey, name: name, platform: platform, attestation: attestation))
    }

    static func hmac(code: String, _ input: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: SymmetricKey(data: Data(code.utf8)))
        return Base64URL.encode(Data(mac))
    }

    // MARK: claim

    public struct Claim: Equatable, Sendable {
        public let pairingId: String
        public let gatewayId: String
        public let deviceId: String
        /// `POST /v1/pairings/{pairing_id}/claim` body.
        public let body: JSONValue
    }

    /// Build the claim (§7.3) from the QR and the device's own public key. Re-checks expiry. The claim carries
    /// proof v1 and `device.proof_v2`; `proofV2: false` leaves v2 out (what iOS build 7 sent; tests only).
    public static func claim(qr: QRPayload, devicePublicKey: PublicJWK, platform: String, name: String, attestation: Attestation?, software: Bool, nowMs: Int64, proofV2 includeV2: Bool = true) -> Result<Claim, QRParseError> {
        guard let exp = Timestamp.parse(qr.expiresAt), nowMs <= exp else { return .failure(.expired) }
        let deviceId = devicePublicKey.deviceId
        let gatewayId = qr.gatewayId
        var device = JSONObject([
            ("public_key", devicePublicKey.json),
            ("platform", .string(platform)),
            ("name", .string(name)),
            ("attestation", attestation?.json ?? .null),
            ("software", .bool(software)),
        ])
        if includeV2 {
            device["proof_v2"] = .string(proofV2(code: qr.code, gatewayId: gatewayId, deviceId: deviceId, devicePublicKey: devicePublicKey, name: name, platform: platform, attestation: attestation))
        }
        let body: JSONValue = ["device": .object(device), "proof": .string(proof(code: qr.code, gatewayId: gatewayId, deviceId: deviceId, devicePublicKey: devicePublicKey))]
        return .success(Claim(pairingId: qr.pairingId, gatewayId: gatewayId, deviceId: deviceId, body: body))
    }

    // MARK: confirmation

    /// Shape check for a pin list received from the network (absent → []). nil when it is not one.
    public static func parseTemplatesPinned(_ v: JSONValue?) -> [TemplatePin]? {
        guard let v else { return [] }
        guard let arr = v.arrayValue else { return nil }
        var out: [TemplatePin] = []
        for p in arr {
            guard let o = p.objectValue, o.count == 3,
                  let id = o["template_id"]?.stringValue, (1...128).contains(id.utf16.count),
                  let verD = o["template_version"]?.numberValue, CanonicalActions.isJSInteger(verD), verD >= 1, let ver = Int(exactly: verD),
                  let sha = o["sha256"]?.stringValue, Chars.hex64(sha) else { return nil }
            out.append(TemplatePin(templateId: id, templateVersion: ver, sha256: sha))
        }
        return out
    }

    /// §5.3 point 7: a confirmation's `approver_id` is 1 to 64 characters (UTF-16 code units, as JavaScript counts
    /// them, matching a receipt's bounds) with no control characters.
    public static func isValidApproverId(_ s: String) -> Bool {
        (1...64).contains(s.utf16.count) && !s.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F }
    }

    /// `JCS{approver_id, device_id, gateway_id, paired_at, pairing_id, templates_pinned}`, pins in the order received.
    public static func confirmationSigningInput(gatewayId: String, deviceId: String, pairingId: String, pairedAt: String, approverId: String, templatesPinned: [TemplatePin]) -> String {
        try! JCS.canonicalize([
            "approver_id": .string(approverId),
            "device_id": .string(deviceId),
            "gateway_id": .string(gatewayId),
            "paired_at": .string(pairedAt),
            "pairing_id": .string(pairingId),
            "templates_pinned": .array(templatesPinned.map(\.json)),
        ])
    }

    /// §5.3 points 4 and 7, §5.4: verify the confirmation with the key from the QR (never one from the relay)
    /// over the approver and the pin list as received, then produce the record to store. Nothing is pinned on
    /// failure. A confirmation without a valid `approver_id` is invalid.
    public static func acceptConfirmation(qr: QRPayload, devicePublicKey: PublicJWK, pairingId: String, deviceId: String?, pairedAt: String, confirmation: String, approverId: JSONValue?, templatesPinned: JSONValue?) -> Result<PinnedGateway, ConfirmationError> {
        let gatewayId = qr.gatewayId
        let ownDeviceId = devicePublicKey.deviceId
        guard exactlyEqual(pairingId, qr.pairingId), deviceId.map({ exactlyEqual($0, ownDeviceId) }) ?? true else { return .failure(.pairingMismatch) }
        guard let pins = parseTemplatesPinned(templatesPinned) else { return .failure(.confirmationInvalid) }
        guard let approver = approverId?.stringValue, isValidApproverId(approver) else { return .failure(.confirmationInvalid) }
        let si = confirmationSigningInput(gatewayId: gatewayId, deviceId: ownDeviceId, pairingId: pairingId, pairedAt: pairedAt, approverId: approver, templatesPinned: pins)
        guard qr.gatewayPublicKey.verify(base64URLSignature: confirmation, over: si) else { return .failure(.confirmationInvalid) }
        return .success(PinnedGateway(gatewayId: gatewayId, gatewayName: qr.gatewayName, gatewayPublicKey: qr.gatewayPublicKey, gatewayFingerprint: qr.gatewayFingerprint, deviceId: ownDeviceId, deviceFingerprint: devicePublicKey.fingerprint, pairingId: pairingId, pairedAt: pairedAt, relay: qr.relay, approverId: approver, templatesPinned: pins))
    }

    /// `GET /v1/pairings/{id}` view → confirmation acceptance. Returns nil while still open/claimed.
    public static func acceptConfirmation(qr: QRPayload, devicePublicKey: PublicJWK, view: JSONValue) -> Result<PinnedGateway, ConfirmationError>? {
        guard view["status"]?.stringValue == "confirmed" else { return nil }
        guard let pairedAt = view["paired_at"]?.stringValue, let conf = view["confirmation"]?.stringValue else { return .failure(.confirmationInvalid) }
        // The pairing id is our own (derived from the QR code), as the CLI does; the relay's echo is not trusted.
        if let pid = view["pairing_id"]?.stringValue, !exactlyEqual(pid, qr.pairingId) { return .failure(.pairingMismatch) }
        return acceptConfirmation(qr: qr, devicePublicKey: devicePublicKey, pairingId: qr.pairingId, deviceId: view["device_id"]?.stringValue, pairedAt: pairedAt, confirmation: conf, approverId: view["approver_id"], templatesPinned: view["templates_pinned"])
    }

    // MARK: App Attest binding

    /// The `clientDataHash` this package uses for App Attest when attesting a device key: the 32-byte RFC 7638
    /// thumbprint of the device public key (the bytes behind `device_id`). A verifier recomputes it from the JWK
    /// in the claim. Attestation format string: `apple-appattest`, data = base64url(attestation object).
    public static func appAttestClientDataHash(devicePublicKey: PublicJWK) -> Data { devicePublicKey.thumbprint }
    public static let appAttestFormat = "apple-appattest"
}
