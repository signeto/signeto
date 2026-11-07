// docs/protocol.md §7.9: the account freeze flag, set or lifted by a device-signed object.
import Foundation

public struct FreezeState: Equatable, Sendable {
    public let frozen: Bool
    public let setByDeviceId: String?
    public let signedAt: String?
    public let signature: String?

    public init(frozen: Bool, setByDeviceId: String?, signedAt: String?, signature: String?) {
        self.frozen = frozen
        self.setByDeviceId = setByDeviceId
        self.signedAt = signedAt
        self.signature = signature
    }

    /// From `GET /v1/accounts/me/freeze`.
    public init?(json: JSONValue) {
        guard let f = json["frozen"]?.boolValue else { return nil }
        self.init(frozen: f, setByDeviceId: json["set_by_device_id"]?.stringValue, signedAt: json["signed_at"]?.stringValue, signature: json["signature"]?.stringValue)
    }

    /// True when the state carries a signature that verifies with `key` (e.g. this device's own key).
    public func verifies(with key: PublicJWK) -> Bool {
        guard let signedAt, let signature else { return false }
        return key.verify(base64URLSignature: signature, over: Freeze.signingInput(frozen: frozen, signedAt: signedAt))
    }
}

public enum Freeze {
    /// UTF-8 JCS of `{frozen, signed_at}`.
    public static func signingInput(frozen: Bool, signedAt: String) -> String {
        try! JCS.canonicalize(["frozen": .bool(frozen), "signed_at": .string(signedAt)])
    }

    /// `PUT /v1/accounts/me/freeze` body, signed with the device key.
    public static func body(frozen: Bool, signedAt: String, signer: DeviceSigner) throws -> JSONValue {
        let sig = try signer.signBase64URL(signingInput(frozen: frozen, signedAt: signedAt))
        return ["frozen": .bool(frozen), "signed_at": .string(signedAt), "signature": .string(sig)]
    }
}
