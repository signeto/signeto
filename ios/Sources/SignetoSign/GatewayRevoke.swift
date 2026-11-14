// Revoke a gateway on the account from an approver device (SIG-157): a device-signed object, like a freeze.
import Foundation

public enum GatewayRevoke {
    /// The `purpose` member that binds the signature to this use. It is signed, not sent.
    public static let purpose = "gateway.revoke"

    /// UTF-8 JCS of `{gateway_id, purpose: "gateway.revoke", signed_at}`.
    public static func signingInput(gatewayId: String, signedAt: String) -> String {
        try! JCS.canonicalize(["gateway_id": .string(gatewayId), "purpose": .string(purpose), "signed_at": .string(signedAt)])
    }

    /// `POST /v1/gateways/{gateway_id}/revoke` body, signed with the device key.
    public static func body(gatewayId: String, signedAt: String, signer: DeviceSigner) throws -> JSONValue {
        let sig = try signer.signBase64URL(signingInput(gatewayId: gatewayId, signedAt: signedAt))
        return ["gateway_id": .string(gatewayId), "signed_at": .string(signedAt), "signature": .string(sig)]
    }
}
