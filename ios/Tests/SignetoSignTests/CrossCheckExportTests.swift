// Swift → TypeScript cross-check. With SIGNETO_EXPORT_DIR set, writes receipts, a relay header and a
// freeze body signed here with the vector ES256 key; Fixtures/verify-swift-output.mjs then verifies them
// with @signeto/protocol:
//   SIGNETO_EXPORT_DIR=/tmp/sig swift test --filter CrossCheckExportTests
//   node Tests/SignetoSignTests/Fixtures/verify-swift-output.mjs /tmp/sig
import Foundation
import XCTest
@testable import SignetoSign

final class CrossCheckExportTests: XCTestCase {
    func testExportSwiftSignedArtifacts() throws {
        guard let dir = ProcessInfo.processInfo.environment["SIGNETO_EXPORT_DIR"] else { throw XCTSkip("set SIGNETO_EXPORT_DIR to export Swift-signed artifacts for the TS cross-check") }
        let signer = try vectorP256Signer("device-es256")
        let v = try vectors("receipts").first { $0.name == "es256-approve.json" }!.v
        let i = v["inputs"]!
        let bytes = i["canonical_bytes"]!.s
        var receipts: [JSONValue] = []
        for (d, reason) in [(Decision.approve, nil), (.deny, "Zoë says 不 😀 \"no\"\n")] as [(Decision, String?)] {
            receipts.append(try Receipts.sign(actionId: "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", canonicalBytes: bytes, decision: d, reason: reason, approverId: "jason", signedAt: "2026-11-05T18:05:00.000Z", signer: signer).json)
        }
        let body = try JCS.canonicalize(receipts[0])
        let ts = "2026-11-05T18:05:00.000Z"
        let path = "/v1/approvals/apr_01JBXK4Q9R2T4V6W8Y0Z1A3B5D/receipt?x=%2F1"
        let header = try RelayAuth.deviceHeader(method: "POST", path: path, body: Data(body.utf8), ts: ts, signer: signer)
        let freeze = try Freeze.body(frozen: true, signedAt: ts, signer: signer)
        let out: JSONValue = [
            "canonical_bytes": .string(bytes), "issued_at": i["issued_at"]!, "expires_at": i["expires_at"]!, "device_public_key": signer.publicKey.json,
            "receipts": .array(receipts),
            "relay": ["header": .string(header), "method": "POST", "path": .string(path), "body": .string(body), "now": .number(Double(Timestamp.parse(ts)!))],
            "freeze": freeze,
        ]
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try JCS.canonicalData(out).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-signed.json"))
    }
}
