// Pairing, device side, against Fixtures/pairing.json (generated with @signeto/protocol following §5.2–§5.4;
// the shared vectors have no `pairing/` set yet).
import Foundation
import XCTest
@testable import SignetoSign

final class PairingTests: XCTestCase {
    var f: JSONValue!
    let now = Timestamp.parse("2026-11-07T12:00:00.000Z")!

    override func setUpWithError() throws { f = try fixture("pairing.json") }

    func qr() throws -> QRPayload {
        guard case .success(let q) = Pairing.parseQR(f["qr_uri"]!.s, nowMs: now) else { throw XCTSkip("unreachable") }
        return q
    }

    func testQRParsing() throws {
        let q = try qr()
        XCTAssertEqual(q.gatewayId, f["gateway_id"]!.s)
        XCTAssertEqual(q.gatewayFingerprint, f["gateway_fingerprint"]!.s)
        XCTAssertEqual(q.gatewayName, "home-01")
        XCTAssertEqual(q.relay, "https://api.signeto.dev")
        XCTAssertEqual(q.manualString, f["qr_manual"]!.s)
        XCTAssertEqual(q.uri, f["qr_uri"]!.s)
        // the bare manual string, with surrounding whitespace
        XCTAssertEqual(Pairing.parseQR("  \(f["qr_manual"]!.s)\n", nowMs: now), .success(q))
        // expiry: valid up to and including expires_at, expired one millisecond later
        let exp = Timestamp.parse(f["qr"]!["expires_at"]!.s)!
        XCTAssertEqual(Pairing.parseQR(f["qr_uri"]!.s, nowMs: exp), .success(q))
        XCTAssertEqual(Pairing.parseQR(f["qr_uri"]!.s, nowMs: exp + 1), .failure(.expired))
    }

    func testQRRejections() throws {
        func enc(_ mutate: (inout JSONObject) -> Void) -> String {
            var o = f["qr"]!.objectValue!
            mutate(&o)
            return Base64URL.encode(try! JCS.canonicalData(.object(o)))
        }
        XCTAssertEqual(Pairing.parseQR(enc { $0["v"] = 2 }, nowMs: now), .failure(.versionUnsupported))
        XCTAssertEqual(Pairing.parseQR(enc { $0["extra"] = 1 }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR(enc { $0["code"] = "short" }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR(enc { $0["gateway_name"] = "" }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR(enc { $0["expires_at"] = "2026-11-07T12:10:00Z" }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR(enc { o in var k = o["gateway_public_key"]!.objectValue!; k["d"] = "x"; o["gateway_public_key"] = .object(k) }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR("signeto://pair?x=1", nowMs: now), .failure(.malformed))
        // §5.1 (SIG-92 N1): a small-order Ed25519 gateway key (here the identity point) is refused.
        let identity = Base64URL.encode(Data([1] + [UInt8](repeating: 0, count: 31)))
        XCTAssertEqual(Pairing.parseQR(enc { $0["gateway_public_key"] = ["kty": "OKP", "crv": "Ed25519", "x": .string(identity)] }, nowMs: now), .failure(.malformed))
        XCTAssertEqual(Pairing.parseQR("not base64!", nowMs: now), .failure(.malformed))
    }

    func testIdsProofAndClaim() throws {
        let q = try qr()
        let device = f["device_public_key"]!.jwk()!
        XCTAssertEqual(device.deviceId, f["device_id"]!.s)
        XCTAssertEqual(q.pairingId, f["pairing_id"]!.s)
        XCTAssertEqual(Pairing.codeHash(code: q.code), f["code_hash"]!.s)
        XCTAssertEqual(Pairing.proofSigningInput(gatewayId: q.gatewayId, deviceId: device.deviceId, devicePublicKey: device), f["proof_signing_input"]!.s)
        XCTAssertEqual(Pairing.proof(code: q.code, gatewayId: q.gatewayId, deviceId: device.deviceId, devicePublicKey: device), f["proof"]!.s)

        guard case .success(let claim) = Pairing.claim(qr: q, devicePublicKey: device, platform: "ios", name: "iPhone", attestation: nil, software: false, nowMs: now) else { return XCTFail() }
        XCTAssertEqual(claim.pairingId, f["pairing_id"]!.s)
        XCTAssertEqual(claim.body["proof"]?.s, f["proof"]!.s)
        XCTAssertEqual(claim.body["device"]?["public_key"], device.json)
        XCTAssertEqual(claim.body["device"]?["attestation"], .null)
        XCTAssertEqual(claim.body["device"]?["platform"], "ios")
        XCTAssertNotEqual(f["substituted_key_proof"]!.s, f["proof"]!.s)
        let exp = Timestamp.parse(q.expiresAt)!
        XCTAssertEqual(Pairing.claim(qr: q, devicePublicKey: device, platform: "ios", name: "iPhone", attestation: nil, software: false, nowMs: exp + 1).map(\.pairingId), .failure(.expired))
    }

    /// §5.3 proof v2 (SIG-104): `device.proof_v2` next to the v1 proof, covering name, platform and attestation.
    func testProofV2() throws {
        let q = try qr()
        let device = f["device_public_key"]!.jwk()!
        let v = f["proof_v2"]!
        XCTAssertEqual(Pairing.proofV2SigningInput(gatewayId: q.gatewayId, deviceId: device.deviceId, devicePublicKey: device, name: "iPhone", platform: "ios", attestation: nil), v["signing_input"]!.s)
        guard case .success(let claim) = Pairing.claim(qr: q, devicePublicKey: device, platform: "ios", name: "iPhone", attestation: nil, software: false, nowMs: now) else { return XCTFail() }
        XCTAssertEqual(claim.body["device"]?["proof_v2"]?.s, v["proof"]!.s)
        XCTAssertEqual(claim.body["proof"]?.s, f["proof"]!.s, "v1 stays, so a gateway from before v2 still pairs")
        // A relay that renames the device cannot keep the proof valid.
        XCTAssertNotEqual(v["renamed_proof"]!.s, v["proof"]!.s)

        let att = Attestation(format: v["attestation"]!["format"]!.s, data: v["attestation"]!["data"]!.s)
        XCTAssertEqual(Pairing.attestationSHA256(att), v["attestation_sha256"]!.s)
        XCTAssertNil(Pairing.attestationSHA256(nil))
        XCTAssertEqual(Pairing.proofV2SigningInput(gatewayId: q.gatewayId, deviceId: device.deviceId, devicePublicKey: device, name: "iPhone", platform: "ios", attestation: att), v["signing_input_attested"]!.s)
        guard case .success(let attested) = Pairing.claim(qr: q, devicePublicKey: device, platform: "ios", name: "iPhone", attestation: att, software: false, nowMs: now) else { return XCTFail() }
        XCTAssertEqual(attested.body["device"]?["proof_v2"]?.s, v["proof_attested"]!.s)

        // What build 7 sent: v1 only.
        guard case .success(let legacy) = Pairing.claim(qr: q, devicePublicKey: device, platform: "ios", name: "iPhone", attestation: nil, software: false, nowMs: now, proofV2: false) else { return XCTFail() }
        XCTAssertNil(legacy.body["device"]?["proof_v2"])
        XCTAssertEqual(legacy.body["proof"]?.s, f["proof"]!.s)
    }

    func testConfirmations() throws {
        let q = try qr()
        let device = f["device_public_key"]!.jwk()!
        let approver = f["approver_id"]!.s
        XCTAssertEqual(Pairing.confirmationSigningInput(gatewayId: q.gatewayId, deviceId: device.deviceId, pairingId: q.pairingId, pairedAt: "2026-11-07T12:02:03.456Z", approverId: approver, templatesPinned: []), f["confirmation_signing_input_no_pins"]!.s)
        let pins = Pairing.parseTemplatesPinned(f["pins"])!
        XCTAssertEqual(Pairing.confirmationSigningInput(gatewayId: q.gatewayId, deviceId: device.deviceId, pairingId: q.pairingId, pairedAt: "2026-11-07T12:02:03.456Z", approverId: approver, templatesPinned: pins), f["confirmation_signing_input_pins"]!.s)

        for c in f["confirmations"]!.arrayValue! {
            let name = c["description"]!.s
            guard let r = Pairing.acceptConfirmation(qr: q, devicePublicKey: device, view: c["view"]!) else { XCTFail("\(name): not confirmed"); continue }
            switch r {
            case .success(let pinned):
                XCTAssertEqual(c["expected"]!.s, "ok", name)
                XCTAssertEqual(pinned.gatewayId, f["gateway_id"]!.s)
                XCTAssertEqual(pinned.gatewayPublicKey, q.gatewayPublicKey)
                XCTAssertEqual(pinned.gatewayFingerprint, f["gateway_fingerprint"]!.s)
                XCTAssertEqual(pinned.deviceFingerprint, f["device_fingerprint"]!.s)
                XCTAssertEqual(pinned.templatesPinned, Pairing.parseTemplatesPinned(c["pins"])!, name)
                // the approver name comes from the signed confirmation (§5.3 point 7)
                XCTAssertEqual(pinned.approverId, approver, name)
                XCTAssertFalse(pinned.needsRepair)
                // the record round-trips through Codable storage
                let back = try JSONDecoder().decode(PinnedGateway.self, from: JSONEncoder().encode(pinned))
                XCTAssertEqual(back, pinned)
            case .failure(let e):
                XCTAssertEqual(e.rawValue, c["expected"]!.s, name)
            }
        }
        // still open: nothing to accept yet
        XCTAssertNil(Pairing.acceptConfirmation(qr: q, devicePublicKey: device, view: ["pairing_id": .string(q.pairingId), "status": "claimed"]))
        // every approver_id negative in the fixture is there
        let names = f["confirmations"]!.arrayValue!.map { $0["description"]!.s }
        XCTAssertTrue(names.contains("relay dropped approver_id"))
        XCTAssertTrue(names.contains("relay replaced approver_id with the account's approver id"))
    }

    func testApproverIdBounds() {
        XCTAssertTrue(Pairing.isValidApproverId("jason"))
        XCTAssertTrue(Pairing.isValidApproverId(String(repeating: "a", count: 64)))
        XCTAssertFalse(Pairing.isValidApproverId(""))
        XCTAssertFalse(Pairing.isValidApproverId(String(repeating: "a", count: 65)))
        XCTAssertFalse(Pairing.isValidApproverId("ja\u{7F}son"))
        XCTAssertFalse(Pairing.isValidApproverId("ja\tson"))
    }

    /// A record stored before confirmations named the approver decodes with no approver: it needs re-pairing.
    func testPinWithoutApproverDecodesAsNeedingRepair() throws {
        let q = try qr()
        let device = f["device_public_key"]!.jwk()!
        guard case .success(let pinned)? = Pairing.acceptConfirmation(qr: q, devicePublicKey: device, view: f["confirmations"]!.arrayValue![0]["view"]!) else { return XCTFail() }
        var o = try JSONParser.parse(data: JSONEncoder().encode(pinned)).objectValue!
        XCTAssertEqual(o["approver_id"], .string(f["approver_id"]!.s))
        o["approver_id"] = nil
        let old = try JSONDecoder().decode(PinnedGateway.self, from: JCS.canonicalData(.object(o)))
        XCTAssertNil(old.approverId)
        XCTAssertTrue(old.needsRepair)
        XCTAssertEqual(old.gatewayId, pinned.gatewayId)
    }
}
