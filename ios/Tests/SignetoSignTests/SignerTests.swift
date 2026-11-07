import CryptoKit
import Foundation
import XCTest
@testable import SignetoSign

final class SignerTests: XCTestCase {
    func testSoftwareSignerProducesRawES256() throws {
        let s = SoftwareP256Signer()
        let data = Data("hello".utf8)
        let sig = try s.sign(data)
        XCTAssertEqual(sig.count, 64)
        XCTAssertTrue(s.publicKey.verify(signature: sig, over: data))
        XCTAssertFalse(s.publicKey.verify(signature: sig, over: Data("hellO".utf8)))
        // raw r||s is the same signature CryptoKit verifies over SHA-256(data)
        let ck = try P256.Signing.ECDSASignature(rawRepresentation: sig)
        XCTAssertTrue(s.privateKey.publicKey.isValidSignature(ck, for: SHA256.hash(data: data)))
        XCTAssertEqual(s.algorithm, .es256)
        XCTAssertFalse(s.isHardwareBacked)
        XCTAssertTrue(Identifiers.isDeviceId(s.deviceId))
    }

    func testVectorKeyLoads() throws {
        let s = try vectorP256Signer("device-es256")
        XCTAssertEqual(s.deviceId, "dev_a0_Fuycw9mkJA94-PL1NxHX3GQN6Q_J3KLGwoNfjX2Q")
        XCTAssertThrowsError(try SoftwareP256Signer(jwkD: "g7G1o63IinFK7UujHq2908mCEXCVZ1M3TTpX_G7wIiI", expected: .p256(x: "Of8uj529uXHN5vuSVnd9npjQoo3omxCJUxXVYt_WXS8", y: "AAAA")))
    }

    func testEd25519Verification() throws {
        let k = try vectorKey("gateway-ed25519")
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: Base64URL.decode(k["d"]!.s)!)
        let pub = k.publicHalf()!
        XCTAssertEqual(PublicJWK(ed25519: priv.publicKey), pub)
        let sig = try priv.signature(for: Data("x".utf8))
        XCTAssertTrue(pub.verify(signature: sig, over: Data("x".utf8)))
        XCTAssertFalse(pub.verify(signature: sig.dropLast(), over: Data("x".utf8)))
    }

    func testFreezeBody() throws {
        let s = try vectorP256Signer("device-es256")
        XCTAssertEqual(Freeze.signingInput(frozen: true, signedAt: "2026-11-07T12:00:00.000Z"), "{\"frozen\":true,\"signed_at\":\"2026-11-07T12:00:00.000Z\"}")
        let body = try Freeze.body(frozen: false, signedAt: "2026-11-07T12:00:00.000Z", signer: s)
        let state = FreezeState(json: ["frozen": false, "set_by_device_id": .string(s.deviceId), "signed_at": "2026-11-07T12:00:00.000Z", "signature": body["signature"]!])!
        XCTAssertTrue(state.verifies(with: s.publicKey))
        let flipped = FreezeState(frozen: true, setByDeviceId: s.deviceId, signedAt: state.signedAt, signature: state.signature)
        XCTAssertFalse(flipped.verifies(with: s.publicKey))
    }

    /// The Secure Enclave path needs hardware, an unlocked Mac with Touch ID and a signed test runner;
    /// opt in with SIGNETO_SE_TESTS=1. Key creation does not prompt; signing would.
    func testSecureEnclaveKeyCreation() throws {
        guard ProcessInfo.processInfo.environment["SIGNETO_SE_TESTS"] == "1" else { throw XCTSkip("set SIGNETO_SE_TESTS=1 to run on Secure Enclave hardware") }
        guard SecureEnclaveSigner.isAvailable else { throw XCTSkip("no Secure Enclave") }
        let s = try SecureEnclaveSigner.generate()
        XCTAssertTrue(s.isHardwareBacked)
        XCTAssertEqual(s.algorithm, .es256)
        let again = try SecureEnclaveSigner(dataRepresentation: s.dataRepresentation)
        XCTAssertEqual(again.publicKey, s.publicKey)
    }
}
