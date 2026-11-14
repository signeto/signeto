import XCTest
@testable import SignetoSign

/// Shared vectors `vectors/handoff/` (protocol.md §5.6): the device-side handoff check, case for case with
/// `verifyHandoffForDevice` in @signeto/protocol.
final class HandoffTests: XCTestCase {
    private func pin(_ v: JSONValue) throws -> HandoffGatewayPin {
        let pins = try (v["templates_pinned"]?.arrayValue ?? []).map { p in
            TemplatePin(templateId: p["template_id"]!.s, templateVersion: try XCTUnwrap(p["template_version"]?.intValue), sha256: p["sha256"]!.s)
        }
        return HandoffGatewayPin(gatewayId: v["gateway_id"]!.s, publicKey: try XCTUnwrap(v["public_key"]!.jwk()), approverId: v["approver_id"]!.s, templatesPinned: pins)
    }

    private func move() throws -> JSONValue { try loadJSON(Paths.vectors.appendingPathComponent("handoff/move.json")) }

    func testDeviceCases() throws {
        let cases = try XCTUnwrap(loadJSON(Paths.vectors.appendingPathComponent("handoff/device-cases.json"))["cases"]?.arrayValue)
        XCTAssertEqual(cases.count, 23)
        for c in cases {
            let name = c["name"]!.s, i = c["inputs"]!, e = c["expected"]!
            let r = Handoff.verifyForDevice(handoff: try XCTUnwrap(HandoffRequest(json: i["handoff"]!), name), pin: try pin(i["pin"]!), devicePublicKey: try XCTUnwrap(i["device_public_key"]!.jwk(), name), receipt: i["receipt"]!, completion: i["completion"])
            if e["ok"]?.boolValue == true {
                guard case .success(let v) = r else { XCTFail("\(name): \(r)"); continue }
                XCTAssertEqual(v.completed, e["completed"]?.boolValue, name)
                XCTAssertEqual(v.late, e["late"]?.boolValue, name)
            } else {
                guard case .failure(let code) = r else { XCTFail("\(name): expected \(e["error"]!.s), got success"); continue }
                XCTAssertEqual(code.rawValue, e["error"]!.s, name)
            }
        }
    }

    func testMoveVectorSuccessorPin() throws {
        let m = try move(), i = m["inputs"]!, e = m["expected"]!
        let device = try XCTUnwrap(i["device_private_key"]!.publicHalf())
        let r = Handoff.verifyForDevice(handoff: try XCTUnwrap(HandoffRequest(json: e["handoff"]!)), pin: try pin(i["pin"]!), devicePublicKey: device, receipt: e["receipt"]!, completion: e["completion"]!)
        guard case .success(let v) = r else { return XCTFail("\(r)") }
        let want = e["successor_pin"]!
        XCTAssertEqual(v.successor, SuccessorPin(gatewayId: want["gateway_id"]!.s, publicKey: try XCTUnwrap(want["public_key"]!.jwk()), name: want["name"]!.s, approverId: want["approver_id"]!.s, templatesPinned: try pin(want).templatesPinned, predecessorGatewayId: want["predecessor_gateway_id"]!.s))
        XCTAssertTrue(v.completed)
        XCTAssertFalse(v.late)
        XCTAssertTrue(exactlyEqual(v.action.canonicalBytes, e["canonical_bytes"]!.s))
    }

    func testCompletionSigningInput() throws {
        let e = try move()["expected"]!
        let input = try Handoff.completionSigningInput(try XCTUnwrap(e["completion"]!.objectValue))
        XCTAssertTrue(exactlyEqual(input, e["completion_signing_input"]!.s))
        XCTAssertTrue(input.contains("\"purpose\":\"gateway.handoff.complete\""))
    }

    func testBundledTemplateRenders() throws {
        let e = try move()["expected"]!
        guard case .ok(let r) = Templates.render(canonicalBytes: e["canonical_bytes"]!.s, registries: Templates.builtinRegistries) else { return XCTFail("handoff template did not verify") }
        XCTAssertTrue(exactlyEqual(r.text, e["rendered"]!["text"]!.s))
        XCTAssertTrue(exactlyEqual(r.note ?? "", e["rendered"]!["note"]!.s))
        XCTAssertEqual(r.hidden, e["rendered"]!["hidden"]!.arrayValue!.map(\.s))
        XCTAssertEqual(r.template.templateId, Handoff.tool)
    }

    func testSuccessorNameRule() {
        XCTAssertTrue(Handoff.isValidSuccessorName("Signeto Cloud"))
        for bad in ["", " padded", "padded ", "a\u{202E}b", String(repeating: "x", count: 65)] { XCTAssertFalse(Handoff.isValidSuccessorName(bad), bad) }
    }
}
