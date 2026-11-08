// Runs the shared conformance vectors in public/packages/protocol/vectors/ (protocol.md §9), the same
// files `@signeto/protocol`'s vectors.test.ts runs, with the same expectations.
import Foundation
import XCTest
@testable import SignetoSign

final class CanonicalVectorTests: XCTestCase {
    func testCanonical() throws {
        for (name, v) in try vectors("canonical") {
            let action = v["inputs"]!["action"]!
            let expected = v["expected"]!
            let bytes = try JCS.canonicalize(action)
            XCTAssertEqual(bytes, expected["canonical_bytes"]!.s, name)
            XCTAssertEqual(Digest.sha256Hex(bytes), expected["canonical_bytes_sha256"]!.s, name)
            XCTAssertEqual(try CanonicalActions.idempotencyKey(action.objectValue!), expected["idempotency_key"]!.s, name)
            switch CanonicalActions.parse(expected["canonical_bytes"]!.s) {
            case .failure(let e): XCTFail("\(name): \(e)")
            case .success(let enc):
                XCTAssertEqual(enc.canonicalBytesSHA256, expected["canonical_bytes_sha256"]!.s, name)
                if let rendered = expected["rendered"]?.stringValue {
                    XCTAssertEqual(Templates.render(enc, registries: Templates.builtinRegistries), .ok(RenderedTemplate(text: rendered, template: Templates.find(Templates.builtinRegistries, id: enc.action.templateId, version: 1)!, hidden: [])), name)
                }
            }
        }
    }

    func testCanonicalInvalid() throws {
        for (name, v) in try vectors("canonical-invalid") {
            let bytes = v["inputs"]!["canonical_bytes"]!.s
            switch CanonicalActions.parse(bytes) {
            case .success: XCTFail("\(name): accepted")
            case .failure(let e): XCTAssertEqual(e.rawValue, v["expected_error"]!.s, name)
            }
        }
    }
}

final class TemplateVectorTests: XCTestCase {
    func registries(_ v: JSONValue) throws -> [TemplateRegistry] {
        if v == .string("builtin") { return Templates.builtinRegistries }
        return try JSONDecoder().decode([TemplateRegistry].self, from: JCS.canonicalData(v))
    }

    func check(_ name: String, bytes: String, regs: [TemplateRegistry], expected e: JSONValue) {
        let r = Templates.render(canonicalBytes: bytes, registries: regs)
        switch r {
        case .ok(let ok):
            let text = ok.text
            XCTAssertEqual(e["status"]?.s, "ok", "\(name): rendered \(text)")
            XCTAssertTrue(exactlyEqual(text, e["text"]?.s ?? ""), "\(name): \(text.debugDescription) != \(String(describing: e["text"]))")
            XCTAssertEqual(ok.hidden, e["hidden"]?.arrayValue?.map(\.s), name)
            // §3.2 note and §3.5 links, byte for byte (absent in a vector means none)
            XCTAssertTrue(exactlyEqual(ok.note ?? "<none>", e["note"]?.stringValue ?? "<none>"), "\(name): note \(String(describing: ok.note))")
            let want = (e["links"]?.arrayValue ?? []).map { ($0["label"]!.s, $0["url"]!.s) }
            XCTAssertEqual(ok.links.count, want.count, "\(name): links \(ok.links.map(\.url))")
            for (got, w) in zip(ok.links, want) {
                XCTAssertTrue(exactlyEqual(got.label, w.0) && exactlyEqual(got.url, w.1), "\(name): \(got.label) \(got.url) != \(w.0) \(w.1)")
                XCTAssertTrue(got.url.hasPrefix("https://\(got.host)/"), name)
            }
            XCTAssertEqual(ok.linksError?.rawValue, e["links_error"]?.stringValue, name)
        case .unverified(let reason, let detail, let raw):
            XCTAssertEqual(e["status"]?.s, "unverified", "\(name): \(reason)")
            XCTAssertEqual(reason.rawValue, e["reason"]?.s, name)
            if let d = e["detail"]?.stringValue { XCTAssertEqual(detail, d, name) }
            XCTAssertEqual(raw, bytes, "\(name): fallback must carry the raw bytes")
        }
    }

    func testTemplates() throws {
        for (name, v) in try vectors("templates") {
            check(name, bytes: v["inputs"]!["canonical_bytes"]!.s, regs: try registries(v["inputs"]!["registries"]!), expected: v["expected"]!)
        }
    }

    /// §3.5 review links and §3.2 notes: good cases, injection attempts, invalid templates.
    func testLinks() throws {
        for (name, v) in try vectors("links") {
            check(name, bytes: v["inputs"]!["canonical_bytes"]!.s, regs: try registries(v["inputs"]!["registries"]!), expected: v["expected"]!)
        }
    }

    /// §3.1 template hash input: text alone, or JCS of the extended members.
    func testTemplateSHA256() throws {
        for (name, v) in try vectors("template-sha256") {
            let t = v["inputs"]!["template"]!
            let links = t["links"]?.arrayValue?.map { TemplateLink(label: $0["label"]!.s, url: $0["url"]!.s) }
            let input = Templates.hashInput(text: t["text"]!.s, elide: t["elide"]?.arrayValue?.map(\.s), note: t["note"]?.stringValue, links: links, linkHosts: t["link_hosts"]?.arrayValue?.map(\.s))
            XCTAssertTrue(exactlyEqual(input, v["expected"]!["hash_input"]!.s), "\(name): \(input)")
            XCTAssertEqual(Digest.sha256Hex(input), v["expected"]!["sha256"]!.s, name)
        }
    }

    /// Fixtures/renders.json: builtin templates, ECMAScript key order, value rendering, failure modes.
    func testRenderFixtures() throws {
        for c in try fixture("renders.json")["cases"]!.arrayValue! {
            check(c["description"]!.s, bytes: c["canonical_bytes"]!.s, regs: try registries(c["registries"]!), expected: c["expected"]!)
        }
    }

    /// The JSON resource is a faithful port of `@signeto/protocol` builtinRegistries.
    func testBuiltinRegistriesMatchTypeScript() throws {
        let want = try JSONDecoder().decode([TemplateRegistry].self, from: JCS.canonicalData(fixture("builtin-registries.json")))
        XCTAssertFalse(Templates.builtinRegistries.isEmpty)
        XCTAssertEqual(Templates.builtinRegistries, want)
        for r in Templates.builtinRegistries {
            for t in r.templates {
                XCTAssertEqual(t.computedSHA256, t.sha256, t.templateId)
                XCTAssertNil(Templates.linksError(t), t.templateId)
            }
        }
        XCTAssertEqual(Templates.find(Templates.builtinRegistries, id: "github.merge_pull_request", version: 2)?.links?.count, 3)
    }

    func testTemplateSourceOnlyWhenPinned() throws {
        let text = "Rotate {key} in {vault}"
        let src = TemplateSource(templateId: "acme.rotate_key", templateVersion: 3, text: text, sha256: Templates.sha256(text), elide: [])
        let pin = TemplatePin(templateId: "acme.rotate_key", templateVersion: 3, sha256: Templates.sha256(text))
        XCTAssertEqual(Templates.registries(templateSource: src, pinned: []).count, Templates.builtinRegistries.count)
        XCTAssertEqual(Templates.registries(templateSource: src, pinned: [pin]).count, Templates.builtinRegistries.count + 1)
        // text that does not hash to its claimed sha256
        let lying = TemplateSource(templateId: src.templateId, templateVersion: 3, text: "Rotate {key}", sha256: src.sha256)
        XCTAssertEqual(Templates.registries(templateSource: lying, pinned: [pin]).count, Templates.builtinRegistries.count)
        // pinned at another version
        let v2 = TemplatePin(templateId: "acme.rotate_key", templateVersion: 2, sha256: src.sha256)
        XCTAssertEqual(Templates.registries(templateSource: src, pinned: [v2]).count, Templates.builtinRegistries.count)
    }

    /// The pin covers elide: a relay cannot hide a field by adding it to a pinned text-only template_source.
    func testTemplateSourceElideCoveredByPin() throws {
        let text = "Rotate {key} in {vault}"
        let textOnlyPin = TemplatePin(templateId: "acme.rotate_key", templateVersion: 3, sha256: Templates.sha256(text))
        let added = TemplateSource(templateId: "acme.rotate_key", templateVersion: 3, text: text, sha256: Templates.sha256(text), elide: ["force"])
        XCTAssertEqual(Templates.registries(templateSource: added, pinned: [textOnlyPin]).count, Templates.builtinRegistries.count)
        // pinned with the elide, it verifies
        let withElide = Template(templateId: "acme.rotate_key", templateVersion: 3, text: text, elide: ["force"])
        XCTAssertNotEqual(withElide.sha256, Templates.sha256(text))
        let src = TemplateSource(templateId: "acme.rotate_key", templateVersion: 3, text: text, sha256: withElide.sha256, elide: ["force"])
        XCTAssertEqual(Templates.registries(templateSource: src, pinned: [TemplatePin(templateId: "acme.rotate_key", templateVersion: 3, sha256: withElide.sha256)]).last?.templates.first, withElide)
        // an empty elide is absent: a text-only pin still matches
        let empty = TemplateSource(templateId: "acme.rotate_key", templateVersion: 3, text: text, sha256: Templates.sha256(text), elide: [])
        XCTAssertEqual(Templates.registries(templateSource: empty, pinned: [textOnlyPin]).count, Templates.builtinRegistries.count + 1)
    }

    /// The pin covers links: a relay cannot add, change or drop a link of a pinned template_source.
    func testTemplateSourceLinksCoveredByPin() throws {
        let text = "Rotate {key} in {vault}"
        let links = [TemplateLink(label: "Open vault", url: "https://vault.example.com/{vault}/keys/{key}")]
        let good = Template(templateId: "acme.rotate_key", templateVersion: 4, text: text, links: links, linkHosts: ["vault.example.com"])
        let pin = TemplatePin(templateId: good.templateId, templateVersion: 4, sha256: good.sha256)
        XCTAssertNotEqual(good.sha256, Templates.sha256(text))
        let src = TemplateSource(templateId: good.templateId, templateVersion: 4, text: text, sha256: good.sha256, elide: [], links: links, linkHosts: ["vault.example.com"])
        XCTAssertEqual(Templates.registries(templateSource: src, pinned: [pin]).last?.templates.first, good)
        for forged in [
            TemplateSource(templateId: good.templateId, templateVersion: 4, text: text, sha256: good.sha256, links: [TemplateLink(label: "Open vault", url: "https://vault.example.com/{vault}")], linkHosts: ["vault.example.com"]),
            TemplateSource(templateId: good.templateId, templateVersion: 4, text: text, sha256: good.sha256, links: links, linkHosts: ["vault.example.com", "evil.example"]),
            TemplateSource(templateId: good.templateId, templateVersion: 4, text: text, sha256: good.sha256),
        ] {
            XCTAssertEqual(Templates.registries(templateSource: forged, pinned: [pin]).count, Templates.builtinRegistries.count)
        }
    }
}

final class ReceiptVectorTests: XCTestCase {
    func testSigningInput() throws {
        for (name, v) in try vectors("receipts/signing-input") {
            let i = v["inputs"]!
            let si = Receipts.signingInput(canonicalBytesSHA256: i["canonical_bytes_sha256"]!.s, decision: Decision(rawValue: i["decision"]!.s)!, reason: i["reason"]?.stringValue, signedAt: i["signed_at"]!.s)
            XCTAssertEqual(si, v["expected"]!["signing_input"]!.s, name)
            XCTAssertEqual(Base64URL.encode(Receipts.webauthnChallenge(si)), v["expected"]!["webauthn_challenge"]!.s, name)
        }
    }

    func policy(_ v: JSONValue?) -> WebAuthnPolicy? {
        guard let v else { return nil }
        return WebAuthnPolicy(allowedOrigins: v["allowed_origins"]!.arrayValue!.map(\.s), rpId: v["rp_id"]!.s, requireUserVerified: v["require_user_verified"]!.boolValue!)
    }

    /// Positive ES256, Ed25519 and WebAuthn receipts and every negative code the TS verifier reports.
    func testReceipts() throws {
        for (name, v) in try vectors("receipts") {
            let i = v["inputs"]!
            let r = Receipts.verify(receipt: i["receipt"]!, canonicalBytes: i["canonical_bytes"]!.s, issuedAt: i["issued_at"]!.s, expiresAt: i["expires_at"]!.s, devicePublicKey: i["device_public_key"]!.jwk()!, webauthn: policy(i["webauthn_policy"]))
            let e = v["expected"]!
            switch r {
            case .success(let ok):
                XCTAssertEqual(e["verify"]?.s, "ok", name)
                if let si = e["signing_input"]?.stringValue { XCTAssertEqual(ok.signingInput, si, name) }
            case .failure(let code):
                XCTAssertEqual(e["verify"]?.s, "error", "\(name): \(code)")
                XCTAssertEqual(code.rawValue, e["code"]?.s, name)
            }
        }
    }

    /// Fixtures/receipts-es256.json: ES256 receipts with a unicode reason, signed by the TS package.
    func testTypeScriptSignedES256Receipts() throws {
        let f = try fixture("receipts-es256.json")
        for c in f["cases"]!.arrayValue! {
            let r = Receipts.verify(receipt: c["receipt"]!, canonicalBytes: f["canonical_bytes"]!.s, issuedAt: f["issued_at"]!.s, expiresAt: f["expires_at"]!.s, devicePublicKey: f["device_public_key"]!.jwk()!)
            switch r {
            case .success(let ok):
                XCTAssertEqual(c["verify"]!.s, "ok", c["description"]!.s)
                XCTAssertEqual(ok.signingInput, c["signing_input"]!.s)
            case .failure(let code): XCTAssertEqual(code.rawValue, c["verify"]!.s, c["description"]!.s)
            }
        }
    }

    /// Sign with a software P-256 key (the vector device key) and verify with the TS-equivalent rules.
    func testSwiftSignedReceiptsVerify() throws {
        let signer = try vectorP256Signer("device-es256")
        let v = try vectors("receipts").first { $0.name == "es256-approve.json" }!.v
        let bytes = v["inputs"]!["canonical_bytes"]!.s
        let key = v["inputs"]!["device_public_key"]!.jwk()!
        XCTAssertEqual(signer.publicKey, key)
        for (decision, reason) in [(Decision.approve, nil), (.deny, "Not during market hours"), (.deny, "Zoë says 不 😀 \"no\"\n"), (.approve, "")] as [(Decision, String?)] {
            let r = try Receipts.sign(actionId: "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", canonicalBytes: bytes, decision: decision, reason: reason, approverId: "jason", signedAt: "2026-11-05T18:05:00.000Z", signer: signer)
            XCTAssertEqual(r.deviceId, key.deviceId)
            XCTAssertEqual(r.alg, .es256)
            XCTAssertEqual(r.signature.count, 86)
            XCTAssertNil(Receipts.schemaProblem(r.json))
            let body = try JSONParser.parse(data: r.body())
            guard case .success = Receipts.verify(receipt: body, canonicalBytes: bytes, issuedAt: v["inputs"]!["issued_at"]!.s, expiresAt: v["inputs"]!["expires_at"]!.s, devicePublicKey: key) else { return XCTFail("\(decision) \(String(describing: reason))") }
            // flipping the decision breaks it
            var flipped = r
            flipped.decision = decision == .approve ? .deny : .approve
            if case .success = Receipts.verify(receipt: flipped.json, canonicalBytes: bytes, issuedAt: v["inputs"]!["issued_at"]!.s, expiresAt: v["inputs"]!["expires_at"]!.s, devicePublicKey: key) { XCTFail("flipped decision verified") }
        }
        XCTAssertThrowsError(try Receipts.sign(actionId: "act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", canonicalBytes: bytes, decision: .deny, reason: String(repeating: "é", count: 257), approverId: "jason", signedAt: "2026-11-05T18:05:00.000Z", signer: signer))
        XCTAssertEqual(Receipts.clampReason(String(repeating: "é", count: 300)).utf8.count, 512)
        XCTAssertEqual(Receipts.clampReason("😀" + String(repeating: "a", count: 509)).utf8.count, 513 - 1 - 4 + 4) // 4 + 509 = 513 → drop last 'a'
    }
}

final class ApprovalRequestVectorTests: XCTestCase {
    func pinned(_ v: JSONValue) -> [String: PublicJWK] {
        var out: [String: PublicJWK] = [:]
        for (k, j) in v.objectValue!.entries { out[k] = j.jwk()! }
        return out
    }

    func verify(_ req: JSONValue, _ pins: [String: PublicJWK]) -> Result<VerifiedApprovalRequest, ApprovalRequestVerifyCode> {
        ApprovalRequests.verify(actionId: req["action_id"]!.s, canonicalBytes: req["canonical_bytes"]!.s, expiresAt: req["expires_at"]!.s, gatewaySignature: req["gateway_signature"]!.s, pinned: pins)
    }

    func testApprovalRequests() throws {
        for (name, v) in try vectors("approval-request") {
            let req = v["inputs"]!["request"]!
            let r = verify(req, pinned(v["inputs"]!["pinned"]!))
            let e = v["expected"]!
            switch r {
            case .success:
                XCTAssertEqual(e["verify"]?.s, "ok", name)
                let (f, _) = ApprovalRequests.fields(actionId: req["action_id"]!.s, canonicalBytes: req["canonical_bytes"]!.s, expiresAt: req["expires_at"]!.s)!
                XCTAssertEqual(ApprovalRequests.signingInput(f), e["signing_input"]!.s, name)
            case .failure(let code):
                XCTAssertEqual(e["verify"]?.s, "error", "\(name): \(code)")
                XCTAssertEqual(code.rawValue, e["code"]?.s, name)
            }
        }
    }

    func testES256Gateway() throws {
        let f = try fixture("approval-request-es256.json")
        guard case .success(let ok) = verify(f["request"]!, pinned(f["pinned"]!)) else { return XCTFail("ES256 gateway signature rejected") }
        XCTAssertEqual(ok.encoded.action.requester.gatewayId, ok.gatewayId)
        let (fields, _) = ApprovalRequests.fields(actionId: f["request"]!["action_id"]!.s, canonicalBytes: f["request"]!["canonical_bytes"]!.s, expiresAt: f["request"]!["expires_at"]!.s)!
        XCTAssertEqual(ApprovalRequests.signingInput(fields), f["signing_input"]!.s)
    }

    func testTamperedSignature() throws {
        let v = try vectors("approval-request").first { $0.name == "ok.json" }!.v
        var req = v["inputs"]!["request"]!.objectValue!
        var sig = Array(req["gateway_signature"]!.s)
        sig[10] = sig[10] == "A" ? "B" : "A"
        req["gateway_signature"] = .string(String(sig))
        if case .success = verify(.object(req), pinned(v["inputs"]!["pinned"]!)) { XCTFail("tampered signature accepted") }
        req["gateway_signature"] = "not base64url!"
        XCTAssertEqual(verify(.object(req), pinned(v["inputs"]!["pinned"]!)), .failure(.gatewaySignatureInvalid))
    }
}

final class IdsVectorTests: XCTestCase {
    func testThumbprints() throws {
        for (name, v) in try vectors("ids") {
            let i = v["inputs"]!, e = v["expected"]!
            XCTAssertEqual(i["gateway"]!.jwk()!.gatewayId, e["gateway_id"]!.s, name)
            XCTAssertEqual(i["device_es256"]!.jwk()!.deviceId, e["device_es256_id"]!.s, name)
            XCTAssertEqual(i["device_ed25519"]!.jwk()!.deviceId, e["device_ed25519_id"]!.s, name)
            XCTAssertEqual(i["gateway"]!.jwk()!.fingerprint, e["gateway_fingerprint"]!.s, name)
            XCTAssertEqual(i["device_es256"]!.jwk()!.fingerprint, e["device_es256_fingerprint"]!.s, name)
        }
    }

    func testJWKParsing() {
        let good: JSONValue = ["kty": "EC", "crv": "P-256", "x": "Of8uj529uXHN5vuSVnd9npjQoo3omxCJUxXVYt_WXS8", "y": "ymLO0QWGOus6jSc_kOwiyELsXG3f1Gf9MmJQczzivw4"]
        XCTAssertNotNil(PublicJWK(json: good))
        var withD = good.objectValue!
        withD["d"] = "g7G1o63IinFK7UujHq2908mCEXCVZ1M3TTpX_G7wIiI"
        XCTAssertNil(PublicJWK(json: .object(withD)), "private member must be refused")
        var extra = good.objectValue!
        extra["kid"] = "x"
        XCTAssertNil(PublicJWK(json: .object(extra)))
        XCTAssertNotNil(PublicJWK(json: .object(extra), allowExtraMembers: true))
        XCTAssertNil(PublicJWK(json: ["kty": "EC", "crv": "P-384", "x": "a", "y": "b"]))
        XCTAssertNil(PublicJWK(json: ["kty": "OKP", "crv": "X25519", "x": "nuh3Kz3y1tS5JZzEAq1tfujPokfE_BySBKwiGzdYA28"]))
        XCTAssertTrue(Identifiers.isActionId("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C"))
        XCTAssertFalse(Identifiers.isActionId("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5I"))
        XCTAssertFalse(Identifiers.isGatewayId("gw_jtl8uXbA19Z9r2ZrSBMGyfEddtXMM_d4wo1k0O_GMrs\n"))
    }
}

final class RelayAuthVectorTests: XCTestCase {
    func body(_ v: JSONValue?) -> Data? {
        guard let v, let s = v.stringValue else { return nil }
        return Data(s.utf8)
    }

    func testRelayAuth() throws {
        for (name, v) in try vectors("relay-auth") {
            let i = v["inputs"]!, e = v["expected"]!
            if let b = e["body_sha256"]?.stringValue { XCTAssertEqual(RelayAuth.bodySHA256(body(i["body"])), b, name) }
            if let si = e["signing_input"]?.stringValue {
                XCTAssertEqual(try RelayAuth.signingInput(method: i["method"]!.s, path: i["path"]!.s, ts: i["ts"]!.s, bodySHA256: RelayAuth.bodySHA256(body(i["body"]))), si, name)
            }
            let r = RelayAuth.verify(header: i["header"]?.stringValue, method: i["method"]!.s, path: i["path"]!.s, body: body(i["body"]), publicKey: i["public_key"]!.jwk()!, nowMs: Int64(i["now"]!.numberValue!))
            switch r {
            case .success(let p):
                XCTAssertEqual(e["verify"]?.s, "ok", name)
                if let k = e["key_id"]?.stringValue { XCTAssertEqual(p.keyId, k, name) }
            case .failure(let code):
                XCTAssertEqual(e["verify"]?.s, "error", "\(name): \(code)")
                XCTAssertEqual(code.rawValue, e["code"]?.s, name)
            }
        }
    }

    /// The device path: sign `Signeto-Device` with the ES256 vector key, verify with the TS-equivalent rules.
    /// (ES256 is randomised, so the header is verified rather than compared with the vector's.)
    func testDeviceHeaderSigning() throws {
        let v = try vectors("relay-auth").first { $0.name == "device-es256-post-with-body.json" }!.v
        let i = v["inputs"]!
        let signer = try vectorP256Signer("device-es256")
        let h = try RelayAuth.deviceHeader(method: i["method"]!.s, path: i["path"]!.s, body: body(i["body"]), ts: i["ts"]!.s, signer: signer)
        XCTAssertTrue(h.hasPrefix("Signeto-Device \(v["expected"]!["key_id"]!.s).\(i["ts"]!.s)."))
        let r = RelayAuth.verify(header: h, method: i["method"]!.s, path: i["path"]!.s, body: body(i["body"]), publicKey: signer.publicKey, nowMs: Int64(i["now"]!.numberValue!), schemes: [.device])
        guard case .success = r else { return XCTFail("\(r)") }
        // the signature covers the query string, method and body
        XCTAssertEqual(RelayAuth.verify(header: h, method: "PUT", path: i["path"]!.s, body: body(i["body"]), publicKey: signer.publicKey, nowMs: Int64(i["now"]!.numberValue!)), .failure(.invalidSignature))
        XCTAssertEqual(RelayAuth.verify(header: h, method: i["method"]!.s, path: i["path"]! .s + "?x=1", body: body(i["body"]), publicKey: signer.publicKey, nowMs: Int64(i["now"]!.numberValue!)), .failure(.invalidSignature))
        XCTAssertThrowsError(try RelayAuth.signingInput(method: "get", path: "/v1", ts: i["ts"]!.s, bodySHA256: RelayAuth.emptyBodySHA256))
        XCTAssertThrowsError(try RelayAuth.signingInput(method: "GET", path: "https://x/v1", ts: i["ts"]!.s, bodySHA256: RelayAuth.emptyBodySHA256))
        XCTAssertThrowsError(try RelayAuth.signingInput(method: "GET", path: "/v1#f", ts: i["ts"]!.s, bodySHA256: RelayAuth.emptyBodySHA256))
    }
}
