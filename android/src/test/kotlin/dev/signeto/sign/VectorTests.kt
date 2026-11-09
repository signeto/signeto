// Runs the shared conformance vectors in public/packages/protocol/vectors/ (protocol.md §9), the same files
// `@signeto/protocol`'s vectors.test.ts and SignetoSign's VectorTests.swift run, with the same expectations.
package dev.signeto.sign

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class CanonicalVectorTests {
    @Test
    fun canonical() {
        for ((name, v) in vectors("canonical")) {
            val action = v("inputs")("action")
            val expected = v("expected")
            val bytes = Jcs.canonicalize(action)
            assertEquals(expected("canonical_bytes").s, bytes, name)
            assertEquals(expected("canonical_bytes_sha256").s, Digest.sha256Hex(bytes), name)
            assertEquals(expected("idempotency_key").s, CanonicalActions.idempotencyKey(action.objectValue!!), name)
            when (val r = CanonicalActions.parse(expected("canonical_bytes").s)) {
                is Outcome.Err -> fail("$name: ${r.error}")
                is Outcome.Ok -> {
                    val enc = r.value
                    assertEquals(expected("canonical_bytes_sha256").s, enc.canonicalBytesSha256, name)
                    expected["rendered"]?.stringValue?.let { rendered ->
                        val t = Templates.find(Templates.builtinRegistries, enc.action.templateId, 1)!!
                        assertEquals(RenderResult.Ok(RenderedTemplate(rendered, t, emptyList())), Templates.render(enc, Templates.builtinRegistries), name)
                    }
                }
            }
        }
    }

    @Test
    fun canonicalInvalid() {
        for ((name, v) in vectors("canonical-invalid")) {
            when (val r = CanonicalActions.parse(v("inputs")("canonical_bytes").s)) {
                is Outcome.Ok -> fail("$name: accepted")
                is Outcome.Err -> assertEquals(v("expected_error").s, r.error.code, name)
            }
        }
    }
}

class TemplateVectorTests {
    private fun registries(v: JsonValue): List<TemplateRegistry> =
        if (v == str("builtin")) Templates.builtinRegistries else TemplateRegistry.listFromJson(v)!!

    private fun check(name: String, bytes: String, regs: List<TemplateRegistry>, e: JsonValue) {
        when (val r = Templates.render(bytes, regs)) {
            is RenderResult.Ok -> {
                val ok = r.rendered
                assertEquals("ok", e["status"]?.s, "$name: rendered ${ok.text}")
                assertEquals(e["text"]?.s ?: "", ok.text, name)
                assertEquals(e["hidden"]?.arrayValue?.map { it.s }, ok.hidden, name)
                // §3.2 note and §3.5 links, byte for byte (absent in a vector means none)
                assertEquals(e["note"]?.stringValue ?: "<none>", ok.note ?: "<none>", "$name: note")
                val want = (e["links"]?.arrayValue ?: emptyList()).map { it("label").s to it("url").s }
                assertEquals(want, ok.links.map { it.label to it.url }, "$name: links")
                for (l in ok.links) assertTrue(l.url.startsWith("https://${l.host}/"), name)
                assertEquals(e["links_error"]?.stringValue, ok.linksError?.code, name)
            }
            is RenderResult.Unverified -> {
                assertEquals("unverified", e["status"]?.s, "$name: ${r.reason}")
                assertEquals(e["reason"]?.s, r.reason.code, name)
                e["detail"]?.stringValue?.let { assertEquals(it, r.detail, name) }
                assertEquals(bytes, r.canonicalBytes, "$name: fallback must carry the raw bytes")
            }
        }
    }

    @Test
    fun templates() {
        for ((name, v) in vectors("templates")) check(name, v("inputs")("canonical_bytes").s, registries(v("inputs")("registries")), v("expected"))
    }

    /** §3.5 review links and §3.2 notes: good cases, injection attempts, invalid templates. */
    @Test
    fun links() {
        for ((name, v) in vectors("links")) check(name, v("inputs")("canonical_bytes").s, registries(v("inputs")("registries")), v("expected"))
    }

    /** Fixtures/renders.json: builtin templates, ECMAScript key order, value rendering, failure modes. */
    @Test
    fun renderFixtures() {
        for (c in fixture("renders.json")("cases").arrayValue!!) check(c("description").s, c("canonical_bytes").s, registries(c("registries")), c("expected"))
    }

    /** §5.1 small-order Ed25519 keys: the same cases `isWeakPublicJwk` in TypeScript refuses. */
    @Test
    fun weakKeys() {
        for ((name, v) in vectors("weak-keys")) {
            for (c in v("cases").arrayValue!!) {
                val jwk = PublicJwk.Ed25519(c("x").s)
                val weak = c["weak"] == JsonValue.Bool(true)
                assertEquals(weak, jwk.isWeak, "$name: ${c("description").s}")
                if (weak) {
                    // Nothing verifies under it, not even R = identity, S = 0 over any message.
                    val sig = ByteArray(64).also { it[0] = 1 }
                    assertFalse(jwk.verify(sig, "approve anything".toByteArray()), c("description").s)
                }
            }
        }
    }

    /** §3.6 display escape: the same expected output as `displayEscape` in TypeScript. */
    @Test
    fun displayEscape() {
        for ((name, v) in vectors("display-escape")) {
            val escaped = Display.escape(v("inputs")("value").s)
            assertEquals(v("expected")("escaped").s, escaped, name)
            assertTrue(Display.isSafe(escaped), name)
        }
    }

    /** §3.6 escaped set, code point by code point (the vectors cover examples; this covers the boundaries). */
    @Test
    fun displayEscapeSetBoundaries() {
        val escaped = listOf(0x00..0x1F, 0x7F..0x9F, 0x61C..0x61C, 0x200B..0x200F, 0x2028..0x202E, 0x2060..0x2069, 0xFEFF..0xFEFF, 0xD800..0xDFFF)
        for (v in 0..0x3_0000) {
            val expect = escaped.any { v in it }
            assertEquals(expect, Display.isEscaped(v), Integer.toHexString(v))
            val s = String(Character.toChars(v))
            assertEquals(expect, Display.escape(s) != s, Integer.toHexString(v))
        }
        // A lone surrogate (which a Kotlin String, unlike a Swift one, can hold) is escaped as TypeScript does.
        assertEquals("a\\u{D800}b", Display.escape("a\uD800b"))
        assertEquals("\\u{DC00}", Display.escape("\uDC00"))
        assertEquals("😀", Display.escape("😀"))
    }

    /** §3.1 template hash input: text alone, or JCS of the extended members. */
    @Test
    fun templateSha256() {
        for ((name, v) in vectors("template-sha256")) {
            val t = v("inputs")("template")
            val links = t["links"]?.arrayValue?.map { TemplateLink(it("label").s, it("url").s) }
            val input = Templates.hashInput(t("text").s, t["elide"]?.arrayValue?.map { it.s }, t["note"]?.stringValue, links, t["link_hosts"]?.arrayValue?.map { it.s })!!
            assertEquals(v("expected")("hash_input").s, input, name)
            assertEquals(v("expected")("sha256").s, Digest.sha256Hex(input), name)
        }
    }

    /** The JSON resource is a faithful port of `@signeto/protocol` builtinRegistries. */
    @Test
    fun builtinRegistriesMatchTypeScript() {
        val want = TemplateRegistry.listFromJson(fixture("builtin-registries.json"))!!
        assertFalse(Templates.builtinRegistries.isEmpty())
        assertEquals(want, Templates.builtinRegistries)
        for (r in Templates.builtinRegistries) {
            for (t in r.templates) {
                assertEquals(t.sha256, t.computedSha256, t.templateId)
                assertNull(Templates.linksError(t), t.templateId)
            }
        }
        assertEquals(3, Templates.find(Templates.builtinRegistries, "github.merge_pull_request", 2)?.links?.size)
        // and the resource is byte-identical to the Swift package's
        val swift = java.io.File(Paths.public, "ios/Sources/SignetoSign/Resources/builtin-registries.json").readBytes()
        val kotlin = Templates::class.java.getResourceAsStream("/dev/signeto/sign/builtin-registries.json")!!.use { it.readBytes() }
        assertTrue(swift.contentEquals(kotlin), "copy public/ios/Sources/SignetoSign/Resources/builtin-registries.json to src/main/resources/dev/signeto/sign/")
    }

    @Test
    fun templateSourceOnlyWhenPinned() {
        val text = "Rotate {key} in {vault}"
        val builtin = Templates.builtinRegistries.size
        val src = TemplateSource("acme.rotate_key", 3, text, Templates.sha256(text), elide = emptyList())
        val pin = TemplatePin("acme.rotate_key", 3, Templates.sha256(text))
        assertEquals(builtin, Templates.registries(src, emptyList()).size)
        assertEquals(builtin + 1, Templates.registries(src, listOf(pin)).size)
        // text that does not hash to its claimed sha256
        val lying = TemplateSource(src.templateId, 3, "Rotate {key}", src.sha256)
        assertEquals(builtin, Templates.registries(lying, listOf(pin)).size)
        // pinned at another version
        val v2 = TemplatePin("acme.rotate_key", 2, src.sha256)
        assertEquals(builtin, Templates.registries(src, listOf(v2)).size)
    }

    /** The pin covers elide: a relay cannot hide a field by adding it to a pinned text-only template_source. */
    @Test
    fun templateSourceElideCoveredByPin() {
        val text = "Rotate {key} in {vault}"
        val builtin = Templates.builtinRegistries.size
        val textOnlyPin = TemplatePin("acme.rotate_key", 3, Templates.sha256(text))
        val added = TemplateSource("acme.rotate_key", 3, text, Templates.sha256(text), elide = listOf("force"))
        assertEquals(builtin, Templates.registries(added, listOf(textOnlyPin)).size)
        // pinned with the elide, it verifies
        val withElide = Template.computed("acme.rotate_key", 3, text, elide = listOf("force"))
        assertNotEquals(Templates.sha256(text), withElide.sha256)
        val src = TemplateSource("acme.rotate_key", 3, text, withElide.sha256, elide = listOf("force"))
        assertEquals(withElide, Templates.registries(src, listOf(TemplatePin("acme.rotate_key", 3, withElide.sha256))).last().templates.first())
        // an empty elide is absent: a text-only pin still matches
        val empty = TemplateSource("acme.rotate_key", 3, text, Templates.sha256(text), elide = emptyList())
        assertEquals(builtin + 1, Templates.registries(empty, listOf(textOnlyPin)).size)
    }

    /** The pin covers links: a relay cannot add, change or drop a link of a pinned template_source. */
    @Test
    fun templateSourceLinksCoveredByPin() {
        val text = "Rotate {key} in {vault}"
        val builtin = Templates.builtinRegistries.size
        val links = listOf(TemplateLink("Open vault", "https://vault.example.com/{vault}/keys/{key}"))
        val good = Template.computed("acme.rotate_key", 4, text, links = links, linkHosts = listOf("vault.example.com"))
        val pin = TemplatePin(good.templateId, 4, good.sha256)
        assertNotEquals(Templates.sha256(text), good.sha256)
        val src = TemplateSource(good.templateId, 4, text, good.sha256, elide = emptyList(), links = links, linkHosts = listOf("vault.example.com"))
        assertEquals(good, Templates.registries(src, listOf(pin)).last().templates.first())
        for (forged in listOf(
            TemplateSource(good.templateId, 4, text, good.sha256, links = listOf(TemplateLink("Open vault", "https://vault.example.com/{vault}")), linkHosts = listOf("vault.example.com")),
            TemplateSource(good.templateId, 4, text, good.sha256, links = links, linkHosts = listOf("vault.example.com", "evil.example")),
            TemplateSource(good.templateId, 4, text, good.sha256),
        )) {
            assertEquals(builtin, Templates.registries(forged, listOf(pin)).size)
        }
    }

    /** A member that cannot be canonicalized (a lone surrogate) never yields a hash that matches. */
    @Test
    fun uncanonicalizableTemplateNeverMatches() {
        val t = Template.computed("a.b", 1, "x {k}", note = "\uD800")
        assertEquals("", t.sha256)
        assertFalse(t.hashMatches)
        assertEquals("", Templates.sha256("\uD800"))
        assertEquals("", Templates.sha256("\uD800", null, null, null, null))
        assertFalse(timingSafeEqual("\uD800", "?"))
    }

    /** `template_source` as the relay sends it decodes to the same template. */
    @Test
    fun templateSourceFromJson() {
        val links = listOf(TemplateLink("Open vault", "https://vault.example.com/{vault}/keys/{key}"))
        val good = Template.computed("acme.rotate_key", 4, "Rotate {key} in {vault}", note = "n", links = links, linkHosts = listOf("vault.example.com"))
        assertEquals(good, TemplateSource.fromJson(good.json)!!.template)
        assertEquals(good, Template.fromJson(JsonParser.parse(Jcs.canonicalize(good.json))))
        assertNull(TemplateSource.fromJson(JsonValue.obj("template_id" to str("x"), "template_version" to JsonValue.of(1.5), "text" to str("t"), "sha256" to str("s"))))
        assertNull(TemplateSource.fromJson(JsonValue.obj("template_id" to str("x"), "template_version" to JsonValue.of(1), "text" to str("t"), "sha256" to str("s"), "elide" to str("k"))))
    }
}

class ReceiptVectorTests {
    @Test
    fun signingInput() {
        for ((name, v) in vectors("receipts/signing-input")) {
            val i = v("inputs")
            val si = Receipts.signingInput(i("canonical_bytes_sha256").s, Decision.fromWire(i("decision").s)!!, i["reason"]?.stringValue, i("signed_at").s)
            assertEquals(v("expected")("signing_input").s, si, name)
            assertEquals(v("expected")("webauthn_challenge").s, Base64Url.encode(Receipts.webauthnChallenge(si)), name)
        }
    }

    private fun policy(v: JsonValue?): WebAuthnPolicy? =
        v?.let { WebAuthnPolicy(it("allowed_origins").arrayValue!!.map { o -> o.s }, it("rp_id").s, it("require_user_verified").boolValue!!) }

    /** Positive ES256, Ed25519 and WebAuthn receipts and every negative code the TS verifier reports. */
    @Test
    fun receipts() {
        for ((name, v) in vectors("receipts")) {
            val i = v("inputs")
            val r = Receipts.verify(
                i("receipt"), canonicalBytes = i("canonical_bytes").s, issuedAt = i("issued_at").s, expiresAt = i("expires_at").s,
                devicePublicKey = i("device_public_key").jwk()!!, webauthn = policy(i["webauthn_policy"]),
            )
            val e = v("expected")
            when (r) {
                is Outcome.Ok -> {
                    assertEquals("ok", e["verify"]?.s, name)
                    e["signing_input"]?.stringValue?.let { assertEquals(it, r.value.signingInput, name) }
                }
                is Outcome.Err -> {
                    assertEquals("error", e["verify"]?.s, "$name: ${r.error}")
                    assertEquals(e["code"]?.s, r.error.code, name)
                }
            }
        }
    }

    /** Fixtures/receipts-es256.json: ES256 receipts with a unicode reason, signed by the TS package. */
    @Test
    fun typeScriptSignedEs256Receipts() {
        val f = fixture("receipts-es256.json")
        for (c in f("cases").arrayValue!!) {
            val r = Receipts.verify(c("receipt"), canonicalBytes = f("canonical_bytes").s, issuedAt = f("issued_at").s, expiresAt = f("expires_at").s, devicePublicKey = f("device_public_key").jwk()!!)
            when (r) {
                is Outcome.Ok -> {
                    assertEquals("ok", c("verify").s, c("description").s)
                    assertEquals(c("signing_input").s, r.value.signingInput)
                }
                is Outcome.Err -> assertEquals(c("verify").s, r.error.code, c("description").s)
            }
        }
    }

    /** Sign with a software P-256 key (the vector device key) and verify with the TS-equivalent rules. */
    @Test
    fun kotlinSignedReceiptsVerify() = runBlocking {
        val signer = vectorP256Signer("device-es256")
        val v = vectors("receipts").first { it.first == "es256-approve.json" }.second
        val bytes = v("inputs")("canonical_bytes").s
        val issued = v("inputs")("issued_at").s
        val expires = v("inputs")("expires_at").s
        val key = v("inputs")("device_public_key").jwk()!!
        assertEquals(key, signer.publicKey)
        for ((decision, reason) in listOf(Decision.APPROVE to null, Decision.DENY to "Not during market hours", Decision.DENY to "Zoë says 不 😀 \"no\"\n", Decision.APPROVE to "")) {
            val r = Receipts.sign("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", bytes, decision, reason, "jason", "2026-11-05T18:05:00.000Z", signer)
            assertEquals(key.deviceId, r.deviceId)
            assertEquals(SignatureAlgorithm.ES256, r.alg)
            assertEquals(86, r.signature.length)
            assertNull(Receipts.schemaProblem(r.json))
            val body = JsonParser.parse(r.body())
            assertTrue(Receipts.verify(body, canonicalBytes = bytes, issuedAt = issued, expiresAt = expires, devicePublicKey = key) is Outcome.Ok, "$decision $reason")
            // flipping the decision breaks it
            val flipped = r.copy(decision = if (decision == Decision.APPROVE) Decision.DENY else Decision.APPROVE)
            assertTrue(Receipts.verify(flipped.json, canonicalBytes = bytes, issuedAt = issued, expiresAt = expires, devicePublicKey = key) is Outcome.Err, "flipped decision verified")
        }
        assertThrows(ReceiptBuildException.ReasonTooLong::class.java) {
            runBlocking { Receipts.sign("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", bytes, Decision.DENY, "é".repeat(257), "jason", "2026-11-05T18:05:00.000Z", signer) }
        }
        assertEquals(512, Utf8.length(Receipts.clampReason("é".repeat(300))))
        assertEquals(512, Utf8.length(Receipts.clampReason("😀" + "a".repeat(509)))) // 4 + 509 = 513 → drop the last 'a'
        assertEquals("😀" + "a".repeat(508), Receipts.clampReason("😀" + "a".repeat(509)))
    }
}

class ApprovalRequestVectorTests {
    private fun pinned(v: JsonValue): Map<String, PublicJwk> = v.objectValue!!.entries.associate { it.first to it.second.jwk()!! }

    private fun verify(req: JsonValue, pins: Map<String, PublicJwk>) =
        ApprovalRequests.verify(req("action_id").s, req("canonical_bytes").s, req("expires_at").s, req("gateway_signature").s, pins)

    @Test
    fun approvalRequests() {
        for ((name, v) in vectors("approval-request")) {
            val req = v("inputs")("request")
            val e = v("expected")
            when (val r = verify(req, pinned(v("inputs")("pinned")))) {
                is Outcome.Ok -> {
                    assertEquals("ok", e["verify"]?.s, name)
                    val (f, _) = ApprovalRequests.fields(req("action_id").s, req("canonical_bytes").s, req("expires_at").s)!!
                    assertEquals(e("signing_input").s, ApprovalRequests.signingInput(f), name)
                }
                is Outcome.Err -> {
                    assertEquals("error", e["verify"]?.s, "$name: ${r.error}")
                    assertEquals(e["code"]?.s, r.error.code, name)
                }
            }
        }
    }

    @Test
    fun es256Gateway() {
        val f = fixture("approval-request-es256.json")
        val ok = (verify(f("request"), pinned(f("pinned"))) as? Outcome.Ok)?.value ?: fail("ES256 gateway signature rejected")
        assertEquals(ok.gatewayId, ok.encoded.action.requester.gatewayId)
        val (fields, _) = ApprovalRequests.fields(f("request")("action_id").s, f("request")("canonical_bytes").s, f("request")("expires_at").s)!!
        assertEquals(f("signing_input").s, ApprovalRequests.signingInput(fields))
    }

    @Test
    fun tamperedSignature() {
        val v = vectors("approval-request").first { it.first == "ok.json" }.second
        val req = v("inputs")("request").objectValue!!
        val sig = req["gateway_signature"]!!.s.toCharArray()
        sig[10] = if (sig[10] == 'A') 'B' else 'A'
        val pins = pinned(v("inputs")("pinned"))
        assertTrue(verify(JsonValue.Obj(req.with("gateway_signature", str(String(sig)))), pins) is Outcome.Err, "tampered signature accepted")
        assertEquals(
            Outcome.Err(ApprovalRequestVerifyCode.GATEWAY_SIGNATURE_INVALID),
            verify(JsonValue.Obj(req.with("gateway_signature", str("not base64url!"))), pins),
        )
    }
}

class IdsVectorTests {
    @Test
    fun thumbprints() {
        for ((name, v) in vectors("ids")) {
            val i = v("inputs")
            val e = v("expected")
            assertEquals(e("gateway_id").s, i("gateway").jwk()!!.gatewayId, name)
            assertEquals(e("device_es256_id").s, i("device_es256").jwk()!!.deviceId, name)
            assertEquals(e("device_ed25519_id").s, i("device_ed25519").jwk()!!.deviceId, name)
            assertEquals(e("gateway_fingerprint").s, i("gateway").jwk()!!.fingerprint, name)
            assertEquals(e("device_es256_fingerprint").s, i("device_es256").jwk()!!.fingerprint, name)
        }
    }

    @Test
    fun jwkParsing() {
        val good = JsonValue.obj("kty" to str("EC"), "crv" to str("P-256"), "x" to str("Of8uj529uXHN5vuSVnd9npjQoo3omxCJUxXVYt_WXS8"), "y" to str("ymLO0QWGOus6jSc_kOwiyELsXG3f1Gf9MmJQczzivw4"))
        assertNotNull(PublicJwk.parse(good))
        assertNull(PublicJwk.parse(JsonValue.Obj(good.objectValue!!.with("d", str("g7G1o63IinFK7UujHq2908mCEXCVZ1M3TTpX_G7wIiI")))), "private member must be refused")
        val extra = JsonValue.Obj(good.objectValue!!.with("kid", str("x")))
        assertNull(PublicJwk.parse(extra))
        assertNotNull(PublicJwk.parse(extra, allowExtraMembers = true))
        assertNull(PublicJwk.parse(JsonValue.obj("kty" to str("EC"), "crv" to str("P-384"), "x" to str("a"), "y" to str("b"))))
        assertNull(PublicJwk.parse(JsonValue.obj("kty" to str("OKP"), "crv" to str("X25519"), "x" to str("nuh3Kz3y1tS5JZzEAq1tfujPokfE_BySBKwiGzdYA28"))))
        assertTrue(Identifiers.isActionId("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C"))
        assertFalse(Identifiers.isActionId("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5I"))
        assertFalse(Identifiers.isGatewayId("gw_jtl8uXbA19Z9r2ZrSBMGyfEddtXMM_d4wo1k0O_GMrs\n"))
    }
}

class RelayAuthVectorTests {
    private fun body(v: JsonValue?): ByteArray? = v?.stringValue?.toByteArray(Charsets.UTF_8)

    @Test
    fun relayAuth() {
        for ((name, v) in vectors("relay-auth")) {
            val i = v("inputs")
            val e = v("expected")
            e["body_sha256"]?.stringValue?.let { assertEquals(it, RelayAuth.bodySha256(body(i["body"])), name) }
            e["signing_input"]?.stringValue?.let {
                assertEquals(it, RelayAuth.signingInput(i("method").s, i("path").s, i("ts").s, RelayAuth.bodySha256(body(i["body"]))), name)
            }
            val r = RelayAuth.verify(i["header"]?.stringValue, i("method").s, i("path").s, body(i["body"]), i("public_key").jwk()!!, i("now").numberValue!!.toLong())
            when (r) {
                is Outcome.Ok -> {
                    assertEquals("ok", e["verify"]?.s, name)
                    e["key_id"]?.stringValue?.let { assertEquals(it, r.value.keyId, name) }
                }
                is Outcome.Err -> {
                    assertEquals("error", e["verify"]?.s, "$name: ${r.error}")
                    assertEquals(e["code"]?.s, r.error.code, name)
                }
            }
        }
    }

    /**
     * The device path: sign `Signeto-Device` with the ES256 vector key, verify with the TS-equivalent rules.
     * (ES256 is randomised, so the header is verified rather than compared with the vector's.)
     */
    @Test
    fun deviceHeaderSigning() = runBlocking {
        val v = vectors("relay-auth").first { it.first == "device-es256-post-with-body.json" }.second
        val i = v("inputs")
        val signer = vectorP256Signer("device-es256")
        val now = i("now").numberValue!!.toLong()
        val h = RelayAuth.deviceHeader(i("method").s, i("path").s, body(i["body"]), i("ts").s, signer)
        assertTrue(h.startsWith("Signeto-Device ${v("expected")("key_id").s}.${i("ts").s}."))
        assertTrue(RelayAuth.verify(h, i("method").s, i("path").s, body(i["body"]), signer.publicKey, now, listOf(RelayAuthScheme.DEVICE)) is Outcome.Ok)
        // the signature covers the query string, method and body
        assertEquals(Outcome.Err(RelayAuthError.INVALID_SIGNATURE), RelayAuth.verify(h, "PUT", i("path").s, body(i["body"]), signer.publicKey, now))
        assertEquals(Outcome.Err(RelayAuthError.INVALID_SIGNATURE), RelayAuth.verify(h, i("method").s, i("path").s + "?x=1", body(i["body"]), signer.publicKey, now))
        for ((method, path) in listOf("get" to "/v1", "GET" to "https://x/v1", "GET" to "/v1#f", "GET" to "/v1 x", "GET" to "/v1 ")) {
            assertThrows(RelayAuthException::class.java) { RelayAuth.signingInput(method, path, i("ts").s, RelayAuth.EMPTY_BODY_SHA256) }
        }
    }
}
