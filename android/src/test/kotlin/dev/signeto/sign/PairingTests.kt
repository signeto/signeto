// Pairing, device side, against the Swift package's Fixtures/pairing.json (generated with @signeto/protocol
// following §5.2–§5.4; the shared vectors have no `pairing/` set yet).
package dev.signeto.sign

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class PairingTests {
    private val f = fixture("pairing.json")
    private val now = Timestamp.parse("2026-11-07T12:00:00.000Z")!!

    private fun qr(): QrPayload = Pairing.parseQr(f("qr_uri").s, now).valueOrNull ?: fail("QR did not parse")

    private fun device(): PublicJwk = f("device_public_key").jwk()!!

    @Test
    fun qrParsing() {
        val q = qr()
        assertEquals(f("gateway_id").s, q.gatewayId)
        assertEquals(f("gateway_fingerprint").s, q.gatewayFingerprint)
        assertEquals("home-01", q.gatewayName)
        assertEquals("https://api.signeto.dev", q.relay)
        assertEquals(f("qr_manual").s, q.manualString)
        assertEquals(f("qr_uri").s, q.uri)
        // the bare manual string, with surrounding whitespace
        assertEquals(Outcome.Ok(q), Pairing.parseQr("  ${f("qr_manual").s}\n", now))
        // expiry: valid up to and including expires_at, expired one millisecond later
        val exp = Timestamp.parse(f("qr")("expires_at").s)!!
        assertEquals(Outcome.Ok(q), Pairing.parseQr(f("qr_uri").s, exp))
        assertEquals(Outcome.Err(QrParseError.EXPIRED), Pairing.parseQr(f("qr_uri").s, exp + 1))
        // the code stays out of toString (logs, crash reports)
        assertFalse(q.toString().contains(q.code))
    }

    @Test
    fun qrRejections() {
        fun enc(mutate: (JsonObject) -> JsonObject): String = Base64Url.encode(Jcs.canonicalBytes(JsonValue.Obj(mutate(f("qr").objectValue!!))))
        val malformed = Outcome.Err(QrParseError.MALFORMED)
        assertEquals(Outcome.Err(QrParseError.VERSION_UNSUPPORTED), Pairing.parseQr(enc { it.with("v", JsonValue.of(2)) }, now))
        assertEquals(malformed, Pairing.parseQr(enc { it.with("extra", JsonValue.of(1)) }, now))
        assertEquals(malformed, Pairing.parseQr(enc { it.with("code", str("short")) }, now))
        assertEquals(malformed, Pairing.parseQr(enc { it.with("gateway_name", str("")) }, now))
        assertEquals(malformed, Pairing.parseQr(enc { it.with("expires_at", str("2026-11-07T12:10:00Z")) }, now))
        assertEquals(malformed, Pairing.parseQr(enc { o -> o.with("gateway_public_key", JsonValue.Obj(o["gateway_public_key"]!!.objectValue!!.with("d", str("x")))) }, now))
        assertEquals(malformed, Pairing.parseQr("signeto://pair?x=1", now))
        assertEquals(malformed, Pairing.parseQr("signeto://pair?d", now))
        assertEquals(malformed, Pairing.parseQr("signeto://pair?d=", now))
        // §5.1 (SIG-92 N1): a small-order Ed25519 gateway key (here the identity point) is refused.
        val identity = Base64Url.encode(byteArrayOf(1) + ByteArray(31))
        assertEquals(malformed, Pairing.parseQr(enc { it.with("gateway_public_key", JsonValue.obj("kty" to str("OKP"), "crv" to str("Ed25519"), "x" to str(identity))) }, now))
        assertEquals(malformed, Pairing.parseQr("not base64!", now))
    }

    @Test
    fun queryParameter() {
        assertEquals("abc", Pairing.queryParameter("signeto://pair?d=abc", "d"))
        assertEquals("abc", Pairing.queryParameter("signeto://pair?x=1&d=abc&d=zzz", "d"))
        assertEquals("a/b", Pairing.queryParameter("signeto://pair?d=a%2Fb", "d"))
        assertEquals("a+b", Pairing.queryParameter("signeto://pair?d=a+b", "d"))
        assertEquals("a b", Pairing.queryParameter("signeto://pair?d=a b", "d"))
        assertNull(Pairing.queryParameter("signeto://pair", "d"))
        assertNull(Pairing.queryParameter("signeto://pair?d=%zz", "d"))
        assertEquals("abc", Pairing.queryParameter("signeto://pair?d=abc#frag", "d"))
        // junk in another parameter does not hide `d` (URLComponents finds it too)
        for (junk in listOf("x=a b", "x={}", "x=|", "x=%zz")) assertEquals("AAA", Pairing.queryParameter("signeto://pair?$junk&d=AAA", "d"), junk)
    }

    @Test
    fun idsProofAndClaim() {
        val q = qr()
        val device = device()
        assertEquals(f("device_id").s, device.deviceId)
        assertEquals(f("pairing_id").s, q.pairingId)
        assertEquals(f("code_hash").s, Pairing.codeHash(q.code))
        assertEquals(f("proof_signing_input").s, Pairing.proofSigningInput(q.gatewayId, device.deviceId, device))
        assertEquals(f("proof").s, Pairing.proof(q.code, q.gatewayId, device.deviceId, device))

        val claim = Pairing.claim(q, device, "ios", "iPhone", null, false, now).valueOrNull ?: fail("claim")
        assertEquals(f("pairing_id").s, claim.pairingId)
        assertEquals(f("proof").s, claim.body["proof"]?.s)
        assertEquals(device.json, claim.body("device")["public_key"])
        assertEquals(JsonValue.Null, claim.body("device")["attestation"])
        assertEquals(str("ios"), claim.body("device")["platform"])
        assertNotEquals(f("proof").s, f("substituted_key_proof").s)
        val exp = Timestamp.parse(q.expiresAt)!!
        assertEquals(Outcome.Err(QrParseError.EXPIRED), Pairing.claim(q, device, "ios", "iPhone", null, false, exp + 1))
    }

    /** §5.3 proof v2 (SIG-104): `device.proof_v2` next to the v1 proof, covering name, platform and attestation. */
    @Test
    fun proofV2() {
        val q = qr()
        val device = device()
        val v = f("proof_v2")
        assertEquals(v("signing_input").s, Pairing.proofV2SigningInput(q.gatewayId, device.deviceId, device, "iPhone", "ios", null))
        val claim = Pairing.claim(q, device, "ios", "iPhone", null, false, now).valueOrNull!!
        assertEquals(v("proof").s, claim.body("device")["proof_v2"]?.s)
        assertEquals(f("proof").s, claim.body["proof"]?.s, "v1 stays, so a gateway from before v2 still pairs")
        // A relay that renames the device cannot keep the proof valid.
        assertNotEquals(v("proof").s, v("renamed_proof").s)

        val att = Attestation(v("attestation")("format").s, v("attestation")("data").s)
        assertEquals(v("attestation_sha256").s, Pairing.attestationSha256(att))
        assertNull(Pairing.attestationSha256(null))
        assertEquals(v("signing_input_attested").s, Pairing.proofV2SigningInput(q.gatewayId, device.deviceId, device, "iPhone", "ios", att))
        val attested = Pairing.claim(q, device, "ios", "iPhone", att, false, now).valueOrNull!!
        assertEquals(v("proof_attested").s, attested.body("device")["proof_v2"]?.s)

        // What iOS build 7 sent: v1 only.
        val legacy = Pairing.claim(q, device, "ios", "iPhone", null, false, now, proofV2 = false).valueOrNull!!
        assertNull(legacy.body("device")["proof_v2"])
        assertEquals(f("proof").s, legacy.body["proof"]?.s)
    }

    @Test
    fun confirmations() {
        val q = qr()
        val device = device()
        val approver = f("approver_id").s
        assertEquals(
            f("confirmation_signing_input_no_pins").s,
            Pairing.confirmationSigningInput(q.gatewayId, device.deviceId, q.pairingId, "2026-11-07T12:02:03.456Z", approver, emptyList()),
        )
        val pins = Pairing.parseTemplatesPinned(f["pins"])!!
        assertEquals(
            f("confirmation_signing_input_pins").s,
            Pairing.confirmationSigningInput(q.gatewayId, device.deviceId, q.pairingId, "2026-11-07T12:02:03.456Z", approver, pins),
        )

        for (c in f("confirmations").arrayValue!!) {
            val name = c("description").s
            when (val r = Pairing.acceptConfirmation(q, device, c("view")) ?: fail("$name: not confirmed")) {
                is Outcome.Ok -> {
                    val pinned = r.value
                    assertEquals("ok", c("expected").s, name)
                    assertEquals(f("gateway_id").s, pinned.gatewayId)
                    assertEquals(q.gatewayPublicKey, pinned.gatewayPublicKey)
                    assertEquals(f("gateway_fingerprint").s, pinned.gatewayFingerprint)
                    assertEquals(f("device_fingerprint").s, pinned.deviceFingerprint)
                    assertEquals(Pairing.parseTemplatesPinned(c["pins"]), pinned.templatesPinned, name)
                    // the approver name comes from the signed confirmation (§5.3 point 7)
                    assertEquals(approver, pinned.approverId, name)
                    assertFalse(pinned.needsRepair)
                    // the record round-trips through its storage form
                    assertEquals(pinned, PinnedGateway.fromJson(JsonParser.parse(Jcs.canonicalize(pinned.json))))
                }
                is Outcome.Err -> assertEquals(c("expected").s, r.error.code, name)
            }
        }
        // still open: nothing to accept yet
        assertNull(Pairing.acceptConfirmation(q, device, JsonValue.obj("pairing_id" to str(q.pairingId), "status" to str("claimed"))))
        // every approver_id negative in the fixture is there
        val names = f("confirmations").arrayValue!!.map { it("description").s }
        assertTrue("relay dropped approver_id" in names)
        assertTrue("relay replaced approver_id with the account's approver id" in names)
    }

    @Test
    fun approverIdBounds() {
        assertTrue(Pairing.isValidApproverId("jason"))
        assertTrue(Pairing.isValidApproverId("a".repeat(64)))
        assertFalse(Pairing.isValidApproverId(""))
        assertFalse(Pairing.isValidApproverId("a".repeat(65)))
        assertFalse(Pairing.isValidApproverId("ja\u007Fson"))
        assertFalse(Pairing.isValidApproverId("ja\tson"))
    }

    /** A record stored before confirmations named the approver decodes with no approver: it needs re-pairing. */
    @Test
    fun pinWithoutApproverDecodesAsNeedingRepair() {
        val q = qr()
        val pinned = (Pairing.acceptConfirmation(q, device(), f("confirmations").arrayValue!![0]("view")) as? Outcome.Ok)?.value ?: fail("first confirmation")
        val o = pinned.json.objectValue!!
        assertEquals(str(f("approver_id").s), o["approver_id"])
        val old = PinnedGateway.fromJson(JsonValue.Obj(o.without("approver_id")))!!
        assertNull(old.approverId)
        assertTrue(old.needsRepair)
        assertEquals(pinned.gatewayId, old.gatewayId)
        // a record with a member missing or mistyped does not decode
        assertNull(PinnedGateway.fromJson(JsonValue.Obj(o.without("relay"))))
        assertNull(PinnedGateway.fromJson(JsonValue.Obj(o.with("templates_pinned", str("x")))))
    }

    /** §5.3 point 3: an `android-key` attestation's data is base64url(JCS {"x5c": [...]}) of the chain, leaf first. */
    @Test
    fun androidKeyAttestationData() {
        val data = Pairing.androidKeyAttestationData(listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))
        val decoded = String(Base64Url.decode(data)!!, Charsets.UTF_8)
        assertEquals("{\"x5c\":[\"AQID\",\"BAU\"]}", decoded)
        assertEquals("android-key", Pairing.ANDROID_KEY_ATTESTATION_FORMAT)
    }
}
