package dev.signeto.sign

import java.security.Signature
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SignerTests {
    @Test
    fun softwareSignerProducesRawEs256() = runBlocking {
        val s = SoftwareP256Signer.generate()
        val data = "hello".toByteArray()
        val sig = s.sign(data)
        assertEquals(64, sig.size)
        assertTrue(s.publicKey.verify(sig, data))
        assertFalse(s.publicKey.verify(sig, "hellO".toByteArray()))
        // raw r||s is the DER signature JCA verifies over SHA-256(data)
        val p = s.publicKey as PublicJwk.P256
        val jca = P256.publicKey(Base64Url.decode(p.x)!!, Base64Url.decode(p.y)!!)!!
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(jca); update(data); verify(Der.rawToDer(sig)) })
        assertEquals(SignatureAlgorithm.ES256, s.algorithm)
        assertFalse(s.isHardwareBacked)
        assertTrue(Identifiers.isDeviceId(s.deviceId))
        // a stored raw scalar reopens the same key
        assertEquals(s.publicKey, SoftwareP256Signer.fromRaw(s.rawPrivateKey).publicKey)
    }

    @Test
    fun vectorKeyLoads() {
        val s = vectorP256Signer("device-es256")
        assertEquals("dev_a0_Fuycw9mkJA94-PL1NxHX3GQN6Q_J3KLGwoNfjX2Q", s.deviceId)
        assertThrows(SignerException::class.java) {
            SoftwareP256Signer.fromJwkD("g7G1o63IinFK7UujHq2908mCEXCVZ1M3TTpX_G7wIiI", PublicJwk.P256("Of8uj529uXHN5vuSVnd9npjQoo3omxCJUxXVYt_WXS8", "AAAA"))
        }
        assertThrows(SignerException::class.java) { SoftwareP256Signer.fromRaw(ByteArray(32)) }
        assertThrows(SignerException::class.java) { SoftwareP256Signer.fromRaw(ByteArray(31) { 1 }) }
    }

    @Test
    fun ed25519Verification() {
        val k = vectorKey("gateway-ed25519")
        val seed = Base64Url.decode(k("d").s)!!
        val pub = k.publicHalf()!!
        assertEquals(pub, PublicJwk.ed25519(Ed25519.publicKey(seed)))
        val sig = Ed25519.sign(seed, "x".toByteArray())
        assertTrue(pub.verify(sig, "x".toByteArray()))
        assertFalse(pub.verify(sig.copyOf(63), "x".toByteArray()))
        assertFalse(pub.verify(sig, "y".toByteArray()))
    }

    /**
     * BouncyCastle's cofactored check accepts these; CryptoKit and Node (cofactorless) refuse them, and so must we, or
     * a gateway with a crafted key could sign what Android accepts and iOS and the CLI reject. Message "m".
     */
    @Test
    fun ed25519RefusesTorsionLikeCryptoKitAndNode() {
        val msg = "m".toByteArray()
        // R plus an order-8 point, S recomputed
        val torsionR = PublicJwk.ed25519(Hex.decode("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")!!)
        assertFalse(torsionR.verify(Hex.decode("d32f8fe4bf7ce3d3aa2f6f6b97725fb11d74b9228078c4b409a6c841bc1973ebbe98c8af90a5ba0f6827690e9abe4e96c4d7ff370a21ac97298f87894faf780c")!!, msg))
        // mixed-order public key (A plus an order-8 point): not small-order, but never a valid key
        val mixed = PublicJwk.ed25519(Hex.decode("1f4f580e73ac208f06760190e9edc6f5916775dabd9c1cdca393175c2d6d1083")!!)
        assertFalse(mixed.isWeak)
        assertFalse(mixed.verify(Hex.decode("058030d4a08971a38d20eb455bad733e673d4b2d94e5c712a2447aa3b0020b2c9ecb4053a628e9887ce5b0d06cfc669482f0aef938af80425c61c797102b4d06")!!, msg))
        // honest keys and signatures still verify
        repeat(20) {
            val seed = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            val m = ByteArray(it * 7).also { java.security.SecureRandom().nextBytes(it) }
            assertTrue(PublicJwk.ed25519(Ed25519.publicKey(seed)).verify(Ed25519.sign(seed, m), m))
        }
    }

    @Test
    fun p256RefusesOffCurveAndOutOfRange() {
        val s = vectorP256Signer("device-es256")
        val p = s.publicKey as PublicJwk.P256
        val data = "x".toByteArray()
        val sig = s.signBlocking(data)
        assertTrue(s.publicKey.verify(sig, data))
        // y + 1 is not on the curve
        val y = Base64Url.decode(p.y)!!
        y[31] = (y[31] + 1).toByte()
        assertFalse(PublicJwk.P256(p.x, Base64Url.encode(y)).verify(sig, data))
        // r = 0, s = 0, and s = n are refused before JCA sees them
        assertFalse(s.publicKey.verify(ByteArray(64), data))
        val n = P256.fixed32(P256.n)
        assertFalse(s.publicKey.verify(sig.copyOfRange(0, 32) + n, data))
    }

    @Test
    fun derConversions() {
        repeat(200) {
            val raw = ByteArray(64).also { java.security.SecureRandom().nextBytes(it) }
            if (it % 3 == 0) raw.fill(0, 0, 5) // short r
            if (it % 5 == 0) raw[32] = 0x80.toByte() // s needs a sign byte
            assertArrayEquals(raw, Der.derToRaw(Der.rawToDer(raw)))
        }
        assertNull(Der.derToRaw(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01)))
        assertNull(Der.derToRaw(byteArrayOf(0x30, 0x06, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01))) // non-minimal r
        assertNull(Der.derToRaw(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x81.toByte(), 0x02, 0x01, 0x01))) // negative r
        // a 33-byte r whose first byte is not the sign byte is wider than 32 bytes, not a truncatable r
        assertNull(Der.derToRaw(byteArrayOf(0x30, 0x27, 0x02, 0x21, 0x01) + ByteArray(32) { 0x11 } + byteArrayOf(0x02, 0x02, 0x01, 0x01)))
    }

    @Test
    fun freezeBody() = runBlocking {
        val s = vectorP256Signer("device-es256")
        assertEquals("{\"frozen\":true,\"signed_at\":\"2026-11-07T12:00:00.000Z\"}", Freeze.signingInput(true, "2026-11-07T12:00:00.000Z"))
        val body = Freeze.body(false, "2026-11-07T12:00:00.000Z", s)
        val state = FreezeState.fromJson(
            JsonValue.obj("frozen" to JsonValue.of(false), "set_by_device_id" to str(s.deviceId), "signed_at" to str("2026-11-07T12:00:00.000Z"), "signature" to body("signature")),
        )!!
        assertTrue(state.verifies(s.publicKey))
        assertFalse(state.copy(frozen = true).verifies(s.publicKey))
    }
}
