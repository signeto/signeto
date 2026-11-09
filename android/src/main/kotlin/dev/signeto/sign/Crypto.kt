// The primitives under Keys.kt and Signer.kt, kept in one place to audit:
//   ES256: ECDSA P-256 over SHA-256 through JCA (`SHA256withECDSA`), signatures converted between the protocol's raw
//          r||s (64 bytes) and JCA's DER (Der.rawToDer / Der.derToRaw);
//   Ed25519: BouncyCastle's lightweight RFC 8032 code (org.bouncycastle.math.ec.rfc8032), no JCA provider registered;
//   HMAC-SHA256: JCA.
// SignetoSign (Swift) uses CryptoKit for the same operations.
package dev.signeto.sign

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.math.ec.rfc8032.Ed25519 as BcEd25519

/** NIST P-256 (secp256r1). */
object P256 {
    internal val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    internal val a = BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
    internal val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    internal val n = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val gx = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    private val gy = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

    /** The named-curve parameters from the platform (what Android's providers expect), else the explicit ones. */
    val params: ECParameterSpec by lazy {
        try {
            AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec("secp256r1"))
                getParameterSpec(ECParameterSpec::class.java)
            }
        } catch (_: Exception) {
            ECParameterSpec(EllipticCurve(ECFieldFp(p), a, b), ECPoint(gx, gy), n, 1)
        }
    }

    /** True when (x, y) is a point on the curve (coordinates in range, y² = x³ + ax + b mod p). */
    fun isOnCurve(x: BigInteger, y: BigInteger): Boolean {
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        val lhs = y.multiply(y).mod(p)
        val rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p)
        return lhs == rhs
    }

    /** A JCA public key from 32-byte big-endian coordinates; null when they are not a point on the curve. */
    fun publicKey(x: ByteArray, y: ByteArray): ECPublicKey? {
        if (x.size != 32 || y.size != 32) return null
        val bx = BigInteger(1, x)
        val by = BigInteger(1, y)
        if (!isOnCurve(bx, by)) return null
        return try {
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(bx, by), params)) as ECPublicKey
        } catch (_: Exception) {
            null
        }
    }

    /** ECDSA P-256 over SHA-256(data); `signature` is raw r||s. Any malformed input is false, never a throw. */
    fun verify(x: ByteArray, y: ByteArray, signature: ByteArray, data: ByteArray): Boolean {
        if (signature.size != 64) return false
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        if (r.signum() == 0 || r >= n || s.signum() == 0 || s >= n) return false
        val key = publicKey(x, y) ?: return false
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(data)
                verify(Der.rawToDer(signature))
            }
        } catch (_: Exception) {
            false
        }
    }

    /** ECDSA P-256 over SHA-256(data) with a JCA private key (software or Android Keystore); raw r||s. */
    fun sign(key: PrivateKey, data: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(data)
            sign()
        }
        return Der.derToRaw(der) ?: throw SignerException.BadSignatureLength
    }

    /** A JCA private key for scalar `d` (32 bytes, big-endian). */
    fun privateKey(d: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, d), params))

    /** The public point d·G as 32-byte x and y. */
    fun publicPoint(d: ByteArray): Pair<ByteArray, ByteArray> {
        val k = BigInteger(1, d)
        require(k.signum() > 0 && k < n) { "scalar out of range" }
        val curve = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256r1")
        val q = curve.g.multiply(k).normalize()
        return fixed32(q.affineXCoord.toBigInteger()) to fixed32(q.affineYCoord.toBigInteger())
    }

    /** A big-endian unsigned integer as exactly 32 bytes. */
    internal fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size == 33 && raw[0] == 0.toByte() -> raw.copyOfRange(1, 33)
            raw.size < 32 -> ByteArray(32 - raw.size) + raw
            else -> throw IllegalArgumentException("integer wider than 32 bytes")
        }
    }
}

/** ECDSA signature encodings: raw r||s (protocol) ⇄ DER `SEQUENCE { INTEGER r, INTEGER s }` (JCA, Android Keystore). */
object Der {
    /** 64-byte r||s → DER. */
    fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64) { "raw ECDSA signature must be 64 bytes" }
        fun int(bytes: ByteArray): ByteArray {
            var i = 0
            while (i < bytes.size - 1 && bytes[i] == 0.toByte()) i++
            var v = bytes.copyOfRange(i, bytes.size)
            if (v[0].toInt() and 0x80 != 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** DER → 64-byte r||s; null when it is not a DER ECDSA signature with r and s of at most 32 bytes. */
    fun derToRaw(der: ByteArray): ByteArray? {
        fun u(i: Int) = der[i].toInt() and 0xFF
        if (der.size < 8 || u(0) != 0x30) return null
        // short-form lengths only: a P-256 signature is at most 72 bytes
        if (u(1) != der.size - 2) return null
        var i = 2
        val out = ByteArray(64)
        for (half in 0..1) {
            if (i + 2 > der.size || u(i) != 0x02) return null
            val len = u(i + 1)
            i += 2
            if (len == 0 || len > 33 || i + len > der.size) return null
            var v = der.copyOfRange(i, i + len)
            if (v[0].toInt() and 0x80 != 0) return null // negative
            if (v.size > 1 && v[0] == 0.toByte() && v[1].toInt() and 0x80 == 0) return null // non-minimal
            if (v.size == 33) {
                if (v[0] != 0.toByte()) return null // wider than 32 bytes
                v = v.copyOfRange(1, 33)
            }
            v.copyInto(out, half * 32 + (32 - v.size))
            i += len
        }
        return if (i == der.size) out else null
    }
}

/** Ed25519 (PureEdDSA, RFC 8032) through BouncyCastle's lightweight implementation. */
object Ed25519 {
    /**
     * Verify a 64-byte signature over `data` with a 32-byte public key. Small-order keys are refused by the caller.
     *
     * BouncyCastle checks the cofactored equation [8][S]B = [8]R + [8][k]A; CryptoKit and Node (OpenSSL) check the
     * cofactorless [S]B = R + [k]A. They differ only when A or R has a small-order component, which an honest signer
     * never produces. Requiring both A and R to be in the prime-order subgroup makes the two agree, so a crafted key or
     * signature cannot verify here and fail on iOS or in the gateway (or the reverse in our favour: we only refuse more).
     */
    fun verify(publicKey: ByteArray, signature: ByteArray, data: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            BcEd25519.validatePublicKeyFull(publicKey, 0) &&
                BcEd25519.validatePublicKeyFull(signature, 0) && // R, the first 32 bytes, is a point encoded the same way
                BcEd25519.verify(signature, 0, publicKey, 0, data, 0, data.size)
        } catch (_: Exception) {
            false
        }
    }

    /** The 32-byte public key of a 32-byte seed. */
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        return ByteArray(32).also { BcEd25519.generatePublicKey(seed, 0, it, 0) }
    }

    /** Sign `data` with a 32-byte seed (gateways, the demo, tests; a device signs with ES256). */
    fun sign(seed: ByteArray, data: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        return ByteArray(64).also { BcEd25519.sign(seed, 0, data, 0, data.size, it, 0) }
    }
}

internal object Hmac {
    fun sha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }
}
