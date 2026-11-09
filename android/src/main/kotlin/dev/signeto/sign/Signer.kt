// Device signing keys (docs/protocol.md §5.1). A device key signs receipts (§4.2) and freeze objects (§7.9);
// a software key may also sign relay requests (§7.1, `Signeto-Device`). A key that needs a biometric per
// signature (the Android Keystore key in the app) authenticates to the relay with a device session instead.
//
// The auditable signing path is short:
//   signing input (UTF-8 JCS) → DeviceSigner.sign(data) → ECDSA P-256 over SHA-256(data)
//   → raw r||s (64 bytes) → base64url (86 characters).
// Port of SignetoSign Signer.swift. Deliberate difference: `sign` is a suspend function, because on Android the
// hardware key is unlocked by a BiometricPrompt callback (one prompt per signature, see the app's BiometricSigner).
// The Secure Enclave and Keychain parts of the Swift file have no counterpart here: the Keystore signer lives in
// the app, next to the Android APIs it needs.
package dev.signeto.sign

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

interface DeviceSigner {
    val publicKey: PublicJwk

    /** True only for keys generated inside secure hardware. */
    val isHardwareBacked: Boolean

    /** ES256 signature over SHA-256(`data`), raw r||s, 64 bytes. */
    suspend fun sign(data: ByteArray): ByteArray

    val algorithm: SignatureAlgorithm get() = publicKey.algorithm
    val deviceId: String get() = publicKey.deviceId
    val fingerprint: String get() = publicKey.fingerprint
}

/** Sign the UTF-8 bytes of a signing input; base64url without padding. */
suspend fun DeviceSigner.signBase64Url(input: String): String {
    val sig = sign(input.toByteArray(Charsets.UTF_8))
    if (sig.size != 64) throw SignerException.BadSignatureLength
    return Base64Url.encode(sig)
}

sealed class SignerException(message: String) : Exception(message) {
    object BadSignatureLength : SignerException("signature is not 64 bytes") {
        private fun readResolve(): Any = BadSignatureLength
    }
    object InvalidKeyMaterial : SignerException("invalid key material") {
        private fun readResolve(): Any = InvalidKeyMaterial
    }
}

/**
 * A P-256 key in process memory. For tests, the emulator and the demo only. Devices enrolled with it are not
 * hardware-backed and must say so (`software: true`).
 */
class SoftwareP256Signer private constructor(
    private val privateKey: PrivateKey,
    override val publicKey: PublicJwk,
) : DeviceSigner {
    override val isHardwareBacked: Boolean get() = false

    override suspend fun sign(data: ByteArray): ByteArray = signBlocking(data)

    /** The same signature without suspending (the key needs no prompt). */
    fun signBlocking(data: ByteArray): ByteArray = P256.sign(privateKey, data)

    /** The 32-byte private scalar (to persist a test or demo key). */
    val rawPrivateKey: ByteArray get() = P256.fixed32((privateKey as ECPrivateKey).s)

    companion object {
        /** A new random key. */
        fun generate(): SoftwareP256Signer {
            val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), SecureRandom()) }.generateKeyPair()
            return SoftwareP256Signer(kp.private, PublicJwk.p256(kp.public as ECPublicKey))
        }

        /** From a raw 32-byte private scalar. */
        fun fromRaw(d: ByteArray): SoftwareP256Signer {
            if (d.size != 32) throw SignerException.InvalidKeyMaterial
            val (x, y) = try {
                P256.publicPoint(d)
            } catch (_: IllegalArgumentException) {
                throw SignerException.InvalidKeyMaterial
            }
            return SoftwareP256Signer(P256.privateKey(d), PublicJwk.p256(x, y))
        }

        /** From a private JWK's `d` (32 bytes, base64url); `expected` checks the public half. */
        fun fromJwkD(d: String, expected: PublicJwk? = null): SoftwareP256Signer {
            val raw = Base64Url.decode(d) ?: throw SignerException.InvalidKeyMaterial
            val s = fromRaw(raw)
            if (expected != null && expected != s.publicKey) throw SignerException.InvalidKeyMaterial
            return s
        }
    }
}
