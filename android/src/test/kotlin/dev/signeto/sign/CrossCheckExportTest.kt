// Kotlin → TypeScript cross-check. With SIGNETO_EXPORT_DIR set, writes receipts, a relay header and a freeze body
// signed here with the vector ES256 key, in the same file the Swift package exports; the Swift package's
// Fixtures/verify-swift-output.mjs then verifies them with @signeto/protocol:
//   SIGNETO_EXPORT_DIR=/tmp/sig ./gradlew test --tests '*CrossCheckExportTest'
//   node ../ios/Tests/SignetoSignTests/Fixtures/verify-swift-output.mjs /tmp/sig
package dev.signeto.sign

import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class CrossCheckExportTest {
    @Test
    fun exportKotlinSignedArtifacts() = runBlocking {
        val dir = System.getenv("SIGNETO_EXPORT_DIR")
        assumeTrue(dir != null, "set SIGNETO_EXPORT_DIR to export Kotlin-signed artifacts for the TS cross-check")
        val signer = vectorP256Signer("device-es256")
        val i = vectors("receipts").first { it.first == "es256-approve.json" }.second("inputs")
        val bytes = i("canonical_bytes").s
        val receipts = listOf(Decision.APPROVE to null, Decision.DENY to "Zoë says 不 😀 \"no\"\n").map { (d, reason) ->
            Receipts.sign("act_01JBXK4Q9R2T4V6W8Y0Z1A3B5C", bytes, d, reason, "jason", "2026-11-05T18:05:00.000Z", signer).json
        }
        val body = Jcs.canonicalize(receipts[0])
        val ts = "2026-11-05T18:05:00.000Z"
        val path = "/v1/approvals/apr_01JBXK4Q9R2T4V6W8Y0Z1A3B5D/receipt?x=%2F1"
        val header = RelayAuth.deviceHeader("POST", path, body.toByteArray(), ts, signer)
        val freeze = Freeze.body(true, ts, signer)
        val out = JsonValue.obj(
            "canonical_bytes" to str(bytes), "issued_at" to i("issued_at"), "expires_at" to i("expires_at"), "device_public_key" to signer.publicKey.json,
            "receipts" to JsonValue.of(receipts),
            "relay" to JsonValue.obj(
                "header" to str(header), "method" to str("POST"), "path" to str(path), "body" to str(body),
                "now" to JsonValue.of(Timestamp.parse(ts)!!),
            ),
            "freeze" to freeze,
        )
        File(dir!!).mkdirs()
        // The verifier reads swift-signed.json; the content is the same shape whichever port signed it.
        File(dir, "swift-signed.json").writeBytes(Jcs.canonicalBytes(out))
    }
}
