package dev.signeto.sign

import java.io.File
import org.junit.jupiter.api.Assertions.assertTrue

/**
 * Shared conformance vectors (`public/packages/protocol/vectors/`) and the Swift package's fixtures, which this suite
 * reads too (read-only). Gradle runs tests with the project directory (public/android) as the working directory.
 */
object Paths {
    val project: File = File(System.getProperty("user.dir")).absoluteFile
    val public: File = project.parentFile
    val vectors: File = File(public, "packages/protocol/vectors")
    val fixtures: File = File(public, "ios/Tests/SignetoSignTests/Fixtures")
}

fun loadJson(f: File): JsonValue = JsonParser.parse(f.readBytes())

/** Every `*.json` in a vector directory, sorted by name. */
fun vectors(dir: String): List<Pair<String, JsonValue>> {
    val d = File(Paths.vectors, dir)
    val names = (d.list() ?: emptyArray()).filter { it.endsWith(".json") }.sorted()
    assertTrue(names.isNotEmpty(), "no vectors in $dir")
    return names.map { it to loadJson(File(d, it)) }
}

fun fixture(name: String): JsonValue = loadJson(File(Paths.fixtures, name))

fun vectorKey(name: String): JsonValue = loadJson(File(Paths.vectors, "keys/$name.json"))

/** Test shorthand: the member, which must exist. */
operator fun JsonValue.invoke(key: String): JsonValue = this[key] ?: error("missing member $key")

val JsonValue.s: String get() = stringValue ?: "<not a string>"

fun JsonValue.jwk(): PublicJwk? = PublicJwk.parse(this, allowExtraMembers = false)

/** A JWK that may carry `d`: the public half. */
fun JsonValue.publicHalf(): PublicJwk? = objectValue?.let { PublicJwk.parse(JsonValue.Obj(it.without("d"))) }

/** Software P-256 signer from a vector key file (`d` present). */
fun vectorP256Signer(name: String): SoftwareP256Signer {
    val k = vectorKey(name)
    return SoftwareP256Signer.fromJwkD(k("d").s, k.publicHalf())
}

fun str(s: String): JsonValue = JsonValue.of(s)
