// See settings.gradle.kts. `./gradlew test` runs the shared conformance vectors in ../packages/protocol/vectors and
// the fixtures in ../ios/Tests/SignetoSignTests/Fixtures (read-only; shared with the Swift package).
plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

group = "dev.signeto"
version = "1.0.0"

kotlin {
    jvmToolchain(17)
    compilerOptions {
        // Compile against the Java 8 API: an Android app (minSdk 28, no desugaring) has no Java 9+ library APIs, and
        // -Xjdk-release turns any use of one into a compile error instead of a crash on a phone.
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // Ed25519 only, through the lightweight API (org.bouncycastle.math.ec.rfc8032); no JCA provider is registered.
    implementation(libs.bcprov)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // Opt-in checks read these (see README.md).
    listOf("SIGNETO_EXPORT_DIR").forEach { k -> System.getenv(k)?.let { environment(k, it) } }
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
