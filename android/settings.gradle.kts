// signeto-sign: the approver-device side of the Signeto protocol (docs/protocol.md) for Android and the JVM.
// Pure Kotlin/JVM; the Android app includes this build (includeBuild("../public/android")).
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "signeto-sign"
