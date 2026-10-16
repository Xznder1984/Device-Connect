// Android Gradle plugin 9 has built-in Kotlin support, so the Kotlin Android
// plugin (org.jetbrains.kotlin.android) must NOT be applied here. The Kotlin JVM
// plugin is still used by the plain-JVM :protocol module. The Compose compiler
// plugin is versioned with Kotlin.
plugins {
    kotlin("jvm") version "2.4.21" apply false
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}

allprojects {
    group = "dev.deviceconnect"
    version = "0.1.0"
}
