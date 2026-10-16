import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // JSON for the QR payload and the control-plane envelopes. Exposed with `api`
    // rather than `implementation` because Gson types appear in this module's
    // public surface (Wire.gson, Request.result, Response.result), so consumers
    // such as the app need it on their own classpath to compile.
    api("com.google.code.gson:gson:2.14.0")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // The golden vectors and schemas are shared with the other platforms and live
    // at the repository root, outside the Android tree.
    systemProperty("dc.testVectorsDir", rootProject.file("../protocol/test-vectors").absolutePath)
    systemProperty("dc.schemaDir", rootProject.file("../protocol/schema").absolutePath)
    testLogging {
        events("passed", "failed", "skipped")
    }
}
