package dev.deviceconnect.protocol

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.HexFormat

/**
 * Loader for the shared golden vectors.
 *
 * The vectors are generated once by the Rust crate (`protocol/rust`, example
 * `gen_vectors`) and committed under `protocol/test-vectors/`, then asserted by
 * every implementation so they cannot drift apart. The directory is injected by
 * `android-app/protocol/build.gradle.kts` because it lives at the repository
 * root, outside the Android tree.
 */
internal object TestVectors {
    private val hexFormat: HexFormat = HexFormat.of()

    fun dir(): File {
        val path = System.getProperty("dc.testVectorsDir")
            ?: error(
                "dc.testVectorsDir system property is not set; " +
                    "run these tests through Gradle (android-app/protocol)",
            )
        return File(path)
    }

    fun load(name: String): JsonObject {
        val file = File(dir(), name)
        require(file.isFile) { "missing vector file: $file" }
        return JsonParser.parseReader(file.reader(StandardCharsets.UTF_8)).asJsonObject
    }

    fun hex(text: String): ByteArray = hexFormat.parseHex(text)

    fun unhex(bytes: ByteArray): String = hexFormat.formatHex(bytes)

    fun array(obj: JsonObject, name: String): JsonArray =
        obj.getAsJsonArray(name) ?: error("vector file missing array '$name'")

    fun parseJson(bytes: ByteArray): JsonElement =
        JsonParser.parseString(String(bytes, StandardCharsets.UTF_8))
}
