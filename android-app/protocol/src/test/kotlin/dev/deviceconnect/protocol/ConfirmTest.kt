package dev.deviceconnect.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Conformance against `protocol/test-vectors/confirm-code.json`. */
internal class ConfirmTest {

    @Test
    fun codesMatchTheVectors() {
        val pairs = TestVectors.array(TestVectors.load("confirm-code.json"), "pairs")
        assertTrue(pairs.size() >= 3, "expected at least three pairs")

        for (element in pairs) {
            val pair = element.asJsonObject
            val expected = pair.get("code").asString
            val pkA = TestVectors.hex(pair.get("pkA").asString)
            val pkB = TestVectors.hex(pair.get("pkB").asString)

            assertEquals(expected, Confirm.code(pkA, pkB), "code for pkA=${pair.get("pkA").asString.take(8)}…")
            // Both sides hold the two keys in either order and must derive one code.
            assertEquals(expected, Confirm.code(pkB, pkA), "code is order independent")
        }
    }

    @Test
    fun codesAreSixDigitsAndDeterministic() {
        val a = ByteArray(32) { 1 }
        val b = ByteArray(32) { 2 }

        val first = Confirm.code(a, b)
        assertEquals(6, first.length, "six digits")
        assertTrue(first.all { it in '0'..'9' }, "digits only, no leading-space padding")
        assertEquals(first, Confirm.code(a, b), "stable across calls")
        assertEquals(first, Confirm.code(b, a), "order independent")
        assertEquals(first, Confirm.code(a.copyOf(), b.copyOf()), "uses bytes, not identity")

        // Leading zeros survive: the code is zero-padded, not decimal-stripped.
        val many = (0 until 40).map { i -> Pair(ByteArray(32) { it.toByte() }, ByteArray(32) { i.toByte() }) }
        for ((left, right) in many) {
            val code = Confirm.code(left, right)
            assertEquals(6, code.length, "every code is exactly six digits")
        }
    }
}
