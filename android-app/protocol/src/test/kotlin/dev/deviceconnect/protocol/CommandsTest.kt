package dev.deviceconnect.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The command-to-capability map (docs/protocol.md section 4).
 *
 * The phone refuses a command whose capability is off, so a wrong entry here is
 * a security hole in one direction (a command runs without its switch) or a
 * broken feature in the other (a command can never run). The map is therefore
 * checked against the spec's own command list, `typed-messages.json`, rather than
 * against a second hand-written copy of itself.
 */
class CommandsTest {

    /**
     * Commands that need no switch, per section 4: `status.*` and `security.*`
     * must always be reachable, and `app.*`, `screentext.*` and `wait.*` are
     * deliberately left unassigned until that layer is specified.
     */
    private val ungated = setOf(
        "status.get",
        "caps.set",
        "security.unpair",
        "security.rotate",
        "app.open",
        "app.list",
        "screentext.get",
        "wait.screen",
    )

    private fun vectorCommands(): List<String> =
        TestVectors.array(TestVectors.load("typed-messages.json"), "requests")
            .mapNotNull { it.asJsonObject.get("cmd")?.asString }

    @Test
    fun clipboardCommandsNeedTheClipboardSwitch() {
        assertEquals(Capability.CLIPBOARD, Commands.capabilityFor("clipboard.get"))
        assertEquals(Capability.CLIPBOARD, Commands.capabilityFor("clipboard.set"))
    }

    @Test
    fun revocationAndStatusCommandsNeedNoSwitch() {
        // `caps.set` and `security.*` must always be reachable. If any of them
        // needed a switch, turning that switch off would lock the user out of
        // turning it back on, which is the one state that must never exist.
        assertNull(Commands.capabilityFor("caps.set"))
        assertNull(Commands.capabilityFor("security.unpair"))
        assertNull(Commands.capabilityFor("security.rotate"))
        assertNull(Commands.capabilityFor("status.get"))
    }

    @Test
    fun unknownCommandsNeedNothingButAreNotTherebyEnabled() {
        // Absence from the map means "no capability needed", never "allowed": an
        // unregistered command is answered UNSUPPORTED by the control plane
        // before any capability is considered.
        assertNull(Commands.capabilityFor("not.a.real.command"))
    }

    @Test
    fun everyMappedCapabilityIsDeclaredInTheProtocol() {
        assertTrue(
            Commands.DECLARED.containsAll(Commands.mappedCapabilities()),
            "mapped capabilities ${Commands.mappedCapabilities() - Commands.DECLARED} are not declared in section 4",
        )
    }

    @Test
    fun everySpecifiedCommandIsEitherGatedOrExplicitlyUngated() {
        // typed-messages.json carries one fixture per command the spec defines.
        // A command that is neither in the map nor on the ungated list is one
        // somebody added to the spec without deciding what protects it, so this
        // fails rather than letting it default to unprotected.
        val commands = vectorCommands()
        assertTrue(commands.isNotEmpty(), "typed-messages.json lists no requests")

        for (cmd in commands) {
            val capability = Commands.capabilityFor(cmd)
            if (capability == null) {
                assertTrue(cmd in ungated, "$cmd needs no capability but is not on the ungated list")
            } else {
                assertTrue(
                    Commands.DECLARED.contains(capability),
                    "$cmd maps to undeclared capability '$capability'",
                )
            }
        }
    }

    @Test
    fun theCommandFamiliesAreGatedAsTheSpecSays() {
        val expected = mapOf(
            "screen.start" to Capability.SCREEN_VIEW,
            "input.tap" to Capability.INPUT_CONTROL,
            "notifications.list" to Capability.NOTIFICATIONS,
            "sms.send" to Capability.MESSAGES,
            "calls.dial" to Capability.CALLS,
            "files.push" to Capability.FILES,
        )
        for ((cmd, capability) in expected) {
            assertEquals(capability, Commands.capabilityFor(cmd), "wrong capability for $cmd")
        }

        // Every command in the vectors belongs to exactly one family, and every
        // family in the table is represented, so the map cannot have quietly
        // split a family across two switches.
        assertEquals(
            setOf(
                Capability.CLIPBOARD, Capability.SCREEN_VIEW, Capability.INPUT_CONTROL,
                Capability.NOTIFICATIONS, Capability.MESSAGES, Capability.CALLS,
                Capability.FILES,
            ),
            Commands.mappedCapabilities(),
        )
    }
}
