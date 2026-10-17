package dev.deviceconnect.app.service

import dev.deviceconnect.protocol.Capability

/**
 * The capabilities this build actually implements, with the wording the app
 * shows for each.
 *
 * The protocol declares eight capabilities (docs/protocol.md section 4) but this
 * build only enforces the ones listed here. The rest are deliberately absent for
 * two reasons: a switch the code cannot honour is a promise the app cannot keep,
 * and `hello` advertises exactly what is switched on, so an unenforceable switch
 * would tell the PC it may do something the phone will then refuse.
 *
 * A capability is added here only together with the code that honours it.
 */
object ImplementedCapabilities {

    /** One implemented capability and the sentence that explains it to the user. */
    data class Info(
        val id: String,
        val title: String,
        val detail: String,
    )

    val entries: List<Info> = listOf(
        Info(
            id = Capability.CLIPBOARD,
            title = "Clipboard",
            detail = "Your PC can read the text on this phone's clipboard and replace " +
                "it. Text only. Android only lets the app on screen read the clipboard, " +
                "so a read while the phone is idle is refused rather than answered " +
                "with the wrong thing.",
        ),
    )

    /** Ids this build enforces. Only these can be switched on or advertised. */
    val ids: Set<String> = entries.map { it.id }.toSet()
}
