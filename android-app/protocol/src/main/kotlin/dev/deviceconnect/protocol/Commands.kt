package dev.deviceconnect.protocol

/**
 * Which capability a command needs (docs/protocol.md section 4).
 *
 * The spec fixes this mapping because the phone refuses a command whose
 * capability is off: a disagreement between two implementations is either a
 * security hole (a command runs with its switch off) or a permanently broken
 * command (it can never run). Writing it down once, here, is what stops each
 * side from deriving its own answer.
 *
 * Like [Channel] and [Capability], this declares the whole protocol, not only
 * the parts the current phone build serves, so a client can plan its UI before
 * the server side exists.
 *
 * A command absent from the map needs no capability: `status.*` and `security.*`
 * must always be reachable, and `app.*`, `screentext.*` and `wait.*` are
 * deliberately unassigned until that layer is specified.
 */
object Commands {

    /** Command -> the capability the phone checks before running it. */
    private val REQUIRED_CAPABILITY: Map<String, String> = mapOf(
        "clipboard.get" to Capability.CLIPBOARD,
        "clipboard.set" to Capability.CLIPBOARD,

        "screen.start" to Capability.SCREEN_VIEW,
        "screen.stop" to Capability.SCREEN_VIEW,
        "screen.configure" to Capability.SCREEN_VIEW,

        "input.tap" to Capability.INPUT_CONTROL,
        "input.longpress" to Capability.INPUT_CONTROL,
        "input.swipe" to Capability.INPUT_CONTROL,
        "input.scroll" to Capability.INPUT_CONTROL,
        "input.text" to Capability.INPUT_CONTROL,
        "input.key" to Capability.INPUT_CONTROL,

        "notifications.list" to Capability.NOTIFICATIONS,
        "notifications.reply" to Capability.NOTIFICATIONS,
        "notifications.dismiss" to Capability.NOTIFICATIONS,

        "sms.list" to Capability.MESSAGES,
        "sms.thread" to Capability.MESSAGES,
        "sms.send" to Capability.MESSAGES,

        "calls.list" to Capability.CALLS,
        "calls.answer" to Capability.CALLS,
        "calls.reject" to Capability.CALLS,
        "calls.dial" to Capability.CALLS,

        "files.push" to Capability.FILES,
        "files.pull" to Capability.FILES,
        "files.cancel" to Capability.FILES,
    )

    /**
     * The capability [cmd] requires, or null when it needs none.
     *
     * A null result means "always allowed", never "unknown command": whether a
     * command exists at all is answered by whether a handler is registered, and
     * an unregistered one is refused with `UNSUPPORTED` before any capability is
     * considered.
     */
    fun capabilityFor(cmd: String): String? = REQUIRED_CAPABILITY[cmd]

    /** Every capability id this map refers to, for validation in tests. */
    fun mappedCapabilities(): Set<String> = REQUIRED_CAPABILITY.values.toSet()

    /** The capabilities the protocol declares (section 4). */
    val DECLARED: Set<String> = setOf(
        Capability.SCREEN_VIEW,
        Capability.INPUT_CONTROL,
        Capability.NOTIFICATIONS,
        Capability.MESSAGES,
        Capability.CALLS,
        Capability.CONTACTS,
        Capability.FILES,
        Capability.CLIPBOARD,
    )
}
