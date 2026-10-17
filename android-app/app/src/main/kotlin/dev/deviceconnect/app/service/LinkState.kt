package dev.deviceconnect.app.service

/**
 * What the connection is doing right now, as the UI needs to show it.
 *
 * This is deliberately small and free of PII: [Connected.peerName] is the name
 * the *peer* reported about itself, and nothing else about the peer is carried
 * into the UI layer.
 */
sealed interface LinkState {

    /** Nothing is connected; this is the resting state. */
    data object Idle : LinkState

    /** Dialling and running the Noise handshake. */
    data class Connecting(val target: String) : LinkState

    /**
     * The handshake finished with a PC that is not pinned yet, so the user must
     * compare [code] with the code shown on the PC and confirm
     * (docs/protocol.md section 3.4). No key is stored until they do.
     */
    data class AwaitingConfirmation(
        val peerName: String,
        val peerId: String,
        val code: String,
    ) : LinkState

    /** Handshake done and the peer is trusted. */
    data class Connected(
        val peerName: String,
        val peerId: String,
    ) : LinkState

    /** The last attempt ended in failure; [message] is safe to display. */
    data class Failed(val message: String) : LinkState
}
