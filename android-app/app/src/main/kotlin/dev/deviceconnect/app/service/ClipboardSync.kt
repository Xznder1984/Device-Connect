package dev.deviceconnect.app.service

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

/**
 * Text-only clipboard access for `clipboard.get` / `clipboard.set`
 * (docs/protocol.md section 5, clipboard channel 0x06).
 *
 * Deliberately the whole feature: no clipboard watcher and no background
 * listener. The clip leaves the phone only inside a reply to an explicit
 * `clipboard.get`, which is what section 5 requires, and it is never logged.
 *
 * Two platform rules shape this class:
 *
 *  - **Reading is foreground-only from Android 10.** `getPrimaryClip` returns
 *    null unless the calling app is the focused app, so a request that arrives
 *    while the phone is idle reports [Read.Absent] rather than an empty string.
 *    The PC must be able to tell "cannot see the clipboard" from "the clipboard
 *    is empty", which is why the three outcomes are distinct types.
 *  - **Only text is transferred.** A clip holding an image or a content URI is
 *    reported as [Read.Absent]; resolving a URI to its string would leak a file
 *    path, and section 5 defines this channel as text.
 */
class ClipboardSync(private val context: Context) {

    /** What a read found. */
    sealed interface Read {
        /** The clip text, exactly as it was on the clipboard (may be empty). */
        data class Text(val value: String) : Read

        /** No readable text clip, or the app is not in the foreground. */
        data object Absent : Read

        /** A clip exists but is larger than this build will transfer. */
        data object TooLarge : Read
    }

    private val manager: ClipboardManager?
        get() = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

    fun read(): Read {
        val clipboard = manager ?: return Read.Absent
        val clip: ClipData? = try {
            clipboard.primaryClip
        } catch (_: SecurityException) {
            // Older platforms throw instead of returning null when the caller
            // may not read. Same meaning: not visible to us.
            return Read.Absent
        }
        if (clip == null || clip.itemCount == 0) return Read.Absent
        val text = clip.getItemAt(0).text?.toString() ?: return Read.Absent
        if (utf8Bytes(text) > MAX_TEXT_BYTES) return Read.TooLarge
        return Read.Text(text)
    }

    /**
     * Put [text] on the clipboard.
     *
     * The caller has already rejected anything over [MAX_TEXT_BYTES], so this
     * only has to report whether the platform accepted the write.
     */
    fun write(text: String): Boolean {
        val clipboard = manager ?: return false
        return try {
            clipboard.setPrimaryClip(ClipData.newPlainText(CLIP_LABEL, text))
            true
        } catch (_: SecurityException) {
            false
        }
    }

    companion object {
        private const val CLIP_LABEL = "Device Connect"

        /**
         * Largest clip text this build will move, in UTF-8 bytes.
         *
         * The schema allows 1 MiB, but a frame can only carry
         * `MAX_BODY_LEN - MIN_BODY_LEN` bytes of JSON, and JSON escaping turns
         * one character into up to six (`\uXXXX`, or twelve for a surrogate
         * pair). 128 KiB cannot exceed the frame budget even in that worst case,
         * so an over-long clip is refused up front with a clear error instead of
         * producing a reply that cannot be framed.
         */
        const val MAX_TEXT_BYTES = 128 * 1024

        /** The UTF-8 size of [text], which is what the wire actually carries. */
        fun utf8Bytes(text: String): Int = text.toByteArray(Charsets.UTF_8).size
    }
}
