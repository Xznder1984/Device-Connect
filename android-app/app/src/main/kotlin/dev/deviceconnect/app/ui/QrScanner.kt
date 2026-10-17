package dev.deviceconnect.app.ui

import android.os.SystemClock
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import dev.deviceconnect.protocol.Qr

/**
 * Camera preview that decodes the pairing QR code the PC displays
 * (docs/protocol.md section 3.1).
 *
 * The frames never leave the device: [QrAnalyzer] turns each frame into a
 * luminance bitmap and hands it to ZXing, which decodes in-process. Nothing is
 * written to disk, nothing is uploaded, and only strings that already carry the
 * `dc1:` prefix are reported upward.
 */
@Composable
fun QrScanner(
    modifier: Modifier = Modifier,
    onDecoded: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnDecoded = rememberUpdatedState(onDecoded)

    val previewView = remember {
        PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
    }
    // Cleared in onDispose; held outside the Runnable so dispose can reach it.
    val holder = remember { arrayOfNulls<ImageAnalysis>(1) }

    DisposableEffect(Unit) {
        val executor = ContextCompat.getMainExecutor(context)
        val providerFuture = ProcessCameraProvider.getInstance(context)

        providerFuture.addListener(
            {
                val provider = runCatching { providerFuture.get() }.getOrNull()
                if (provider == null) return@addListener

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                    .build()
                analysis.setAnalyzer(executor, QrAnalyzer { text -> currentOnDecoded.value(text) })
                holder[0] = analysis

                runCatching {
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                }
            },
            executor,
        )

        onDispose {
            runCatching { holder[0]?.clearAnalyzer() }
            holder[0] = null
            runCatching { if (providerFuture.isDone) providerFuture.get().unbindAll() }
        }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

/**
 * One QR frame at a time, decoded with ZXing's [MultiFormatReader].
 *
 * Only QR codes are searched for, which keeps each frame cheap. A code that
 * decodes but does not carry the Device Connect prefix is ignored: any QR in
 * the room must not be mistaken for a pairing code.
 */
private class QrAnalyzer(
    private val onDecoded: (String) -> Unit,
) : ImageAnalysis.Analyzer {

    private val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
    private val reader = MultiFormatReader()

    private var lastText: String? = null
    private var lastAtMs = 0L

    override fun analyze(image: ImageProxy) {
        try {
            val text = decode(image)
            if (text != null && text.startsWith(Qr.PREFIX)) {
                val now = SystemClock.elapsedRealtime()
                if (text != lastText || now - lastAtMs >= REPEAT_MS) {
                    lastText = text
                    lastAtMs = now
                    onDecoded(text)
                }
            }
        } catch (_: Exception) {
            // A frame that will not decode is the normal case, not an error.
        } finally {
            image.close()
        }
    }

    private fun decode(image: ImageProxy): String? {
        val plane = image.planes.firstOrNull() ?: return null
        val width = image.width
        val height = image.height
        if (width <= 0 || height <= 0) return null

        val rowStride = plane.rowStride
        val pixelStride = plane.pixelStride
        val dataWidth = maxOf(rowStride, width)
        val luminance = ByteArray(dataWidth * height)

        val buffer = plane.buffer
        buffer.rewind()
        if (pixelStride == 1) {
            buffer.get(luminance, 0, minOf(buffer.remaining(), luminance.size))
        } else {
            // Some devices interleave the Y plane; copy pixel by pixel.
            val row = ByteArray(rowStride)
            var y = 0
            while (y < height && buffer.remaining() >= rowStride) {
                buffer.get(row, 0, rowStride)
                var x = 0
                while (x < width) {
                    val from = x * pixelStride
                    if (from < rowStride) luminance[y * dataWidth + x] = row[from]
                    x++
                }
                y++
            }
        }

        val source = PlanarYUVLuminanceSource(luminance, dataWidth, height, 0, 0, width, height, false)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        return try {
            reader.decode(bitmap, hints).text
        } catch (_: NotFoundException) {
            null
        } finally {
            reader.reset()
        }
    }

    private companion object {
        /** Re-report the same code at most this often while it stays in frame. */
        const val REPEAT_MS = 2_000L
    }
}
