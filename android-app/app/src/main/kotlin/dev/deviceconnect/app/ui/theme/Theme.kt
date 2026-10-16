package dev.deviceconnect.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// A small, fixed palette so the app looks the same regardless of device theme
// when dynamic color is unavailable (API < 31).
private val LightColors = lightColorScheme(
    primary = Color(0xFF1F6FEB),
    onPrimary = Color.White,
    secondary = Color(0xFF3B5B7A),
    background = Color(0xFFFBFCFE),
    surface = Color(0xFFFBFCFE),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8FB6FF),
    onPrimary = Color(0xFF00305F),
    secondary = Color(0xFFB6C7DA),
    background = Color(0xFF101418),
    surface = Color(0xFF101418),
)

@Composable
fun DeviceConnectTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content,
    )
}
