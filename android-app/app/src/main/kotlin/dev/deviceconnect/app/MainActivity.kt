package dev.deviceconnect.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.deviceconnect.app.ui.DeviceConnectApp
import dev.deviceconnect.app.ui.theme.DeviceConnectTheme

/**
 * The single Activity. All of the UI is in [DeviceConnectApp]; this class only
 * sets up the window and the theme, so there is no navigator, no fragments and
 * nothing to keep in sync with a second entry point.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeviceConnectTheme {
                DeviceConnectApp()
            }
        }
    }
}
