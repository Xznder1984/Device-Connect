package dev.deviceconnect.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.deviceconnect.app.ui.theme.DeviceConnectTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeviceConnectTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
                    HomeScreen(modifier = Modifier.padding(insets))
                }
            }
        }
    }
}

/**
 * The first screen. It is intentionally a status and consent screen rather than
 * a dashboard: Device Connect only ever controls the phone it is installed on,
 * so the app has to be explicit about what it is and what it will never do.
 */
@Composable
fun HomeScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val versionName = remember {
        runCatching {
            context.packageManager
                .getPackageInfo(context.packageName, 0)
                .versionName
        }.getOrNull() ?: "unknown"
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            text = "Control this phone from your own Windows PC. Direct connection, " +
                "end-to-end encrypted, no accounts and no cloud.",
            style = MaterialTheme.typography.bodyLarge,
        )

        StatusBanner(connected = false)

        HorizontalDivider()

        SectionHeading("What this app does")
        Bullet("Pairs with your PC by scanning a QR code.")
        Bullet("Streams the screen and accepts input only while you have it switched on.")
        Bullet("Keeps a permanent notification showing exactly what is active.")

        SectionHeading("What it never does")
        Bullet("No accounts, no cloud, no analytics, no telemetry, no crash reporting.")
        Bullet("No root, no exploits, no hidden or background capture.")
        Bullet("Never controls anyone else's device: only this phone, and only on purpose.")

        SectionHeading("Your control")
        Bullet("Disconnect or revoke access instantly from this screen.")
        Bullet("Sensitive actions need a confirmation on this device first.")
        Bullet("Keys are generated here and stay in the Android Keystore.")

        Spacer(Modifier.height(8.dp))

        Text(
            text = "Version $versionName",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun StatusBanner(connected: Boolean) {
    val dotColor = if (connected) Color(0xFF2E7D32) else Color(0xFF9A6700)
    val label = if (connected) "Connected to your PC" else "Not connected"
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(dotColor, CircleShape),
            )
            Text(text = label, style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun SectionHeading(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() },
    )
}

@Composable
private fun Bullet(text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text = "\u2022", style = MaterialTheme.typography.bodyLarge)
        Text(text = text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Preview(showBackground = true)
@Composable
private fun HomeScreenPreview() {
    DeviceConnectTheme(dynamicColor = false) { HomeScreen() }
}
