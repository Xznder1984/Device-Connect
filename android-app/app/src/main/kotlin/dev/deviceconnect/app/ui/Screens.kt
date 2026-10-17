package dev.deviceconnect.app.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.deviceconnect.app.R
import dev.deviceconnect.app.discovery.Discovery
import dev.deviceconnect.app.service.LinkState

/**
 * Root composable: one Scaffold, one screen at a time.
 *
 * Screen selection lives in the ViewModel so it survives rotation, and so the
 * service can push the UI to the confirmation screen the moment a handshake
 * with an unknown PC completes.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceConnectApp(viewModel: MainViewModel = viewModel()) {
    val link by viewModel.link.collectAsStateWithLifecycle()
    val screen by viewModel.screen.collectAsStateWithLifecycle()
    val discovered by viewModel.discovered.collectAsStateWithLifecycle()
    val notice by viewModel.notice.collectAsStateWithLifecycle()
    val pairedName by viewModel.pairedPeerName.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(notice) {
        val text = notice ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(text)
        viewModel.dismissNotice()
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(titleFor(screen)) },
                navigationIcon = {
                    if (screen != Screen.Home) {
                        TextButton(onClick = viewModel::back) { Text("Back") }
                    }
                },
            )
        },
    ) { insets ->
        Box(modifier = Modifier.padding(insets)) {
            when (screen) {
                Screen.Home -> HomeScreen(
                    link = link,
                    deviceName = viewModel.deviceName,
                    deviceId = viewModel.deviceId,
                    pairedPeerName = pairedName,
                    onConnect = viewModel::openPairingOptions,
                    onReconnect = viewModel::reconnect,
                    onForget = viewModel::forgetPeer,
                )

                Screen.PairingOptions -> PairingOptionsScreen(
                    onScan = viewModel::openScanner,
                    onManual = viewModel::openManualEntry,
                    onDiscover = viewModel::openDiscovery,
                )

                Screen.Scan -> ScanScreen(onDecoded = viewModel::onQrText)

                Screen.Manual -> ManualScreen(onConnect = viewModel::connectManual)

                Screen.Discovered -> DiscoveredScreen(
                    peers = discovered,
                    onSelect = viewModel::connectTo,
                    onManual = viewModel::openManualEntry,
                )

                Screen.Confirm -> ConfirmScreen(
                    link = link,
                    onConfirm = viewModel::confirmPairing,
                    onReject = viewModel::rejectPairing,
                )

                Screen.Connected -> ConnectedScreen(
                    link = link,
                    deviceId = viewModel.deviceId,
                    onDisconnect = viewModel::disconnect,
                )
            }
        }
    }
}

private fun titleFor(screen: Screen): String = when (screen) {
    Screen.Home -> "Device Connect"
    Screen.PairingOptions -> "Connect to a PC"
    Screen.Scan -> "Scan pairing code"
    Screen.Manual -> "Enter address"
    Screen.Discovered -> "PCs on this network"
    Screen.Confirm -> "Confirm pairing"
    Screen.Connected -> "Connected"
}

// ---------- Home ----------

@Composable
private fun HomeScreen(
    link: LinkState,
    deviceName: String,
    deviceId: String,
    pairedPeerName: String?,
    onConnect: () -> Unit,
    onReconnect: () -> Unit,
    onForget: () -> Unit,
) {
    val context = LocalContext.current
    val versionName = remember {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: "unknown"
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Control this phone from your own Windows PC. Direct connection, " +
                "end-to-end encrypted, no accounts and no cloud.",
            style = MaterialTheme.typography.bodyLarge,
        )

        StatusBanner(link = link)

        ThisDevice(name = deviceName, id = deviceId)

        HorizontalDivider()

        if (pairedPeerName != null) {
            Text(
                text = "Paired with $pairedPeerName",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Button(onClick = onReconnect, modifier = Modifier.fillMaxWidth()) {
                Text("Reconnect")
            }
            OutlinedButton(onClick = onForget, modifier = Modifier.fillMaxWidth()) {
                Text("Forget this PC")
            }
        }

        Button(onClick = onConnect, modifier = Modifier.fillMaxWidth()) {
            Text(if (pairedPeerName == null) "Connect to a PC" else "Connect to another PC")
        }

        HorizontalDivider()

        SectionHeading("What this app does")
        Bullet("Connects straight to your PC; you scan the code your PC shows.")
        Bullet("Keeps a permanent notification showing exactly what is active.")
        Bullet("Sensitive actions will always need a confirmation on this phone.")

        SectionHeading("What it never does")
        Bullet("No accounts, no cloud, no analytics, no telemetry, no crash reporting.")
        Bullet("No root, no exploits, no hidden or background capture.")
        Bullet("Never controls anyone else's device: only this phone, and only on purpose.")

        SectionHeading("Your control")
        Bullet("Disconnect or forget the PC at any time from this screen.")
        Bullet("Keys are generated here and sealed by the Android Keystore.")

        Spacer(Modifier.height(8.dp))

        Text(
            text = "Version $versionName",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun StatusBanner(link: LinkState) {
    val (dotColor, label) = when (link) {
        is LinkState.Connected -> Color(0xFF2E7D32) to "Connected to ${link.peerName}"
        is LinkState.Connecting -> Color(0xFF9A6700) to "Connecting to ${link.target}"
        is LinkState.AwaitingConfirmation -> Color(0xFF9A6700) to "Waiting for your confirmation"
        is LinkState.Failed -> Color(0xFFB3261E) to link.message
        LinkState.Idle -> Color(0xFF9A6700) to "Not connected"
    }
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
private fun ThisDevice(name: String, id: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = "This phone",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = name, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = "Device ID $id",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---------- Pairing options ----------

@Composable
private fun PairingOptionsScreen(
    onScan: () -> Unit,
    onManual: () -> Unit,
    onDiscover: () -> Unit,
) {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Open Device Connect on your PC, then choose how to connect.",
            style = MaterialTheme.typography.bodyLarge,
        )
        Button(
            onClick = onScan,
            enabled = context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Scan the QR code")
        }
        OutlinedButton(onClick = onDiscover, modifier = Modifier.fillMaxWidth()) {
            Text("Find it on this network")
        }
        OutlinedButton(onClick = onManual, modifier = Modifier.fillMaxWidth()) {
            Text("Enter an address")
        }
        Text(
            text = "Scanning is the quickest way and needs the camera. Finding it on " +
                "the network only works when both devices are on the same Wi-Fi.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---------- Scan ----------

@Composable
private fun ScanScreen(onDecoded: (String) -> Unit) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { result -> granted = result }

    LaunchedEffect(Unit) {
        if (!granted) launcher.launch(Manifest.permission.CAMERA)
    }

    if (granted) {
        Column(modifier = Modifier.fillMaxSize()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            ) {
                QrScanner(
                    modifier = Modifier.fillMaxSize(),
                    onDecoded = onDecoded,
                )
            }
            Text(
                text = "Point the camera at the code on your PC.",
                modifier = Modifier.padding(24.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    } else {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Device Connect needs the camera to read the pairing code.",
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = "The camera is only used for this. Frames are decoded on the " +
                    "phone and never stored or sent anywhere.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = { launcher.launch(Manifest.permission.CAMERA) }) {
                Text("Allow camera access")
            }
        }
    }
}

// ---------- Manual ----------

@Composable
private fun ManualScreen(onConnect: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Type the address your PC shows, as ip:port.",
            style = MaterialTheme.typography.bodyLarge,
        )
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            singleLine = true,
            label = { Text("Address") },
            placeholder = { Text("192.168.1.20:47810") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { onConnect(text) },
            enabled = text.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Connect")
        }
    }
}

// ---------- Discovered ----------

@Composable
private fun DiscoveredScreen(
    peers: List<Discovery.Peer>,
    onSelect: (Discovery.Peer) -> Unit,
    onManual: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        Text(
            text = "Looking for PCs running Device Connect on this network…",
            style = MaterialTheme.typography.bodyMedium,
        )

        if (peers.isEmpty()) {
            Text(
                text = "Nothing found yet. Make sure the PC app is open and both " +
                    "devices are on the same Wi-Fi network.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            for (peer in peers) {
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
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = peer.name, style = MaterialTheme.typography.titleMedium)
                            Text(
                                text = "${peer.host}:${peer.port}",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                        Button(onClick = { onSelect(peer) }) { Text("Connect") }
                    }
                }
            }
        }

        OutlinedButton(onClick = onManual, modifier = Modifier.fillMaxWidth()) {
            Text("Enter an address instead")
        }
    }
}

// ---------- Confirm ----------

@Composable
private fun ConfirmScreen(
    link: LinkState,
    onConfirm: () -> Unit,
    onReject: () -> Unit,
) {
    val awaiting = link as? LinkState.AwaitingConfirmation
    if (awaiting == null) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Check that this code matches the one on ${awaiting.peerName}.",
            style = MaterialTheme.typography.bodyLarge,
        )
        Text(
            text = awaiting.code,
            style = MaterialTheme.typography.displayMedium,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier
                .fillMaxWidth()
                .semantics { heading() },
        )
        Text(
            text = "If the codes are different, someone may be intercepting the " +
                "connection. Do not continue.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = onConfirm, modifier = Modifier.fillMaxWidth()) {
            Text("The codes match")
        }
        OutlinedButton(onClick = onReject, modifier = Modifier.fillMaxWidth()) {
            Text("They are different - stop")
        }
        Text(
            text = "Device ID ${awaiting.peerId}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---------- Connected ----------

@Composable
private fun ConnectedScreen(
    link: LinkState,
    deviceId: String,
    onDisconnect: () -> Unit,
) {
    val connected = link as? LinkState.Connected
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusBanner(link = link)
        Text(
            text = connected?.let { "Your PC (${it.peerName}) is connected to this phone." }
                ?: "This phone is connected to your PC.",
            style = MaterialTheme.typography.bodyLarge,
        )
        Text(
            text = "Device ID $deviceId",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        HorizontalDivider()
        Text(
            text = "While this is connected the notification in the status bar shows " +
                "it, and the only action on it ends the connection.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_disconnect))
        }
    }
}

// ---------- shared ----------

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
