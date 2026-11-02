package hu.speeder.mute

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val Green = Color(0xFF00FF66)
private val Dim = Color(0xFF6FA882)
private val Panel = Color(0xFF0B140E)
private val Mono = FontFamily.Monospace

private val HackerColors = darkColorScheme(
    primary = Green, onPrimary = Color.Black,
    background = Color.Black, onBackground = Green,
    surface = Panel, onSurface = Green,
    error = Color(0xFFFF5555),
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording or recent-apps thumbnails of the chat.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            MaterialTheme(colorScheme = HackerColors) {
                Surface(Modifier.fillMaxSize().safeDrawingPadding(), color = Color.Black) {
                    MuteApp()
                }
            }
        }
    }
}

private fun startKeepAlive(ctx: Context) {
    ContextCompat.startForegroundService(ctx, Intent(ctx, MuteService::class.java))
}

@Composable
private fun MuteApp() {
    val s by MuteController.ui.collectAsStateWithLifecycle()
    if (s.started) ChatScreen(s) else SetupScreen(s)
    s.confirm?.let { ConfirmDialog(it) }
}

// ------------------------------------------------------------------ setup
@Composable
private fun SetupScreen(s: UiState) {
    val ctx = LocalContext.current
    var idState by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var burner by remember { mutableStateOf(false) }
    var tor by remember { mutableStateOf(false) }
    var bridges by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        idState = withContext(Dispatchers.IO) {
            try { MuteController.identityState(ctx) } catch (e: Exception) { "" }
        }
    }

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        // The service runs either way; without the permission the notification is just hidden.
        startKeepAlive(ctx)
        MuteController.start(ctx, pass, burner, tor, bridges)
    }

    val needsPass = idState == "encrypted" && !burner
    Column(
        Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("MUTE", fontFamily = Mono, fontSize = 28.sp)
        Text("Serverless end-to-end encrypted chat and file transfer.", color = Dim, fontFamily = Mono)

        ToggleRow("Burner identity (random key, nothing saved)", burner) { burner = it }
        if (!burner) {
            OutlinedTextField(
                value = pass, onValueChange = { pass = it }, singleLine = true,
                label = {
                    Text(
                        when (idState) {
                            "encrypted" -> "Identity passphrase"
                            "missing" -> "New identity passphrase (empty = none)"
                            else -> "Identity passphrase (not needed)"
                        }
                    )
                },
                enabled = idState != "plain",
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        ToggleRow("Tor mode (onion address, hides both IPs)", tor) { tor = it }
        if (tor) {
            OutlinedTextField(
                value = bridges, onValueChange = { bridges = it },
                label = { Text("Bridges (optional, one per line)") },
                modifier = Modifier.fillMaxWidth(), minLines = 3,
            )
            Text("Starting Tor can take up to a minute.", color = Dim, fontFamily = Mono, fontSize = 12.sp)
        } else {
            Text("DIRECT: plain TCP on port 5555 (LAN, port forward or VPN).", color = Dim, fontFamily = Mono, fontSize = 12.sp)
        }

        s.error?.let { Text(it, color = MaterialTheme.colorScheme.error, fontFamily = Mono) }

        Button(
            onClick = {
                if (Build.VERSION.SDK_INT >= 33 &&
                    ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED
                ) {
                    notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    startKeepAlive(ctx)
                    MuteController.start(ctx, pass, burner, tor, bridges)
                }
            },
            enabled = !s.busy && (!needsPass || pass.isNotEmpty()),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (s.busy) "Starting..." else "START") }
    }
}

@Composable
private fun ToggleRow(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), fontFamily = Mono)
        Switch(checked = value, onCheckedChange = onChange)
    }
}

// ------------------------------------------------------------------ chat
@Composable
private fun ChatScreen(s: UiState) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var addr by remember { mutableStateOf("") }
    var peerFp by remember { mutableStateOf("") }
    var input by remember { mutableStateOf("") }
    var renaming by remember { mutableStateOf<Peer?>(null) }
    val listState = rememberLazyListState()

    LaunchedEffect(s.lines.size) {
        if (s.lines.isNotEmpty()) listState.animateScrollToItem(s.lines.size - 1)
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) MuteController.sendUri(ctx, uri)
    }

    val myAddress = s.onion ?: s.ips.firstOrNull()?.let { "$it:5555" } ?: ""

    Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // identity card: what the other person needs to verify you
        Column(Modifier.fillMaxWidth().background(Panel).padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (s.transport == "tor") "TOR" else "DIRECT", fontFamily = Mono, color = Dim)
                Text("  ${s.peers.size} peer(s)", Modifier.weight(1f), fontFamily = Mono, color = Dim)
                OutlinedButton(
                    onClick = {
                        MuteController.shutdown()
                        ctx.startService(Intent(ctx, MuteService::class.java).setAction(MuteService.ACTION_STOP))
                        (ctx as? Activity)?.finishAndRemoveTask()
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("PANIC") }
            }
            SelectionContainer {
                Column {
                    Text("words: ${s.words}", fontFamily = Mono, fontSize = 13.sp)
                    Text("fp: ${s.fp}", fontFamily = Mono, fontSize = 11.sp, color = Dim)
                    if (myAddress.isNotEmpty()) Text("addr: $myAddress", fontFamily = Mono, fontSize = 11.sp, color = Dim)
                }
            }
            Row {
                TextButton(onClick = { clipboard.setText(AnnotatedString(s.fp)) }) { Text("Copy fp") }
                if (myAddress.isNotEmpty()) {
                    TextButton(onClick = { clipboard.setText(AnnotatedString(myAddress)) }) { Text("Copy address") }
                }
            }
        }

        // connect
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = addr, onValueChange = { addr = it }, singleLine = true,
                label = { Text(if (s.transport == "tor") "peer .onion[:port]" else "peer host[:port]") },
                modifier = Modifier.weight(1f),
            )
            OutlinedTextField(
                value = peerFp, onValueChange = { peerFp = it }, singleLine = true,
                label = { Text("fp (optional)") }, modifier = Modifier.weight(1f),
            )
            Button(onClick = { MuteController.connect(addr, peerFp); addr = "" }, enabled = addr.isNotBlank()) {
                Text("GO")
            }
        }

        // peers: tap to give someone a name (only you see it)
        if (s.peers.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.horizontalScroll(rememberScrollState()),
            ) {
                s.peers.forEach { p ->
                    OutlinedButton(onClick = { renaming = p }) { Text(p.name, fontFamily = Mono) }
                }
            }
        }

        // messages
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = listState) {
            items(s.lines, key = { it.id }) { line -> LineRow(line) }
        }

        s.transfer?.let { t ->
            Column {
                Text("${t.label} ${t.done * 100 / t.total}%", fontFamily = Mono, fontSize = 12.sp, color = Dim)
                LinearProgressIndicator(progress = { t.done.toFloat() / t.total }, modifier = Modifier.fillMaxWidth())
                TextButton(onClick = { MuteController.cancelTransfers() }) { Text("Cancel transfers") }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { picker.launch(arrayOf("*/*")) }, enabled = s.peers.isNotEmpty()) { Text("FILE") }
            OutlinedTextField(
                value = input, onValueChange = { input = it },
                placeholder = { Text("message") }, modifier = Modifier.weight(1f), maxLines = 4,
            )
            Button(
                onClick = { MuteController.sendText(input); input = "" },
                enabled = input.isNotBlank() && s.peers.isNotEmpty(),
            ) { Text("SEND") }
        }
    }

    renaming?.let { p ->
        var name by remember(p.fp) { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text("Name this peer") },
            text = {
                Column {
                    Text("Only you see this name. It is never sent or saved.", fontSize = 12.sp, color = Dim)
                    OutlinedTextField(value = name, onValueChange = { name = it.take(24) }, singleLine = true)
                }
            },
            confirmButton = {
                TextButton(onClick = { MuteController.namePeer(p.fp, name); renaming = null }, enabled = name.isNotBlank()) {
                    Text("OK")
                }
            },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun LineRow(line: ChatLine) {
    when (line.kind) {
        Kind.SYS -> Text("[*] ${line.text}", fontFamily = Mono, fontSize = 12.sp, color = Dim)
        Kind.FILE -> Text("[+] ${line.text}", fontFamily = Mono, fontSize = 13.sp, color = Dim)
        Kind.ME -> Text("me> ${line.text}", fontFamily = Mono, fontSize = 14.sp, color = Green)
        Kind.PEER -> Text("${line.who}> ${line.text}", fontFamily = Mono, fontSize = 14.sp, color = Color.White)
    }
}

// ------------------------------------------------------------------ fingerprint check
@Composable
private fun ConfirmDialog(c: Confirm) {
    AlertDialog(
        onDismissRequest = { MuteController.answerConfirm(false) },
        title = { Text("Unknown peer") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Compare these words with the other person over a DIFFERENT channel (phone call, in person).")
                SelectionContainer {
                    Column {
                        Text(c.words, fontFamily = Mono, fontSize = 16.sp)
                        Text(c.fp, fontFamily = Mono, fontSize = 11.sp, color = Dim)
                    }
                }
            }
        },
        confirmButton = { Button(onClick = { MuteController.answerConfirm(true) }) { Text("They match") } },
        dismissButton = { TextButton(onClick = { MuteController.answerConfirm(false) }) { Text("Reject") } },
    )
}
