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
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Mono = FontFamily.Monospace

/** The start-up animation plays once per process (not again after rotation). */
private var introPlayed = false

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording or recent-apps thumbnails of the chat.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        MuteController.initialize(this)
        setContent { MuteRoot() }
    }

    /** Any touch or key press counts as activity for the idle auto-lock. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        MuteController.touch()
    }
}

private fun startKeepAlive(ctx: Context) {
    ContextCompat.startForegroundService(ctx, Intent(ctx, MuteService::class.java))
}

@Composable
private fun MuteRoot() {
    val theme by MuteController.theme.collectAsStateWithLifecycle()
    val view = LocalView.current
    SideEffect {
        (view.context as? Activity)?.window?.let { w ->
            WindowCompat.getInsetsController(w, view).apply {
                isAppearanceLightStatusBars = theme.isLight
                isAppearanceLightNavigationBars = theme.isLight
            }
        }
    }
    MaterialTheme(colorScheme = theme.scheme()) {
        Box(Modifier.fillMaxSize().background(theme.bg).safeDrawingPadding()) {
            MuteApp()
        }
    }
}

@Composable
private fun MuteApp() {
    val s by MuteController.ui.collectAsStateWithLifecycle()
    val locked by MuteController.locked.collectAsStateWithLifecycle()
    var intro by remember { mutableStateOf(!introPlayed && !s.started) }
    if (s.started) ChatScreen(s) else SetupScreen(s)
    if (intro) IntroScreen { introPlayed = true; intro = false }
    // while locked nothing may be shown - a pending fingerprint prompt waits (it times out after 3 minutes)
    if (!locked) s.confirm?.let { ConfirmDialog(it) }
    if (locked) LockScreen()
}

// ------------------------------------------------------------------ setup
@Composable
private fun SetupScreen(s: UiState) {
    val ctx = LocalContext.current
    val settings by MuteController.settings.collectAsStateWithLifecycle()
    var idState by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var burner by remember { mutableStateOf(false) }
    var tor by remember { mutableStateOf(false) }
    var showOptions by remember { mutableStateOf(false) }
    var opts by remember { mutableStateOf(Options()) }

    LaunchedEffect(Unit) {
        idState = withContext(Dispatchers.IO) {
            try { MuteController.identityState(ctx) } catch (e: Exception) { "" }
        }
    }

    fun go() {
        startKeepAlive(ctx)
        MuteController.start(ctx, pass, burner, tor, opts.copy(amnesia = opts.amnesia || burner))
    }

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        // The service runs either way; without the permission the notification is just hidden.
        go()
    }

    val needsPass = idState == "encrypted" && !burner
    Column(
        Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("MUTE", fontSize = 34.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.secondary)
        Text(
            "Serverless end-to-end encrypted chat and file transfer.",
            color = MaterialTheme.colorScheme.outline, fontSize = 14.sp,
        )

        Text("1. Choose connection", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            ModeCard(
                title = "DIRECT", subtitle = "Plain TCP, port 5555.\nLAN, port forward or VPN.",
                selected = !tor, modifier = Modifier.weight(1f),
            ) { tor = false }
            ModeCard(
                title = "TOR", subtitle = "Onion address.\nHides both IP addresses.",
                selected = tor, modifier = Modifier.weight(1f),
            ) { tor = true }
        }
        if (tor) {
            Text(
                "Tor starts when you press START (up to a minute). Bridges and proxy: Options > Tor bridges. " +
                    "After start you get your .onion address; to reach someone, type their .onion address in the chat screen.",
                color = MaterialTheme.colorScheme.outline, fontSize = 12.sp,
            )
        }

        Text("2. Identity", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        SwitchRow("Burner identity (random key, nothing saved)", burner) { burner = it }
        if (!burner) {
            OutlinedTextField(
                value = pass, onValueChange = { pass = it }, singleLine = true,
                shape = RoundedCornerShape(14.dp),
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

        OutlinedButton(onClick = { showOptions = !showOptions }, shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
            Text(if (showOptions) "Hide options" else "Options")
        }
        if (showOptions) {
            OptionsPanel(
                opts = opts, onOpts = { opts = it },
                settings = settings, onSettings = { MuteController.updateSettings(it) },
                tor = tor, started = false, state = null, saveTheme = !(burner || opts.amnesia),
            )
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
                    go()
                }
            },
            enabled = !s.busy && (!needsPass || pass.isNotEmpty()),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        ) { Text(if (s.busy) "Starting..." else if (tor) "START TOR" else "START DIRECT", fontWeight = FontWeight.Bold) }
    }
}

@Composable
private fun ModeCard(title: String, subtitle: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    val accent = MaterialTheme.colorScheme.secondary
    Column(
        modifier
            .clip(shape)
            .background(if (selected) accent.copy(alpha = 0.16f) else MaterialTheme.colorScheme.surface)
            .border(BorderStroke(if (selected) 2.dp else 1.dp, if (selected) accent else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)), shape)
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(title, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = if (selected) accent else MaterialTheme.colorScheme.onSurface)
        Text(subtitle, fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)
    }
}

// ------------------------------------------------------------------ chat
@Composable
private fun ChatScreen(s: UiState) {
    var showOptions by remember { mutableStateOf(false) }
    if (showOptions) {
        OptionsScreen(s, onClose = { showOptions = false })
    } else {
        ChatBody(s, onOptions = { showOptions = true })
    }
}

@Composable
private fun OptionsScreen(s: UiState, onClose: () -> Unit) {
    val settings by MuteController.settings.collectAsStateWithLifecycle()
    var opts by remember { mutableStateOf(MuteController.currentOptions()) }
    Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("OPTIONS", Modifier.weight(1f), fontFamily = Mono, fontSize = 20.sp)
            Button(onClick = { MuteController.applyOptions(opts); onClose() }) { Text("Apply") }
            TextButton(onClick = onClose) { Text("Close") }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            OptionsPanel(
                opts = opts, onOpts = { opts = it },
                settings = settings, onSettings = { MuteController.updateSettings(it) },
                tor = s.transport == "tor", started = true, state = s,
                saveTheme = !(s.burner || s.options.amnesia),
            )
        }
    }
}

@Composable
private fun ChatBody(s: UiState, onOptions: () -> Unit) {
    val ctx = LocalContext.current
    val theme by MuteController.theme.collectAsStateWithLifecycle()
    var addr by remember { mutableStateOf("") }
    var peerFp by remember { mutableStateOf("") }
    var input by remember { mutableStateOf("") }
    var renaming by remember { mutableStateOf<Peer?>(null) }
    val listState = rememberLazyListState()
    val clock = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    LaunchedEffect(s.lines.size) {
        if (s.lines.isNotEmpty()) listState.animateScrollToItem(s.lines.size - 1)
    }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) MuteController.sendUri(ctx, uri)
    }
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) MuteController.sendTree(ctx, uri)
    }

    val myAddress = s.onion ?: s.ips.firstOrNull()?.let { "$it:5555" } ?: ""

    Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // identity card: what the other person needs to verify you
        Column(Modifier.fillMaxWidth().background(theme.chat).padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    (if (s.transport == "tor") "TOR" else "DIRECT") + "  ${s.peers.size} peer(s)",
                    Modifier.weight(1f), fontFamily = Mono, color = theme.dim,
                )
            }
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = { MuteController.lock() }) { Text("LOCK") }
                TextButton(onClick = { MuteController.wipeChat() }) { Text("WIPE") }
                TextButton(onClick = onOptions) { Text("OPTIONS") }
                OutlinedButton(
                    onClick = {
                        MuteController.shutdown()
                        ctx.startService(Intent(ctx, MuteService::class.java).setAction(MuteService.ACTION_STOP))
                        (ctx as? Activity)?.finishAndRemoveTask()
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = theme.red),
                ) { Text("PANIC") }
            }
            SelectionContainer {
                Column {
                    Text("words: ${s.words}", fontFamily = Mono, fontSize = 13.sp)
                    Text("fp: ${s.fp}", fontFamily = Mono, fontSize = 11.sp, color = theme.dim)
                    if (myAddress.isNotEmpty()) Text("addr: $myAddress", fontFamily = Mono, fontSize = 11.sp, color = theme.dim)
                }
            }
            Row {
                TextButton(onClick = { MuteController.copy(ctx, "fingerprint", s.fp) }) { Text("Copy fp") }
                if (myAddress.isNotEmpty()) {
                    TextButton(onClick = { MuteController.copy(ctx, "address", myAddress) }) { Text("Copy address") }
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
                    OutlinedButton(
                        onClick = { renaming = p },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = theme.peerColor(p.color)),
                    ) { Text(p.name, fontFamily = Mono) }
                }
            }
        }

        // messages
        LazyColumn(Modifier.weight(1f).fillMaxWidth().background(theme.chat), state = listState) {
            items(s.lines, key = { it.id }) { line -> LineRow(line, theme, clock) }
        }

        // file queue
        if (s.queue.isNotEmpty()) {
            Column {
                s.queue.forEach { q ->
                    Text("#${q.id} ${q.name} [${q.state}]", fontFamily = Mono, fontSize = 12.sp, color = theme.dim)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { MuteController.togglePause() }) {
                        Text(if (s.options.paused) "Resume transfers" else "Pause transfers")
                    }
                    TextButton(onClick = { MuteController.cancelTransfers() }) { Text("Cancel all") }
                }
            }
        }
        s.transfer?.let { t ->
            Column {
                Text("${t.label} ${t.done * 100 / t.total}%", fontFamily = Mono, fontSize = 12.sp, color = theme.dim)
                LinearProgressIndicator(progress = { t.done.toFloat() / t.total }, modifier = Modifier.fillMaxWidth())
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(2.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { filePicker.launch(arrayOf("*/*")) }, enabled = s.peers.isNotEmpty()) { Text("FILE") }
            TextButton(onClick = { folderPicker.launch(null) }, enabled = s.peers.isNotEmpty()) { Text("FOLDER") }
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
                    Text("Only you see this name. It is never sent or saved.", fontSize = 12.sp, color = theme.dim)
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
private fun LineRow(line: ChatLine, theme: ThemeColors, clock: SimpleDateFormat) {
    val time = "[${clock.format(Date(line.ts))}] "
    when (line.kind) {
        Kind.SYS -> Text("$time[*] ${line.text}", fontFamily = Mono, fontSize = 12.sp, color = theme.dim)
        Kind.FILE -> Text("$time[+] ${line.text}", fontFamily = Mono, fontSize = 13.sp, color = theme.dim)
        Kind.ME -> Text("${time}me> ${line.text}", fontFamily = Mono, fontSize = 14.sp, color = theme.fg)
        Kind.PEER -> Text(
            "$time${line.who}> ${line.text}", fontFamily = Mono, fontSize = 14.sp,
            color = theme.peerColor(line.color),
        )
    }
}

// ------------------------------------------------------------------ lock screen
@Composable
private fun LockScreen() {
    val theme by MuteController.theme.collectAsStateWithLifecycle()
    val settings by MuteController.settings.collectAsStateWithLifecycle()
    var attempt by remember { mutableStateOf("") }
    var wrong by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().background(theme.bg).padding(24.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("LOCKED", fontFamily = Mono, fontSize = 28.sp)
        if (settings.lockPassword.isNotEmpty()) {
            OutlinedTextField(
                value = attempt, onValueChange = { attempt = it; wrong = false }, singleLine = true,
                label = { Text(if (wrong) "Wrong password" else "Password") },
                isError = wrong, visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
            )
        } else {
            Text("Press Unlock. Set a lock password in Options.", fontFamily = Mono, fontSize = 12.sp,
                color = theme.dim, modifier = Modifier.padding(top = 8.dp))
        }
        Button(
            onClick = { if (!MuteController.unlock(attempt)) { wrong = true; attempt = "" } },
            modifier = Modifier.padding(top = 16.dp),
        ) { Text("Unlock") }
    }
}

// ------------------------------------------------------------------ fingerprint check
@Composable
private fun ConfirmDialog(c: Confirm) {
    val theme by MuteController.theme.collectAsStateWithLifecycle()
    AlertDialog(
        onDismissRequest = { MuteController.answerConfirm(false) },
        title = { Text("Unknown peer") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Compare these words with the other person over a DIFFERENT channel (phone call, in person).")
                SelectionContainer {
                    Column {
                        Text(c.words, fontFamily = Mono, fontSize = 16.sp)
                        Text(c.fp, fontFamily = Mono, fontSize = 11.sp, color = theme.dim)
                    }
                }
            }
        },
        confirmButton = { Button(onClick = { MuteController.answerConfirm(true) }) { Text("They match") } },
        dismissButton = { TextButton(onClick = { MuteController.answerConfirm(false) }) { Text("Reject") } },
    )
}
