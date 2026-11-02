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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.ui.text.style.TextAlign
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

// ------------------------------------------------------------------ chat (tabs: Chat, Connect, Files, Settings)
private enum class Tab(val label: String) { CHAT("Chat"), CONNECT("Connect"), FILES("Files"), SETTINGS("Settings") }

@Composable
private fun ChatScreen(s: UiState) {
    val ctx = LocalContext.current
    val theme by MuteController.theme.collectAsStateWithLifecycle()
    var tab by remember { mutableStateOf(Tab.CHAT) }

    Column(Modifier.fillMaxSize()) {
        // slim header: status on the left, the two quick safety actions on the right
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("MUTE", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = theme.acc)
                Text(
                    (if (s.transport == "tor") "TOR" else "DIRECT") + "  ·  ${s.peers.size} peer(s)",
                    fontSize = 12.sp, color = theme.dim,
                )
            }
            TextButton(onClick = { MuteController.lock() }) { Text("LOCK") }
            // STOP ends the session (connection, Tor, chat) and returns to the start screen; the app stays open.
            TextButton(
                onClick = {
                    MuteController.shutdown()
                    ctx.startService(Intent(ctx, MuteService::class.java).setAction(MuteService.ACTION_STOP))
                },
            ) { Text("STOP") }
            TextButton(
                onClick = {
                    MuteController.shutdown()
                    ctx.startService(Intent(ctx, MuteService::class.java).setAction(MuteService.ACTION_STOP))
                    (ctx as? Activity)?.finishAndRemoveTask()
                },
                colors = ButtonDefaults.textButtonColors(contentColor = theme.red),
            ) { Text("PANIC") }
        }

        Box(Modifier.weight(1f).fillMaxWidth()) {
            when (tab) {
                Tab.CHAT -> ChatTab(s, theme, onConnect = { tab = Tab.CONNECT })
                Tab.CONNECT -> ConnectTab(s, theme)
                Tab.FILES -> FilesTab(s, theme)
                Tab.SETTINGS -> SettingsTab(s)
            }
        }

        NavigationBar(containerColor = theme.chat, windowInsets = WindowInsets(0, 0, 0, 0)) {
            Tab.values().forEach { t ->
                NavigationBarItem(
                    selected = tab == t, onClick = { tab = t },
                    icon = { Text(when (t) { Tab.CHAT -> "💬"; Tab.CONNECT -> "🔗"; Tab.FILES -> "📁"; Tab.SETTINGS -> "⚙" }, fontSize = 18.sp) },
                    label = { Text(t.label, fontSize = 12.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedTextColor = theme.acc, unselectedTextColor = theme.dim,
                        indicatorColor = theme.acc.copy(alpha = 0.18f),
                    ),
                )
            }
        }
    }
}

// ---- Chat tab: peers, bubbles, big message bar
@Composable
private fun ChatTab(s: UiState, theme: ThemeColors, onConnect: () -> Unit) {
    val ctx = LocalContext.current
    var input by remember { mutableStateOf("") }
    var renaming by remember { mutableStateOf<Peer?>(null) }
    var attachMenu by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val clock = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }

    LaunchedEffect(s.lines.size) {
        if (s.lines.isNotEmpty()) listState.animateScrollToItem(s.lines.size - 1)
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) MuteController.sendUri(ctx, uri)
    }
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) MuteController.sendTree(ctx, uri)
    }
    val canSend = s.peers.isNotEmpty()

    Column(Modifier.fillMaxSize().padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (s.peers.isNotEmpty()) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                s.peers.forEach { p ->
                    OutlinedButton(
                        onClick = { renaming = p }, shape = RoundedCornerShape(20.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = theme.peerColor(p.color)),
                    ) { Text(p.name) }
                }
            }
        }

        Box(
            Modifier.weight(1f).fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(theme.chat),
        ) {
            if (s.lines.isEmpty()) {
                Text("No messages yet.", Modifier.align(Alignment.Center), color = theme.dim)
            }
            LazyColumn(
                Modifier.fillMaxSize(), state = listState,
                contentPadding = androidx.compose.foundation.layout.PaddingValues(10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(s.lines, key = { it.id }) { line -> LineRow(line, theme, clock) }
            }
        }

        if (!canSend) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Nobody connected yet.", Modifier.weight(1f), color = theme.dim, fontSize = 13.sp)
                TextButton(onClick = onConnect) { Text("CONNECT") }
            }
        }
        s.transfer?.let { t ->
            Column {
                Text("${t.label} ${t.done * 100 / t.total}%", fontSize = 12.sp, color = theme.dim)
                LinearProgressIndicator(progress = { t.done.toFloat() / t.total }, modifier = Modifier.fillMaxWidth())
            }
        }

        // message bar: attach, large rounded field, round send button
        Row(Modifier.fillMaxWidth().padding(bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Bottom) {
            Box {
                Button(
                    onClick = { attachMenu = true }, enabled = canSend, shape = CircleShape,
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = theme.btn, contentColor = theme.fg),
                    modifier = Modifier.size(52.dp),
                ) { Text("+", fontSize = 24.sp) }
                DropdownMenu(expanded = attachMenu, onDismissRequest = { attachMenu = false }) {
                    DropdownMenuItem(text = { Text("Send a file") }, onClick = { attachMenu = false; filePicker.launch(arrayOf("*/*")) })
                    DropdownMenuItem(text = { Text("Send a folder") }, onClick = { attachMenu = false; folderPicker.launch(null) })
                }
            }
            OutlinedTextField(
                value = input, onValueChange = { input = it },
                placeholder = { Text(if (canSend) "Message" else "Connect to someone first") },
                shape = RoundedCornerShape(26.dp), maxLines = 5,
                modifier = Modifier.weight(1f).heightIn(min = 52.dp),
            )
            Button(
                onClick = { MuteController.sendText(input); input = "" },
                enabled = input.isNotBlank() && canSend, shape = CircleShape,
                contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
                modifier = Modifier.size(52.dp),
            ) { Text("➤", fontSize = 20.sp) }
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
                TextButton(onClick = { MuteController.namePeer(p.fp, name); renaming = null }, enabled = name.isNotBlank()) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
        )
    }
}

// ---- Connect tab: connect to a peer, and what to send them
@Composable
private fun ConnectTab(s: UiState, theme: ThemeColors) {
    val ctx = LocalContext.current
    var addr by remember { mutableStateOf("") }
    var peerFp by remember { mutableStateOf("") }
    val myAddress = s.onion ?: s.ips.firstOrNull()?.let { "$it:5555" } ?: ""

    Column(
        Modifier.fillMaxSize().padding(horizontal = 12.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(theme, "CONNECT TO SOMEONE") {
            OutlinedTextField(
                value = addr, onValueChange = { addr = it }, singleLine = true, shape = RoundedCornerShape(14.dp),
                label = { Text(if (s.transport == "tor") "Their .onion address[:port]" else "Their host[:port]") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = peerFp, onValueChange = { peerFp = it }, singleLine = true, shape = RoundedCornerShape(14.dp),
                label = { Text("Their fingerprint (optional, checked on connect)") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = { MuteController.connect(addr, peerFp); addr = "" },
                enabled = addr.isNotBlank(), shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth(),
            ) { Text("CONNECT", fontWeight = FontWeight.Bold) }
        }

        SectionCard(theme, "SEND THIS TO YOUR PEER") {
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("Address", fontSize = 11.sp, color = theme.dim)
                    if (myAddress.isNotEmpty()) {
                        Text(myAddress, fontFamily = Mono, fontSize = 13.sp, color = theme.fg)
                    } else {
                        Text(
                            if (s.transport == "tor") "Waiting for Tor to publish your .onion address..."
                            else "No network address found. Connect to Wi-Fi or mobile data.",
                            fontSize = 13.sp, color = theme.red,
                        )
                    }
                    if (s.transport != "tor" && s.ips.size > 1) {
                        Text("other: " + s.ips.drop(1).joinToString("  ") { "$it:5555" }, fontFamily = Mono, fontSize = 11.sp, color = theme.dim)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text("Verification words", fontSize = 11.sp, color = theme.dim)
                    Text(s.words, fontFamily = Mono, fontSize = 13.sp, color = theme.fg)
                    Spacer(Modifier.height(4.dp))
                    Text("Fingerprint", fontSize = 11.sp, color = theme.dim)
                    Text(s.fp, fontFamily = Mono, fontSize = 11.sp, color = theme.fg)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                if (myAddress.isNotEmpty()) {
                    Button(onClick = {
                        val text = "Mute address: $myAddress\nWords: ${s.words}\nFingerprint: ${s.fp}"
                        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
                        ctx.startActivity(Intent.createChooser(send, "Send to your peer").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }, shape = RoundedCornerShape(12.dp)) { Text("SHARE") }
                    TextButton(onClick = { MuteController.copy(ctx, "address", myAddress) }) { Text("Copy address") }
                }
                TextButton(onClick = { MuteController.copy(ctx, "fingerprint", s.fp) }) { Text("Copy fp") }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

// ---- Files tab
@Composable
private fun FilesTab(s: UiState, theme: ThemeColors) {
    val ctx = LocalContext.current
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) MuteController.sendUri(ctx, uri)
    }
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) MuteController.sendTree(ctx, uri)
    }
    val canSend = s.peers.isNotEmpty()
    Column(
        Modifier.fillMaxSize().padding(horizontal = 12.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(theme, "SEND") {
            if (!canSend) Text("Connect to someone first (Connect tab).", fontSize = 13.sp, color = theme.dim)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { filePicker.launch(arrayOf("*/*")) }, enabled = canSend, shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.weight(1f).heightIn(min = 52.dp)) { Text("📄  File") }
                Button(onClick = { folderPicker.launch(null) }, enabled = canSend, shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.weight(1f).heightIn(min = 52.dp)) { Text("📁  Folder") }
            }
            Text("Folders are sent as one clean zip.", fontSize = 12.sp, color = theme.dim)
        }

        s.transfer?.let { t ->
            SectionCard(theme, "IN PROGRESS") {
                Text("${t.label}  ${t.done * 100 / t.total}%", fontSize = 13.sp)
                LinearProgressIndicator(progress = { t.done.toFloat() / t.total }, modifier = Modifier.fillMaxWidth())
            }
        }

        SectionCard(theme, "QUEUE") {
            if (s.queue.isEmpty()) {
                Text("Nothing waiting.", fontSize = 13.sp, color = theme.dim)
            } else {
                s.queue.forEach { q -> Text("#${q.id}  ${q.name}  [${q.state}]", fontFamily = Mono, fontSize = 12.sp, color = theme.fg) }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { MuteController.togglePause() }) {
                        Text(if (s.options.paused) "Resume transfers" else "Pause transfers")
                    }
                    TextButton(onClick = { MuteController.cancelTransfers() }) { Text("Cancel all") }
                }
            }
        }
        Text("Received files go to Android/data/hu.speeder.mute/files/Mute", fontSize = 11.sp, color = theme.dim)
        Spacer(Modifier.height(8.dp))
    }
}

// ---- Settings tab: wipe + all options
@Composable
private fun SettingsTab(s: UiState) {
    val settings by MuteController.settings.collectAsStateWithLifecycle()
    var opts by remember { mutableStateOf(MuteController.currentOptions()) }
    Column(Modifier.fillMaxSize().padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = { MuteController.applyOptions(opts) }, shape = RoundedCornerShape(12.dp), modifier = Modifier.weight(1f)) {
                Text("APPLY")
            }
            OutlinedButton(onClick = { MuteController.wipeChat() }, shape = RoundedCornerShape(12.dp), modifier = Modifier.weight(1f)) {
                Text("WIPE CHAT")
            }
        }
        val ctx = LocalContext.current
        OutlinedButton(
            onClick = {
                MuteController.shutdown()
                ctx.startService(Intent(ctx, MuteService::class.java).setAction(MuteService.ACTION_STOP))
            },
            shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(),
        ) { Text("STOP SESSION (back to start screen)") }
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
private fun SectionCard(theme: ThemeColors, title: String, content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(theme.chat).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, fontSize = 11.sp, letterSpacing = 1.sp, color = theme.acc, fontWeight = FontWeight.SemiBold)
        content()
    }
}

@Composable
private fun LineRow(line: ChatLine, theme: ThemeColors, clock: SimpleDateFormat) {
    val time = clock.format(Date(line.ts))
    when (line.kind) {
        Kind.SYS -> Text(
            "$time  ${line.text}", fontSize = 11.sp, color = theme.dim,
            modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center,
        )
        Kind.FILE -> Text(
            "📎 ${line.text}  ·  $time", fontSize = 12.sp, color = theme.acc,
            modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center,
        )
        Kind.ME, Kind.PEER -> {
            val mine = line.kind == Kind.ME
            val tint = if (mine) theme.fg else theme.peerColor(line.color)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start) {
                Column(
                    Modifier.widthIn(max = 300.dp)
                        .clip(RoundedCornerShape(18.dp))
                        .background(if (mine) theme.btn else theme.ent)
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    if (!mine) Text(line.who, fontSize = 11.sp, color = tint, fontWeight = FontWeight.SemiBold)
                    SelectionContainer { Text(line.text, fontSize = 15.sp, color = theme.fg) }
                    Text(time, fontSize = 10.sp, color = theme.dim, modifier = Modifier.align(Alignment.End))
                }
            }
        }
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
