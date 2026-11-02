package hu.speeder.mute

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

private val Mono = FontFamily.Monospace

@Composable
fun SectionTitle(text: String) {
    Column(Modifier.padding(top = 8.dp)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
        Text(text.uppercase(), fontFamily = Mono, fontSize = 13.sp, color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.padding(top = 6.dp))
    }
}

@Composable
fun Hint(text: String) {
    Text(text, fontFamily = Mono, fontSize = 11.sp, color = MaterialTheme.colorScheme.outline)
}

@Composable
fun SwitchRow(label: String, checked: Boolean, hint: String? = null, onChange: (Boolean) -> Unit) {
    Column {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(label, Modifier.weight(1f), fontFamily = Mono, fontSize = 14.sp)
            Switch(checked = checked, onCheckedChange = onChange)
        }
        if (hint != null) Hint(hint)
    }
}

@Composable
fun IntField(label: String, value: Int, onValue: (Int) -> Unit) {
    OutlinedTextField(
        value = value.toString(),
        onValueChange = { s -> onValue(s.filter(Char::isDigit).take(6).toIntOrNull() ?: 0) },
        label = { Text(label) }, singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
fun <T> ChipRow(items: List<Pair<String, T>>, selected: T, onSelect: (T) -> Unit) {
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        items.forEach { (label, value) ->
            FilterChip(selected = value == selected, onClick = { onSelect(value) }, label = { Text(label, fontFamily = Mono, fontSize = 12.sp) })
        }
    }
}

/**
 * All options of the desktop Options window. Used on the start screen (before the node exists, so
 * [started] is false and start-only options such as bridges are shown) and on the chat screen.
 */
@Composable
fun OptionsPanel(
    opts: Options, onOpts: (Options) -> Unit,
    settings: AppSettings, onSettings: (AppSettings) -> Unit,
    tor: Boolean, started: Boolean, state: UiState?, saveTheme: Boolean,
) {
    val ctx = LocalContext.current
    val meta by MuteController.meta.collectAsStateWithLifecycle()
    val theme by MuteController.theme.collectAsStateWithLifecycle()

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SectionTitle("Access control")
        SwitchRow(
            "Closed mode", opts.closed,
            "Only allowlisted fingerprints can connect, no prompts.",
        ) { onOpts(opts.copy(closed = it)) }
        OutlinedTextField(
            value = opts.allow, onValueChange = { onOpts(opts.copy(allow = it)) },
            label = { Text("Allowlist: fingerprints, one per line") },
            modifier = Modifier.fillMaxWidth(), minLines = 2,
        )
        OutlinedTextField(
            value = opts.psk, onValueChange = { onOpts(opts.copy(psk = it)) }, singleLine = true,
            label = { Text("Shared secret (both sides must enter the same)") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        Hint("Stops man-in-the-middle even if the fingerprint check is skipped. Use a long passphrase.")

        if (tor) {
            if (!started) {
                OutlinedTextField(
                    value = opts.allowedClients, onValueChange = { onOpts(opts.copy(allowedClients = it)) },
                    label = { Text("Onion client keys allowed to reach you (52 chars each, one per line)") },
                    modifier = Modifier.fillMaxWidth(), minLines = 2,
                )
                Hint("Without a listed key nobody can even find your onion service.")
            } else {
                OutlinedButton(onClick = { MuteController.newClientAuth() }) { Text("Create onion client key") }
                state?.options?.clientAuthPub?.let { pub ->
                    Text(pub, fontFamily = Mono, fontSize = 11.sp)
                    Hint("Give this PUBLIC key to the owner of the onion service you want to reach. It must be on their list before they start.")
                    OutlinedButton(onClick = { MuteController.copy(ctx, "onion client key", pub) }) { Text("Copy key") }
                }
            }
        }

        SectionTitle("Group chat")
        SwitchRow("Relay hub", opts.relay, "Forward messages between peers who are not connected to each other.") {
            onOpts(opts.copy(relay = it))
        }
        SwitchRow("Cover traffic", opts.cover, "Dummy frames that imitate a usage pattern. Adds noise, does not hide when you really talk.") {
            onOpts(opts.copy(cover = it))
        }
        if (opts.cover && meta.coverProfiles.isNotEmpty()) {
            ChipRow(meta.coverProfiles.keys.map { it to it }, opts.coverProfile) { onOpts(opts.copy(coverProfile = it)) }
            meta.coverProfiles[opts.coverProfile]?.let { (text, estimate) -> Hint("$text - $estimate") }
        }
        Text("Constant-rate traffic", fontFamily = Mono, fontSize = 14.sp)
        ChipRow(meta.shapeLabels, opts.shape) { onOpts(opts.copy(shape = it)) }
        Hint(
            if (opts.shape > 0f) MuteController.shapeEstimate(opts.shape, tor)
            else "Every frame the same size on a fixed clock: nobody can see when or how much you talk. Costs bandwidth and speed."
        )

        SectionTitle("Files")
        IntField("Speed limit per peer (KB/s, 0 = unlimited)", opts.speedLimitKbs) { onOpts(opts.copy(speedLimitKbs = it)) }
        SwitchRow("Scrub metadata", opts.scrub, "Strip EXIF, document properties etc. from outgoing files.") {
            onOpts(opts.copy(scrub = it))
        }

        SectionTitle("Privacy")
        SwitchRow("Amnesia (save nothing)", opts.amnesia, "Trusted peers are not remembered between starts.") {
            onOpts(opts.copy(amnesia = it))
        }
        IntField("Key renewal every N seconds (0 = off)", opts.ratchet) { onOpts(opts.copy(ratchet = it)) }
        if (!tor) {
            OutlinedTextField(
                value = opts.proxy, onValueChange = { onOpts(opts.copy(proxy = it)) }, singleLine = true,
                label = { Text("SOCKS5 proxy for direct connections (host:port)") },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (tor && !started) {
            SectionTitle("Tor bridges")
            BridgesBlock(opts, onOpts)
        }

        SectionTitle("App")
        SwitchRow("Clear clipboard 30 s after copying", settings.clipboardClear) {
            onSettings(settings.copy(clipboardClear = it))
        }
        IntField("Auto-clear chat after N minutes (0 = off)", settings.autoClearMin) { onSettings(settings.copy(autoClearMin = it)) }
        IntField("Auto-lock after N idle minutes (0 = off)", settings.autoLockMin) { onSettings(settings.copy(autoLockMin = it)) }
        OutlinedTextField(
            value = settings.lockPassword, onValueChange = { onSettings(settings.copy(lockPassword = it)) },
            singleLine = true, label = { Text("Lock password (empty = Unlock button only)") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        Text("Theme", fontFamily = Mono, fontSize = 14.sp)
        ChipRow(meta.themes.keys.map { it to it }, theme.name) { MuteController.setTheme(it, saveTheme) }
    }
}

/** Tor bridge lines: paste them, or fetch them from the Tor Project (built-in list or captcha). */
@Composable
private fun BridgesBlock(opts: Options, onOpts: (Options) -> Unit) {
    val ctx = LocalContext.current
    val moat by MuteController.moat.collectAsStateWithLifecycle()
    var solution by remember { mutableStateOf("") }

    LaunchedEffect(moat.bridges) {
        moat.bridges?.let { lines ->
            onOpts(opts.copy(bridges = (opts.bridges.trim() + "\n" + lines).trim()))
            MuteController.moatTaken()
        }
    }

    OutlinedTextField(
        value = opts.bridges, onValueChange = { onOpts(opts.copy(bridges = it)) },
        label = { Text("Bridge lines (obfs4, meek_lite, snowflake), one per line") },
        modifier = Modifier.fillMaxWidth(), minLines = 3,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { MuteController.moatBuiltin(ctx, opts.proxy) }, enabled = !moat.busy) { Text("Built-in") }
        OutlinedButton(onClick = { solution = ""; MuteController.moatFetchCaptcha(ctx, opts.proxy) }, enabled = !moat.busy) {
            Text("Get bridges (captcha)")
        }
    }
    if (moat.busy) Hint("Asking the Tor Project...")
    moat.error?.let { Text(it, color = MaterialTheme.colorScheme.error, fontFamily = Mono, fontSize = 12.sp) }
    moat.image?.let { bytes ->
        val bmp = remember(bytes) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap() }
        if (bmp != null) {
            Image(bmp, contentDescription = "captcha", modifier = Modifier.fillMaxWidth().height(110.dp))
        }
        OutlinedTextField(
            value = solution, onValueChange = { solution = it }, singleLine = true,
            label = { Text("Type what the picture shows") }, modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { MuteController.moatSolve(ctx, solution, opts.proxy) }, enabled = solution.isNotBlank() && !moat.busy) {
            Text("Submit")
        }
    }
}
