package hu.speeder.mute

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.OpenableColumns
import androidx.core.app.NotificationCompat
import androidx.documentfile.provider.DocumentFile
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Executors

data class Peer(val fp: String, val name: String, val color: Int)

enum class Kind { ME, PEER, SYS, FILE }

data class ChatLine(
    val id: Long, val who: String, val text: String, val kind: Kind,
    val ts: Long = System.currentTimeMillis(), val color: Int = -1, val via: String = "",
)

data class Confirm(val fp: String, val words: String)

/** A voice call in progress. state: incoming | ringing | active */
data class CallUi(
    val state: String, val fp: String, val name: String,
    val muted: Boolean = false, val remoteMuted: Boolean = false,
    val speaker: Boolean = false, val since: Long = 0L,
)

data class Transfer(val label: String, val done: Long, val total: Long)

data class UiState(
    val started: Boolean = false,
    val busy: Boolean = false,
    val error: String? = null,
    val fp: String = "",
    val words: String = "",
    val ips: List<String> = emptyList(),
    val transport: String = "direct",
    val onion: String? = null,
    val listening: Boolean = false,
    val burner: Boolean = false,
    val options: OptionsState = OptionsState(),
    val peers: List<Peer> = emptyList(),
    val lines: List<ChatLine> = emptyList(),
    val queue: List<QueueItem> = emptyList(),
    val confirm: Confirm? = null,
    val transfer: Transfer? = null,
    val namePrompt: Peer? = null,
    val call: CallUi? = null,
)

/**
 * Process-wide owner of the Python node (android/python/android_bridge.py -> mute.Node).
 * All protocol and crypto work happens in Python; this class forwards calls, turns the bridge's
 * JSON events into [UiState], and implements the app-side features (lock screen, auto-clear,
 * clipboard clearing, themes). Nothing is written to disk except what mute.py itself stores
 * (identity key, optional known-peers list) and the theme name, in the app's private directory.
 */
object MuteController {
    private const val DIRECT_PORT = 5555
    private const val MAX_LINES = 500
    private const val CLIPBOARD_CLEAR_MS = 30_000L
    private const val CALL_NOTIFICATION_ID = 2

    private val pool = Executors.newCachedThreadPool()
    private val main = Handler(Looper.getMainLooper())

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    private val _meta = MutableStateFlow(Meta())
    val meta: StateFlow<Meta> = _meta

    private val _theme = MutableStateFlow(ThemeColors.HACKER)
    val theme: StateFlow<ThemeColors> = _theme

    private val _settings = MutableStateFlow(AppSettings())
    val settings: StateFlow<AppSettings> = _settings

    private val _locked = MutableStateFlow(false)
    val locked: StateFlow<Boolean> = _locked

    private val _moat = MutableStateFlow(MoatState())
    val moat: StateFlow<MoatState> = _moat

    @Volatile private var bridge: PyObject? = null
    @Volatile private var polling = false
    @Volatile private var nextId = 0L
    @Volatile private var lastTouch = System.currentTimeMillis()
    @Volatile private var applied: Options? = null
    @Volatile private var maintenanceStarted = false
    private val peerColors = LinkedHashMap<String, Int>()
    private lateinit var app: Context

    private fun ensurePython(ctx: Context) {
        if (!Python.isStarted()) Python.start(AndroidPlatform(ctx.applicationContext))
    }

    private fun py() = Python.getInstance().getModule("android_bridge")

    private fun dataDir(ctx: Context) = File(ctx.filesDir, "mute")
    private fun outgoingDir(ctx: Context) = File(ctx.cacheDir, "outgoing")
    private fun downloadDir(ctx: Context) =
        ctx.getExternalFilesDir("Mute") ?: File(ctx.filesDir, "downloads")

    /** Python exceptions arrive as "ClassName: message"; the user only needs the message. */
    private fun message(e: Exception, fallback: String): String =
        (e.message ?: fallback).substringAfter(": ", e.message ?: fallback).ifBlank { fallback }

    /** Loads themes and option metadata from mute.py and the saved theme name. Call once at startup. */
    fun initialize(ctx: Context) {
        app = ctx.applicationContext
        pool.execute {
            try {
                ensurePython(app)
                val m = py()
                val themes = ThemeColors.parseAll(m.callAttr("themes").toString())
                val cover = JSONObject(m.callAttr("cover_profiles").toString())
                val shapes = JSONArray(m.callAttr("shape_labels").toString())
                _meta.value = Meta(
                    themes = themes,
                    coverProfiles = cover.keys().asSequence().associateWith {
                        cover.getJSONObject(it).let { o -> o.getString("text") to o.getString("estimate") }
                    },
                    shapeLabels = List(shapes.length()) {
                        shapes.getJSONArray(it).let { a -> a.getString(0) to a.getDouble(1).toFloat() }
                    },
                )
                val saved = try { File(dataDir(app), "theme.txt").readText().trim() } catch (_: Exception) { "" }
                (themes[saved] ?: themes["ice"])?.let { _theme.value = it }
            } catch (_: Exception) {
                // keep the built-in hacker theme; the app still works
            }
            startMaintenance()
        }
    }

    fun setTheme(name: String, save: Boolean) {
        val t = _meta.value.themes[name] ?: return
        _theme.value = t
        if (save && ::app.isInitialized) {
            pool.execute {
                try {
                    dataDir(app).mkdirs()
                    File(dataDir(app), "theme.txt").writeText(name)
                } catch (_: Exception) {}
            }
        }
    }

    fun shapeEstimate(rate: Float, tor: Boolean): String =
        if (rate <= 0f || !Python.isStarted()) "off"
        else try { py().callAttr("shape_estimate", rate.toDouble(), tor).toString() } catch (_: Exception) { "" }

    /** "missing", "plain" or "encrypted" - decides whether the setup screen asks for a passphrase. */
    fun identityState(ctx: Context): String {
        ensurePython(ctx)
        return py().callAttr("identity_state", dataDir(ctx).path).toString()
    }

    fun start(ctx: Context, passphrase: String?, burner: Boolean, tor: Boolean, opts: Options) {
        if (_ui.value.busy || bridge != null) return
        app = ctx.applicationContext
        _ui.update { it.copy(busy = true, error = null) }
        pool.execute {
            try {
                ensurePython(app)
                val native = app.applicationInfo.nativeLibraryDir
                val b = py().callAttr(
                    "Bridge",
                    dataDir(app).path, downloadDir(app).path,
                    File(native, "libtor.so").path, native,
                    passphrase?.takeIf { it.isNotEmpty() }, burner, opts.scrub, opts.amnesia,
                )
                bridge = b
                peerColors.clear()
                lastTouch = System.currentTimeMillis()
                startPolling(b)
                _ui.update { it.copy(started = true) }
                applyState(b.callAttr("state").toString())
                b.callAttr("configure", opts.toJson(null))
                applied = opts
                val st = if (tor) b.callAttr("start_tor") else b.callAttr("start_direct", DIRECT_PORT)
                applyState(st.toString())
                _ui.update { it.copy(busy = false) }
            } catch (e: Exception) {
                fail(message(e, "Start failed"))
            }
        }
    }

    private fun fail(msg: String) {
        val b = bridge
        polling = false
        bridge = null
        try { b?.callAttr("shutdown") } catch (_: Exception) {}
        _ui.value = UiState(error = msg)
    }

    /** Applies changed options to the running node (the first start sends everything). */
    fun applyOptions(opts: Options) {
        val b = bridge ?: return
        val prev = applied
        applied = opts
        pool.execute {
            try {
                applyState(b.callAttr("configure", opts.toJson(prev)).toString())
            } catch (e: Exception) {
                applied = prev
                addLine("", message(e, "Invalid option"), Kind.SYS)
            }
        }
    }

    fun currentOptions(): Options = applied ?: Options()

    fun updateSettings(s: AppSettings) {
        _settings.value = s
    }

    /** Creates a new onion client-auth key pair; the public part shows up in state.options.clientAuthPub. */
    fun newClientAuth() {
        val b = bridge ?: return
        pool.execute {
            try {
                applyState(b.callAttr("configure", JSONObject().put("new_client_auth", true).toString()).toString())
            } catch (e: Exception) {
                addLine("", message(e, "Could not create the key"), Kind.SYS)
            }
        }
    }

    // ---- events from Python
    private fun startPolling(b: PyObject) {
        polling = true
        Thread({
            while (polling) {
                try {
                    val arr = JSONArray(b.callAttr("poll", 500).toString())
                    for (i in 0 until arr.length()) handle(arr.getJSONObject(i), b)
                } catch (e: Exception) {
                    if (!polling) break
                    addLine("", "bridge error: ${e.message}", Kind.SYS)
                    Thread.sleep(500)
                }
            }
        }, "mute-poll").apply { isDaemon = true; start() }
    }

    private fun colorOf(fp: String): Int =
        if (fp.isEmpty()) -1 else synchronized(peerColors) { peerColors.getOrPut(fp) { peerColors.size } }

    private fun handle(ev: JSONObject, b: PyObject) {
        when (ev.getString("k")) {
            "sys" -> addLine("", ev.getString("text"), Kind.SYS)
            "msg" -> addLine(ev.getString("name"), ev.getString("text"), Kind.PEER, colorOf(ev.getString("fp")))
            "relayed" -> addLine(
                ev.getString("name"), ev.getString("text"),
                Kind.PEER, colorOf(ev.getString("fp")), via = ev.getString("via"),
            )
            "connected" -> {
                addLine("", "${ev.getString("name")} connected securely", Kind.SYS)
                applyState(b.callAttr("state").toString())
                // offer to give the new peer a name right away (only you see it, and a relay hub passes it on)
                val fp = ev.getString("fp")
                _ui.update { st -> st.copy(namePrompt = st.peers.firstOrNull { it.fp == fp }) }
            }
            "disconnected" -> {
                addLine("", "${ev.getString("name")} disconnected", Kind.SYS)
                applyState(b.callAttr("state").toString())
            }
            "file" -> {
                val name = File(ev.getString("path")).name
                val text = if (ev.getBoolean("ok")) "File received: $name" else "DAMAGED file: $name"
                addLine("", text, Kind.FILE)
            }
            "progress" -> {
                val total = ev.getLong("total")
                val done = ev.getLong("done")
                _ui.update {
                    it.copy(transfer = if (total <= 0 || done >= total) null
                    else Transfer(ev.getString("label"), done, total))
                }
            }
            "queue" -> {
                val a = JSONArray(b.callAttr("queue").toString())
                val items = List(a.length()) {
                    a.getJSONArray(it).let { r -> QueueItem(r.getInt(0), r.getString(1), r.getString(2)) }
                }
                _ui.update { it.copy(queue = items) }
                applyState(b.callAttr("state").toString())
            }
            "confirm" -> _ui.update { it.copy(confirm = Confirm(ev.getString("fp"), ev.getString("words"))) }
            "call" -> onCallEvent(ev.getString("state"), ev.getString("fp"), ev.getString("name"), ev.optString("detail"))
            "audio" -> onAudioEvent(ev.getString("action"), b)
        }
    }

    // ---- voice calls
    private const val CALL_CHANNEL = "mute_calls"
    private val callEnd = mapOf(
        "rejected" to "Call declined", "busy" to "Busy - the other side is already in a call",
        "noanswer" to "No answer", "missed" to "Missed call", "ended" to "Call ended",
        "ended-remote" to "Call ended by the other side",
    )

    private fun onCallEvent(state: String, fp: String, name: String, detail: String) {
        when (state) {
            "incoming" -> {
                _ui.update { it.copy(call = CallUi("incoming", fp, name)) }
                notifyIncoming()
            }
            "ringing" -> _ui.update { it.copy(call = CallUi("ringing", fp, name)) }
            "active" -> {
                clearIncomingNotification()
                _ui.update { st ->
                    st.copy(call = (st.call ?: CallUi("active", fp, name)).copy(state = "active", since = System.currentTimeMillis()))
                }
                if (::app.isInitialized) MuteService.microphone(app, true)
            }
            "remote-mute" -> _ui.update { st -> st.copy(call = st.call?.copy(remoteMuted = detail == "1")) }
            else -> {                                   // the call is over, whatever the reason
                clearIncomingNotification()
                val secs = _ui.value.call?.takeIf { it.state == "active" }?.let { (System.currentTimeMillis() - it.since) / 1000 }
                val text = if (state == "error") "Call failed: $detail" else (callEnd[state] ?: "Call ended")
                addLine("", text + (if (secs != null) " (%d:%02d)".format(secs / 60, secs % 60) else "") +
                    (if (name.isNotEmpty() && state == "missed") " from $name" else ""), Kind.SYS)
                _ui.update { it.copy(call = null) }
                if (::app.isInitialized) MuteService.microphone(app, false)
            }
        }
    }

    private fun onAudioEvent(action: String, b: PyObject) {
        if (!::app.isInitialized) return
        if (action == "start") {
            val err = CallAudio.start(app, b, _ui.value.call?.speaker == true)
            if (err != null) {
                addLine("", "Audio error: $err", Kind.SYS)
                call("call_hangup")
            }
        } else {
            CallAudio.stop()
        }
    }

    private fun notifyIncoming() {
        if (!::app.isInitialized) return
        try {
            val nm = app.getSystemService(NotificationManager::class.java)
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(NotificationChannel(CALL_CHANNEL, "Calls", NotificationManager.IMPORTANCE_HIGH))
            }
            val open = PendingIntent.getActivity(
                app, 2, Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            nm.notify(
                CALL_NOTIFICATION_ID,
                NotificationCompat.Builder(app, CALL_CHANNEL)
                    .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                    .setContentTitle("Incoming call")
                    .setCategory(NotificationCompat.CATEGORY_CALL)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                    .setContentIntent(open).setFullScreenIntent(open, true).setAutoCancel(true)
                    .setTimeoutAfter(45_000).build(),
            )
        } catch (_: Exception) {
        }
    }

    private fun clearIncomingNotification() {
        if (!::app.isInitialized) return
        try { app.getSystemService(NotificationManager::class.java).cancel(CALL_NOTIFICATION_ID) } catch (_: Exception) {}
    }

    /** The Activity reports the result of the microphone permission request. */
    fun setMicPermission(granted: Boolean) { call("set_mic_permission", granted) }

    fun micDenied() {
        addLine("", "Calls need the microphone permission (Android settings -> Apps -> Mute -> Permissions)", Kind.SYS)
        if (_ui.value.call?.state == "incoming") call("call_reject")
    }

    fun startCall(fp: String) = call("call_peer", fp)
    fun acceptCall() = call("call_accept")
    fun rejectCall() = call("call_reject")
    fun hangup() = call("call_hangup")

    fun toggleMute() {
        val c = _ui.value.call ?: return
        _ui.update { it.copy(call = c.copy(muted = !c.muted)) }
        call("call_mute", !c.muted)
    }

    /** Loudspeaker on: the microphone is muted while the other side talks, so the phone does not echo. */
    fun toggleSpeaker() {
        val c = _ui.value.call ?: return
        _ui.update { it.copy(call = c.copy(speaker = !c.speaker)) }
        CallAudio.setSpeaker(!c.speaker)
        call("call_duck", !c.speaker)
    }

    private fun applyState(json: String) {
        val o = JSONObject(json)
        val ips = o.getJSONArray("ips").let { a -> List(a.length()) { a.getString(it) } }
        val peersJson = o.getJSONArray("peers")
        val peers = List(peersJson.length()) {
            peersJson.getJSONObject(it).let { p -> Peer(p.getString("fp"), p.getString("name"), colorOf(p.getString("fp"))) }
        }
        val op = o.getJSONObject("options")
        _ui.update {
            it.copy(
                fp = o.getString("fp"), words = o.getString("words"), ips = ips,
                transport = o.getString("transport"),
                onion = if (o.isNull("onion")) null else o.getString("onion"),
                listening = o.getBoolean("listening"), burner = o.getBoolean("burner"), peers = peers,
                options = OptionsState(
                    closed = op.getBoolean("closed"), relay = op.getBoolean("relay"),
                    cover = op.getBoolean("cover"), shape = op.getDouble("shape").toFloat(),
                    paused = op.getBoolean("paused"), psk = op.getBoolean("psk"),
                    amnesia = op.getBoolean("amnesia"),
                    clientAuthPub = if (op.isNull("client_auth_pub")) null else op.getString("client_auth_pub"),
                    known = op.getInt("known"),
                ),
            )
        }
    }

    private fun addLine(who: String, text: String, kind: Kind, color: Int = -1, via: String = "") {
        _ui.update {
            val line = ChatLine(nextId++, who, text, kind, color = color, via = via)
            it.copy(lines = (it.lines + line).takeLast(MAX_LINES))
        }
    }

    fun dismissNamePrompt() { _ui.update { it.copy(namePrompt = null) } }

    // ---- actions from the UI
    private fun call(name: String, vararg args: Any?) {
        val b = bridge ?: return
        pool.execute {
            try {
                b.callAttr(name, *args)
            } catch (e: Exception) {
                addLine("", message(e, "Error"), Kind.SYS)
            }
        }
    }

    fun connect(address: String, fp: String) = call("connect", address, fp.ifBlank { null })

    fun sendText(text: String) {
        val b = bridge ?: return
        pool.execute {
            try {
                b.callAttr("send_text", text)
                addLine("me", text, Kind.ME)
            } catch (e: Exception) {
                addLine("", message(e, "Not connected"), Kind.SYS)
            }
        }
    }

    /** Copies the picked document into app cache (mute.py needs a real path) and queues it. */
    fun sendUri(ctx: Context, uri: Uri) {
        val b = bridge ?: return
        pool.execute {
            try {
                val name = ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
                    val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (c.moveToFirst() && i >= 0) c.getString(i) else null
                } ?: "file"
                val dir = outgoingDir(ctx).apply { mkdirs() }
                val dst = File(dir, File(name).name)
                ctx.contentResolver.openInputStream(uri)?.use { input ->
                    dst.outputStream().use { input.copyTo(it) }
                } ?: error("Cannot read the selected file")
                b.callAttr("send_file", dst.path)
                addLine("me", "Sending ${dst.name}", Kind.FILE)
            } catch (e: Exception) {
                addLine("", message(e, "Could not send the file"), Kind.SYS)
            }
        }
    }

    /** Copies a picked folder into app cache and queues it; mute.py zips it (and scrubs metadata). */
    fun sendTree(ctx: Context, treeUri: Uri) {
        val b = bridge ?: return
        pool.execute {
            try {
                val root = DocumentFile.fromTreeUri(ctx, treeUri) ?: error("Cannot open the selected folder")
                val dst = File(outgoingDir(ctx).apply { mkdirs() }, File(root.name ?: "folder").name)
                dst.mkdirs()
                copyTree(ctx, root, dst)
                b.callAttr("send_file", dst.path)
                addLine("me", "Sending folder ${dst.name}", Kind.FILE)
            } catch (e: Exception) {
                addLine("", message(e, "Could not send the folder"), Kind.SYS)
            }
        }
    }

    private fun copyTree(ctx: Context, src: DocumentFile, dst: File) {
        for (child in src.listFiles()) {
            val name = File(child.name ?: continue).name
            if (child.isDirectory) {
                copyTree(ctx, child, File(dst, name).apply { mkdirs() })
            } else {
                ctx.contentResolver.openInputStream(child.uri)?.use { input ->
                    File(dst, name).outputStream().use { input.copyTo(it) }
                }
            }
        }
    }

    fun answerConfirm(accept: Boolean) {
        val c = _ui.value.confirm ?: return
        _ui.update { it.copy(confirm = null) }
        call("answer_confirm", c.fp, accept)
    }

    fun namePeer(fp: String, name: String) {
        val b = bridge ?: return
        pool.execute {
            b.callAttr("name_peer", fp, name)
            applyState(b.callAttr("state").toString())
        }
    }

    fun togglePause() {
        if (_ui.value.options.paused) call("resume_transfers") else call("pause_transfers")
    }

    fun cancelTransfers() = call("cancel_transfers")

    // ---- Tor bridges from the Tor Project (works before the node exists)
    fun moatFetchCaptcha(ctx: Context, proxy: String) {
        _moat.update { it.copy(busy = true, error = null, image = null) }
        pool.execute {
            try {
                ensurePython(ctx)
                val o = JSONObject(py().callAttr("moat_captcha", "obfs4", proxy).toString())
                val img = android.util.Base64.decode(o.getString("image"), android.util.Base64.DEFAULT)
                _moat.update { it.copy(busy = false, image = img, challenge = o.getString("challenge")) }
            } catch (e: Exception) {
                _moat.update { it.copy(busy = false, error = message(e, "Could not reach the bridge service")) }
            }
        }
    }

    fun moatSolve(ctx: Context, solution: String, proxy: String) {
        val challenge = _moat.value.challenge
        _moat.update { it.copy(busy = true, error = null) }
        pool.execute {
            try {
                ensurePython(ctx)
                val lines = py().callAttr("moat_solve", challenge, solution, "obfs4", proxy).toString()
                _moat.update { MoatState(bridges = lines) }
            } catch (e: Exception) {
                _moat.update { it.copy(busy = false, image = null, error = message(e, "Wrong answer")) }
            }
        }
    }

    fun moatBuiltin(ctx: Context, proxy: String) {
        _moat.update { MoatState(busy = true) }
        pool.execute {
            try {
                ensurePython(ctx)
                _moat.update { MoatState(bridges = py().callAttr("moat_builtin", proxy).toString()) }
            } catch (e: Exception) {
                _moat.update { MoatState(error = message(e, "Could not reach the bridge service")) }
            }
        }
    }

    fun moatTaken() = _moat.update { MoatState() }

    // ---- clipboard that cleans up after itself
    fun copy(ctx: Context, label: String, text: String) {
        val cm = ctx.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        if (!_settings.value.clipboardClear) return
        main.postDelayed({
            // only wipe it if it still holds what we put there
            val cur = cm.primaryClip?.getItemAt(0)?.text?.toString()
            if (cur == text) {
                if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
                else cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }, CLIPBOARD_CLEAR_MS)
    }

    // ---- lock screen, auto-clear, wipe
    fun touch() { lastTouch = System.currentTimeMillis() }

    fun lock() { if (_ui.value.started) _locked.value = true }

    /** Returns true and unlocks if the password matches (empty password = always matches). */
    fun unlock(attempt: String): Boolean {
        val secret = _settings.value.lockPassword
        val ok = secret.isEmpty() ||
            MessageDigest.isEqual(attempt.toByteArray(), secret.toByteArray())
        if (ok) {
            _locked.value = false
            touch()
        }
        return ok
    }

    private fun startMaintenance() {
        if (maintenanceStarted) return
        maintenanceStarted = true
        Thread({
            while (true) {
                try {
                    Thread.sleep(5000)
                    val s = _settings.value
                    val now = System.currentTimeMillis()
                    if (s.autoClearMin > 0) {
                        val cut = now - s.autoClearMin * 60_000L
                        _ui.update { st ->
                            if (st.lines.any { it.ts < cut }) st.copy(lines = st.lines.filter { it.ts >= cut }) else st
                        }
                    }
                    if (s.autoLockMin > 0 && _ui.value.started && !_locked.value &&
                        now - lastTouch > s.autoLockMin * 60_000L
                    ) _locked.value = true
                } catch (_: Exception) {}
            }
        }, "mute-maintenance").apply { isDaemon = true; start() }
    }

    /** Clears the chat window only (the connection stays). */
    fun wipeChat() = _ui.update { it.copy(lines = emptyList(), transfer = null) }

    /** Stops Tor and the node, wipes the chat window and deletes files queued for sending. */
    fun shutdown() {
        val b = bridge
        polling = false
        bridge = null
        applied = null
        _locked.value = false
        _ui.value = UiState()
        synchronized(peerColors) { peerColors.clear() }
        CallAudio.stop()
        clearIncomingNotification()
        if (::app.isInitialized) MuteService.microphone(app, false)
        if (b == null) return
        pool.execute {
            try { b.callAttr("shutdown") } catch (_: Exception) {}
            if (::app.isInitialized) outgoingDir(app).deleteRecursively()
        }
    }
}
