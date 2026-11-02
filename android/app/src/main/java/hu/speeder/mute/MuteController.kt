package hu.speeder.mute

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

data class Peer(val fp: String, val name: String)

enum class Kind { ME, PEER, SYS, FILE }

data class ChatLine(val id: Long, val who: String, val text: String, val kind: Kind)

data class Confirm(val fp: String, val words: String)

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
    val peers: List<Peer> = emptyList(),
    val lines: List<ChatLine> = emptyList(),
    val confirm: Confirm? = null,
    val transfer: Transfer? = null,
)

/**
 * Process-wide owner of the Python node (android/python/android_bridge.py -> mute.Node).
 * All protocol and crypto work happens in Python; this class only forwards calls and turns the
 * bridge's JSON events into [UiState]. Nothing is written to disk except what mute.py itself
 * stores (identity key, optional known-peers list) in the app's private directory.
 */
object MuteController {
    private const val DIRECT_PORT = 5555
    private const val MAX_LINES = 500

    private val pool = Executors.newCachedThreadPool()
    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    @Volatile private var bridge: PyObject? = null
    @Volatile private var polling = false
    @Volatile private var nextId = 0L
    private lateinit var app: Context

    private fun ensurePython(ctx: Context) {
        if (!Python.isStarted()) Python.start(AndroidPlatform(ctx.applicationContext))
    }

    private fun dataDir(ctx: Context) = File(ctx.filesDir, "mute")
    private fun outgoingDir(ctx: Context) = File(ctx.cacheDir, "outgoing")
    private fun downloadDir(ctx: Context) =
        ctx.getExternalFilesDir("Mute") ?: File(ctx.filesDir, "downloads")

    /** "missing", "plain" or "encrypted" - decides whether the setup screen asks for a passphrase. */
    fun identityState(ctx: Context): String {
        ensurePython(ctx)
        return Python.getInstance().getModule("android_bridge")
            .callAttr("identity_state", dataDir(ctx).path).toString()
    }

    fun start(ctx: Context, passphrase: String?, burner: Boolean, tor: Boolean, bridges: String) {
        if (_ui.value.busy || bridge != null) return
        app = ctx.applicationContext
        _ui.update { it.copy(busy = true, error = null) }
        pool.execute {
            try {
                ensurePython(app)
                val native = app.applicationInfo.nativeLibraryDir
                val mod = Python.getInstance().getModule("android_bridge")
                val b = mod.callAttr(
                    "Bridge",
                    dataDir(app).path, downloadDir(app).path,
                    File(native, "libtor.so").path, native,
                    passphrase?.takeIf { it.isNotEmpty() }, burner,
                )
                bridge = b
                startPolling(b)
                _ui.update { it.copy(started = true) }
                applyState(b.callAttr("state").toString())
                val st = if (tor) b.callAttr("start_tor", bridges)
                else b.callAttr("start_direct", DIRECT_PORT)
                applyState(st.toString())
                _ui.update { it.copy(busy = false) }
            } catch (e: Exception) {
                fail(e.message ?: "Start failed")
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

    private fun handle(ev: JSONObject, b: PyObject) {
        when (ev.getString("k")) {
            "sys" -> addLine("", ev.getString("text"), Kind.SYS)
            "msg" -> addLine(ev.getString("name"), ev.getString("text"), Kind.PEER)
            "relayed" -> addLine(
                "${ev.getString("name")} (via ${ev.getString("via")})", ev.getString("text"), Kind.PEER,
            )
            "connected" -> {
                addLine("", "${ev.getString("name")} connected securely", Kind.SYS)
                applyState(b.callAttr("state").toString())
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
            "confirm" -> _ui.update { it.copy(confirm = Confirm(ev.getString("fp"), ev.getString("words"))) }
        }
    }

    private fun applyState(json: String) {
        val o = JSONObject(json)
        val ips = o.getJSONArray("ips").let { a -> List(a.length()) { a.getString(it) } }
        val peersJson = o.getJSONArray("peers")
        val peers = List(peersJson.length()) {
            peersJson.getJSONObject(it).let { p -> Peer(p.getString("fp"), p.getString("name")) }
        }
        _ui.update {
            it.copy(
                fp = o.getString("fp"), words = o.getString("words"), ips = ips,
                transport = o.getString("transport"),
                onion = if (o.isNull("onion")) null else o.getString("onion"),
                listening = o.getBoolean("listening"), peers = peers,
            )
        }
    }

    private fun addLine(who: String, text: String, kind: Kind) {
        _ui.update {
            val line = ChatLine(nextId++, who, text, kind)
            it.copy(lines = (it.lines + line).takeLast(MAX_LINES))
        }
    }

    // ---- actions from the UI
    private fun call(name: String, vararg args: Any?) {
        val b = bridge ?: return
        pool.execute {
            try {
                b.callAttr(name, *args)
            } catch (e: Exception) {
                addLine("", "${e.message}", Kind.SYS)
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
                addLine("", e.message ?: "Not connected", Kind.SYS)
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
                addLine("", e.message ?: "Could not send the file", Kind.SYS)
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

    fun cancelTransfers() = call("cancel_transfers")

    /** Wipes the chat window, stops Tor and the node, and deletes files queued for sending. */
    fun shutdown() {
        val b = bridge
        polling = false
        bridge = null
        _ui.value = UiState()
        if (b == null) return
        pool.execute {
            try { b.callAttr("shutdown") } catch (_: Exception) {}
            if (::app.isInitialized) outgoingDir(app).deleteRecursively()
        }
    }
}
