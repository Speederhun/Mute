package hu.speeder.mute

import org.json.JSONObject

/** Everything the Python node can be configured with (see Bridge.configure in android_bridge.py). */
data class Options(
    val closed: Boolean = false,
    val allow: String = "",              // fingerprints, one per line (closed mode allowlist)
    val psk: String = "",                // shared secret
    val relay: Boolean = false,
    val cover: Boolean = false,
    val coverProfile: String = "random",
    val shape: Float = 0f,               // constant-rate frames per second, 0 = off
    val speedLimitKbs: Int = 0,
    val ratchet: Int = 600,              // seconds between fresh DH key renewals, 0 = off
    val proxy: String = "",              // SOCKS5 host:port for DIRECT connections
    val scrub: Boolean = true,           // strip metadata from outgoing files
    val amnesia: Boolean = false,        // save nothing
    val allowedClients: String = "",     // onion client public keys allowed to reach your service (start only)
    val bridges: String = "",            // Tor bridge lines (start only)
) {
    /**
     * JSON for Bridge.configure. With [prev] == null (first start) every non-default value is sent;
     * afterwards only what changed. Start-only values (bridges, onion client keys) are never re-sent.
     */
    fun toJson(prev: Options?): String {
        val o = JSONObject()
        val first = prev == null
        fun <T> changed(a: T, b: T?) = first || a != b
        if (changed(scrub, prev?.scrub)) o.put("scrub", scrub)
        if (changed(amnesia, prev?.amnesia)) o.put("amnesia", amnesia)
        if (changed(closed, prev?.closed)) o.put("closed", closed)
        if (allow.isNotBlank() && changed(allow, prev?.allow)) o.put("allow", allow)
        if (psk != (prev?.psk ?: "")) o.put("psk", psk)
        if (changed(relay, prev?.relay)) o.put("relay", relay)
        if (changed(cover, prev?.cover) || changed(coverProfile, prev?.coverProfile)) {
            o.put("cover", cover)
            o.put("cover_profile", coverProfile)
        }
        if (changed(shape, prev?.shape)) o.put("shape", shape.toDouble())
        if (changed(speedLimitKbs, prev?.speedLimitKbs)) o.put("speed_limit_kbs", speedLimitKbs)
        if (changed(ratchet, prev?.ratchet)) o.put("ratchet", ratchet)
        if (changed(proxy, prev?.proxy)) o.put("proxy", proxy.trim())
        if (first) {
            o.put("allowed_clients", allowedClients)
            o.put("bridges", bridges)
        }
        return o.toString()
    }
}

/** Options as the node reports them back (state()["options"]). */
data class OptionsState(
    val closed: Boolean = false,
    val relay: Boolean = false,
    val cover: Boolean = false,
    val shape: Float = 0f,
    val paused: Boolean = false,
    val psk: Boolean = false,
    val amnesia: Boolean = false,
    val clientAuthPub: String? = null,
    val known: Int = 0,
)

/** App-side settings that never reach Python. Kept in memory only, like on the desktop. */
data class AppSettings(
    val clipboardClear: Boolean = true,   // clear the clipboard 30 s after copying
    val autoClearMin: Int = 0,            // delete chat lines older than N minutes, 0 = off
    val autoLockMin: Int = 0,             // lock the screen after N idle minutes, 0 = off
    val lockPassword: String = "",        // empty = Unlock button only
)

data class QueueItem(val id: Int, val name: String, val state: String)

data class MoatState(
    val busy: Boolean = false,
    val image: ByteArray? = null,
    val challenge: String = "",
    val error: String? = null,
    val bridges: String? = null,         // fresh bridge lines waiting to be taken by the UI
)

data class Meta(
    val themes: Map<String, ThemeColors> = mapOf("hacker" to ThemeColors.HACKER),
    val coverProfiles: Map<String, Pair<String, String>> = emptyMap(),   // name -> (description, estimate)
    val shapeLabels: List<Pair<String, Float>> = listOf("off" to 0f),
)
