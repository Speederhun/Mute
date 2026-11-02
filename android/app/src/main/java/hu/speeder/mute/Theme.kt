package hu.speeder.mute

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.json.JSONObject

/** Same roles as mute.THEMES on the desktop: bg, fg (text), dim, acc, red, btn, ent, chat + peer palette. */
data class ThemeColors(
    val name: String,
    val bg: Color, val fg: Color, val dim: Color, val acc: Color, val red: Color,
    val btn: Color, val ent: Color, val chat: Color,
    val pal: List<Color>,
) {
    val isLight get() = bg.luminance() > 0.5f

    fun peerColor(index: Int): Color = if (index < 0 || pal.isEmpty()) acc else pal[index % pal.size]

    fun scheme(): ColorScheme {
        val base = if (isLight) lightColorScheme() else darkColorScheme()
        return base.copy(
            primary = fg, onPrimary = bg,
            secondary = acc, onSecondary = bg,
            background = bg, onBackground = fg,
            surface = chat, onSurface = fg,
            surfaceVariant = btn, onSurfaceVariant = fg,
            outline = dim, outlineVariant = dim,
            error = red, onError = bg,
        )
    }

    companion object {
        val HACKER = ThemeColors(
            "hacker", c("#000000"), c("#00ff41"), c("#0a7a28"), c("#00e5ff"), c("#ff3b3b"),
            c("#001a00"), c("#050505"), c("#030803"),
            listOf("#00e5ff", "#ffd166", "#ff6bd6", "#a78bfa", "#ff9f43", "#5eead4", "#f472b6", "#93c5fd").map(::c),
        )

        private fun c(hex: String) = Color(android.graphics.Color.parseColor(hex))

        fun parseAll(json: String): Map<String, ThemeColors> {
            val root = JSONObject(json)
            val out = LinkedHashMap<String, ThemeColors>()
            for (name in root.keys()) {
                val t = root.getJSONObject(name)
                val pal = t.getJSONArray("pal")
                out[name] = ThemeColors(
                    name, c(t.getString("bg")), c(t.getString("fg")), c(t.getString("dim")),
                    c(t.getString("acc")), c(t.getString("red")), c(t.getString("btn")),
                    c(t.getString("ent")), c(t.getString("chat")),
                    List(pal.length()) { c(pal.getString(it)) },
                )
            }
            return out
        }
    }
}
