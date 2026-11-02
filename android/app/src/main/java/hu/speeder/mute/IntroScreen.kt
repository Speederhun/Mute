package hu.speeder.mute

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.random.Random

private const val WORD = "MUTE"
private const val GLYPHS = "01#%&@$<>/\\|=+*?!~"

/**
 * Start-up animation (~2.6 s, tap to skip): sonar rings spread out while the letters of the name are
 * "decrypted" from random symbols one by one, then the tagline fades in and the whole screen fades away.
 * Everything is a pure function of the animation progress, so it needs no timers or state.
 */
@Composable
fun IntroScreen(onDone: () -> Unit) {
    val bg = MaterialTheme.colorScheme.background
    val accent = MaterialTheme.colorScheme.secondary
    val fg = MaterialTheme.colorScheme.onBackground
    val dim = MaterialTheme.colorScheme.outline
    val progress = remember { Animatable(0f) }

    LaunchedEffect(Unit) {
        progress.animateTo(1f, tween(2600, easing = LinearEasing))
        onDone()
    }

    val p = progress.value
    val fade = if (p > 0.88f) 1f - (p - 0.88f) / 0.12f else 1f
    val frame = (p * 46).toInt()
    val word = buildString {
        WORD.forEachIndexed { i, c ->
            val settle = 0.22f + i * 0.13f
            append(if (p >= settle) c else GLYPHS[Random(frame * 31 + i * 7).nextInt(GLYPHS.length)])
        }
    }
    val tagline = ((p - 0.62f) / 0.16f).coerceIn(0f, 1f)

    Box(
        Modifier.fillMaxSize().background(bg).alpha(fade).clickable(onClick = onDone),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val maxR = size.maxDimension * 0.55f
            for (k in 0 until 3) {
                val t = ((p * 1.6f) + k / 3f) % 1f
                drawCircle(
                    color = accent.copy(alpha = (1f - t) * 0.35f),
                    radius = maxR * t,
                    center = Offset(size.width / 2, size.height / 2),
                    style = Stroke(width = 2.dp.toPx()),
                )
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(
                word, color = accent, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
                fontSize = 56.sp, letterSpacing = 10.sp,
            )
            Text(
                "end-to-end encrypted · serverless", color = fg, fontSize = 13.sp, letterSpacing = 2.sp,
                modifier = Modifier.alpha(tagline),
            )
            Text(
                "no accounts · no servers · no trace", color = dim, fontSize = 11.sp, letterSpacing = 1.sp,
                modifier = Modifier.alpha(tagline),
            )
        }
    }
}
