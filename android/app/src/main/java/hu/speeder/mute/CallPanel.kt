package hu.speeder.mute

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

/**
 * The call bar at the top of the chat: shows an incoming call with Accept / Decline, a ringing call with
 * Cancel, and a running call with the timer, mute, loudspeaker and hang-up buttons.
 * [withMic] runs an action once the microphone permission is granted (asking for it if needed).
 */
@Composable
fun CallPanel(call: CallUi, theme: ThemeColors, withMic: (() -> Unit) -> Unit) {
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(call.state) {
        while (true) { now = System.currentTimeMillis(); delay(1000) }
    }
    val secs = if (call.state == "active") ((now - call.since) / 1000).coerceAtLeast(0) else 0
    val status = when (call.state) {
        "incoming" -> "Incoming call"
        "ringing" -> "Calling..."
        else -> "%d:%02d".format(secs / 60, secs % 60) + if (call.remoteMuted) "  ·  they are muted" else ""
    }
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
            .clip(RoundedCornerShape(16.dp)).background(theme.acc.copy(alpha = 0.14f)).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("📞  " + call.name, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = theme.fg)
        Text(status, fontSize = 13.sp, color = theme.dim, fontFamily = FontFamily.Monospace)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            when (call.state) {
                "incoming" -> {
                    Button(
                        onClick = { withMic { MuteController.acceptCall() } },
                        colors = ButtonDefaults.buttonColors(containerColor = theme.acc, contentColor = theme.bg),
                    ) { Text("Accept") }
                    Button(
                        onClick = { MuteController.rejectCall() },
                        colors = ButtonDefaults.buttonColors(containerColor = theme.red, contentColor = Color.White),
                    ) { Text("Decline") }
                }
                "ringing" -> Button(
                    onClick = { MuteController.hangup() },
                    colors = ButtonDefaults.buttonColors(containerColor = theme.red, contentColor = Color.White),
                ) { Text("Cancel") }
                else -> {
                    OutlinedButton(onClick = { MuteController.toggleMute() }) { Text(if (call.muted) "Unmute" else "Mute") }
                    OutlinedButton(onClick = { MuteController.toggleSpeaker() }) { Text(if (call.speaker) "Earpiece" else "Speaker") }
                    Button(
                        onClick = { MuteController.hangup() },
                        colors = ButtonDefaults.buttonColors(containerColor = theme.red, contentColor = Color.White),
                    ) { Text("Hang up") }
                }
            }
        }
    }
}
