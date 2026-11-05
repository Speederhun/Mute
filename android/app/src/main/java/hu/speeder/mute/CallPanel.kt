package hu.speeder.mute

import android.app.Activity
import android.media.AudioManager
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

/**
 * The call bar at the top of the chat: shows an incoming call with Accept / Decline, a ringing call with
 * Cancel, and a running call with the timer, volume, mute (or the big hold-to-talk button), loudspeaker and hang-up.
 * [withMic] runs an action once the microphone permission is granted (asking for it if needed).
 */
@Composable
fun CallPanel(call: CallUi, audio: AudioPrefs, theme: ThemeColors, withMic: (() -> Unit) -> Unit) {
    val ctx = LocalContext.current
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(call.state) {
        while (true) { now = System.currentTimeMillis(); delay(1000) }
    }
    // while a call is on screen the phone's volume keys change the call volume, not the media volume
    DisposableEffect(Unit) {
        (ctx as? Activity)?.volumeControlStream = AudioManager.STREAM_VOICE_CALL
        onDispose { (ctx as? Activity)?.volumeControlStream = AudioManager.USE_DEFAULT_STREAM_TYPE }
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
        when (call.state) {
            "incoming" -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                if (audio.ptt) TalkButton(theme)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (!audio.ptt) {
                        OutlinedButton(onClick = { MuteController.toggleMute() }) { Text(if (call.muted) "Unmute" else "Mute") }
                    }
                    OutlinedButton(onClick = { MuteController.toggleSpeaker() }) { Text(if (call.speaker) "Earpiece" else "Speaker") }
                    Button(
                        onClick = { MuteController.hangup() },
                        colors = ButtonDefaults.buttonColors(containerColor = theme.red, contentColor = Color.White),
                    ) { Text("Hang up") }
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Volume ${audio.volume}%", fontSize = 12.sp, color = theme.dim, modifier = Modifier.padding(end = 4.dp))
                    Slider(
                        value = audio.volume.toFloat(), valueRange = 0f..200f,
                        onValueChange = { MuteController.setAudio(audio.copy(volume = it.toInt()), save = false) },
                        onValueChangeFinished = { MuteController.setAudio(audio, save = true) },
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Switch(checked = audio.ptt, onCheckedChange = { MuteController.setAudio(audio.copy(ptt = it)) })
                    Text("Push to talk", fontSize = 13.sp, color = theme.fg)
                }
            }
        }
    }
}

/** Big hold-to-talk button: the microphone transmits only while a finger is on it. */
@Composable
private fun TalkButton(theme: ThemeColors) {
    var down by remember { mutableStateOf(false) }
    val haptic = LocalHapticFeedback.current
    Box(
        Modifier.fillMaxWidth().height(110.dp).clip(RoundedCornerShape(24.dp))
            .background(if (down) theme.acc else theme.btn)
            .pointerInput(Unit) {
                detectTapGestures(onPress = {
                    down = true
                    MuteController.ptt(true)
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    try {
                        tryAwaitRelease()
                    } finally {
                        down = false
                        MuteController.ptt(false)
                    }
                })
            },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            if (down) "TALKING..." else "HOLD TO TALK", fontWeight = FontWeight.Bold, fontSize = 20.sp,
            color = if (down) theme.bg else theme.fg,
        )
    }
}
