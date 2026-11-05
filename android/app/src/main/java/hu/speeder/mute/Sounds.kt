package hu.speeder.mute

import android.content.Context
import android.media.AudioManager
import android.media.Ringtone
import android.media.RingtoneManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Handler
import android.os.Looper

/** The small notification sounds (message, new peer, file, call ringing / connected / ended). */
object Sounds {
    enum class Kind { MESSAGE, PEER, FILE, CONNECTED, ENDED, ERROR }

    @Volatile var enabled = true
    @Volatile var volume = 70           // 0..100
    private val handler = Handler(Looper.getMainLooper())
    private var ringtone: Ringtone? = null
    private var ringback: ToneGenerator? = null

    private fun tone(stream: Int, kind: Int, ms: Int) {
        try {
            val g = ToneGenerator(stream, volume.coerceIn(0, 100))
            g.startTone(kind, ms)
            handler.postDelayed({ try { g.release() } catch (_: Exception) {} }, ms + 300L)
        } catch (_: Exception) {
            // no audio output right now: the sound is optional
        }
    }

    fun play(k: Kind) {
        if (!enabled || volume == 0) return
        val s = AudioManager.STREAM_NOTIFICATION
        when (k) {
            Kind.MESSAGE -> tone(s, ToneGenerator.TONE_PROP_ACK, 200)
            Kind.PEER -> tone(s, ToneGenerator.TONE_PROP_BEEP2, 300)
            Kind.FILE -> tone(s, ToneGenerator.TONE_PROP_PROMPT, 250)
            Kind.CONNECTED -> tone(s, ToneGenerator.TONE_PROP_BEEP, 250)
            Kind.ENDED -> tone(s, ToneGenerator.TONE_CDMA_CALLDROP_LITE, 400)
            Kind.ERROR -> tone(s, ToneGenerator.TONE_SUP_ERROR, 500)
        }
    }

    /** Ringtone for an incoming call, until [stopRing]. */
    @Synchronized
    fun ring(ctx: Context) {
        stopRing()
        if (!enabled || volume == 0) return
        try {
            val r = RingtoneManager.getRingtone(ctx, RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)) ?: return
            if (Build.VERSION.SDK_INT >= 28) { r.isLooping = true; r.volume = volume / 100f }
            r.play()
            ringtone = r
        } catch (_: Exception) {
        }
    }

    /** The "calling..." tone on the caller's side, until [stopRing]. */
    @Synchronized
    fun ringback() {
        stopRing()
        if (!enabled || volume == 0) return
        try {
            val g = ToneGenerator(AudioManager.STREAM_VOICE_CALL, volume.coerceIn(0, 100))
            g.startTone(ToneGenerator.TONE_SUP_RINGTONE)
            ringback = g
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun stopRing() {
        try { ringtone?.stop() } catch (_: Exception) {}
        ringtone = null
        try { ringback?.stopTone(); ringback?.release() } catch (_: Exception) {}
        ringback = null
    }
}
