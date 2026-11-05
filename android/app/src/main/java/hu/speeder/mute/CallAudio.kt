package hu.speeder.mute

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
import com.chaquo.python.PyObject

/**
 * Microphone and speaker for a voice call. Python (mute.CallManager) does the encoding, the
 * encryption and the jitter buffer; this object only moves 20 ms blocks (320 samples, 16 kHz, mono,
 * 16-bit) between AudioRecord / AudioTrack and the bridge (audio_in / audio_out).
 */
object CallAudio {
    private const val RATE = 16000
    private const val BLOCK = 640            // bytes in 20 ms of 16-bit mono

    @Volatile private var running = false
    private var record: AudioRecord? = null
    private var track: AudioTrack? = null
    private var manager: AudioManager? = null
    private var oldMode = AudioManager.MODE_NORMAL
    private var oldSpeaker = false
    private val effects = ArrayList<android.media.audiofx.AudioEffect>()
    private var threads = emptyList<Thread>()

    @Synchronized
    fun start(ctx: Context, bridge: PyObject, speaker: Boolean): String? {
        if (running) return null
        val am = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        manager = am
        oldMode = am.mode
        @Suppress("DEPRECATION")
        oldSpeaker = am.isSpeakerphoneOn
        am.mode = AudioManager.MODE_IN_COMMUNICATION
        @Suppress("DEPRECATION")
        am.isSpeakerphoneOn = speaker

        val minIn = AudioRecord.getMinBufferSize(RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val minOut = AudioTrack.getMinBufferSize(RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
        if (minIn <= 0 || minOut <= 0) { restore(); return "This phone does not support 16 kHz voice audio" }
        val rec: AudioRecord
        try {
            rec = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION, RATE, AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT, maxOf(minIn, BLOCK * 8),
            )
        } catch (e: SecurityException) {
            restore(); return "Microphone permission is missing"
        }
        if (rec.state != AudioRecord.STATE_INITIALIZED) { rec.release(); restore(); return "Could not open the microphone" }
        val trk = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build(),
            )
            .setAudioFormat(
                AudioFormat.Builder().setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(RATE).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build(),
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .setBufferSizeInBytes(maxOf(minOut, BLOCK * 8))
            .build()
        record = rec
        track = trk
        // echo cancellation / noise suppression when the phone offers them (matters on the loudspeaker)
        if (AcousticEchoCanceler.isAvailable()) AcousticEchoCanceler.create(rec.audioSessionId)?.also { it.setEnabled(true); effects.add(it) }
        if (NoiseSuppressor.isAvailable()) NoiseSuppressor.create(rec.audioSessionId)?.also { it.setEnabled(true); effects.add(it) }
        if (AutomaticGainControl.isAvailable()) AutomaticGainControl.create(rec.audioSessionId)?.also { it.setEnabled(true); effects.add(it) }

        running = true
        rec.startRecording()
        trk.play()
        val cap = Thread({
            val buf = ByteArray(BLOCK)
            while (running) {
                var got = 0
                while (running && got < BLOCK) {
                    val n = rec.read(buf, got, BLOCK - got)
                    if (n <= 0) { Thread.sleep(5); continue }
                    got += n
                }
                if (!running) break
                try { bridge.callAttr("audio_in", buf) } catch (_: Exception) {}
            }
        }, "mute-mic").apply { isDaemon = true; priority = Thread.MAX_PRIORITY }
        val play = Thread({
            while (running) {
                try {
                    val pcm = bridge.callAttr("audio_out").toJava(ByteArray::class.java)
                    trk.write(pcm, 0, pcm.size)       // blocks until the hardware has room: this paces the loop
                } catch (_: Exception) {
                    Thread.sleep(10)
                }
            }
        }, "mute-speaker").apply { isDaemon = true; priority = Thread.MAX_PRIORITY }
        threads = listOf(cap, play)
        threads.forEach { it.start() }
        return null
    }

    @Synchronized
    fun stop() {
        if (!running && record == null && track == null) return
        running = false
        threads.forEach { try { it.join(500) } catch (_: Exception) {} }
        threads = emptyList()
        effects.forEach { try { it.release() } catch (_: Exception) {} }
        effects.clear()
        try { record?.stop() } catch (_: Exception) {}
        try { record?.release() } catch (_: Exception) {}
        try { track?.stop() } catch (_: Exception) {}
        try { track?.release() } catch (_: Exception) {}
        record = null
        track = null
        restore()
    }

    fun setSpeaker(on: Boolean) {
        @Suppress("DEPRECATION")
        manager?.isSpeakerphoneOn = on
    }

    private fun restore() {
        manager?.let {
            @Suppress("DEPRECATION")
            it.isSpeakerphoneOn = oldSpeaker
            it.mode = oldMode
        }
    }
}
