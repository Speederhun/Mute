package hu.speeder.mute

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * Foreground service whose only job is to keep the process (and with it the Python node and the
 * tor child process) alive while the app is in the background. The notification never shows
 * message content.
 */
class MuteService : Service() {

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_LOW)
            )
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), baseType())
    }

    private fun baseType() =
        if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0

    /** While a call runs the service also declares the microphone type, so Android keeps the microphone open in the background. */
    private fun setMicrophone(on: Boolean) {
        val type = if (on && Build.VERSION.SDK_INT >= 30 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        ) baseType() or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else baseType()
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), type)
        } catch (_: Exception) {
            // Android refused the type change (for example the app is not visible): the call still works while the app is open
        }
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, MuteService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Mute is running")
            .setContentText("Encrypted connection active")
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                MuteController.shutdown()
                stopSelf()
            }
            ACTION_MIC_ON -> setMicrophone(true)
            ACTION_MIC_OFF -> setMicrophone(false)
        }
        return START_NOT_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Swiping the app away ends the session: the identity stays, the connection and chat do not.
        MuteController.shutdown()
        stopSelf()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_STOP = "hu.speeder.mute.STOP"
        private const val ACTION_MIC_ON = "hu.speeder.mute.MIC_ON"
        private const val ACTION_MIC_OFF = "hu.speeder.mute.MIC_OFF"

        /** Called when a call starts or ends. Does nothing if the service is not running (no session). */
        fun microphone(ctx: Context, on: Boolean) {
            try {
                ctx.startService(Intent(ctx, MuteService::class.java).setAction(if (on) ACTION_MIC_ON else ACTION_MIC_OFF))
            } catch (_: Exception) {
            }
        }
        private const val CHANNEL = "mute_connection"
        private const val NOTIFICATION_ID = 1
    }
}
