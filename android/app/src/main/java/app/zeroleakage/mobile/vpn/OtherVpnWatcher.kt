package app.zeroleakage.mobile.vpn

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.zeroleakage.mobile.MainActivity
import app.zeroleakage.mobile.R
import app.zeroleakage.mobile.data.ZeroLeakage
import java.util.concurrent.ConcurrentHashMap

/**
 * Android allows one VPN at a time. When another VPN app (WireGuard, a work VPN…) starts, Android stops
 * ZeroLeakage. This watcher:
 *  - tells you, with one-tap "turn the shield back on";
 *  - notices when that other VPN disconnects and brings the shield back (automatically if Android still
 *    lets us, otherwise with a one-tap notification, because Android requires your consent again).
 * Lite mode (Private DNS) avoids the conflict entirely: it works alongside any VPN.
 */
object OtherVpnWatcher {
    const val CHANNEL_ALERTS = "shield_alerts"
    const val EXTRA_RESUME = "app.zeroleakage.mobile.RESUME_SHIELD"
    private const val NOTIF_ID = 2

    private val vpnNetworks = ConcurrentHashMap.newKeySet<Network>()
    @Volatile private var registered = false

    fun register(context: Context) {
        if (registered) return
        val app = context.applicationContext
        val nm = app.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL_ALERTS, "Shield alerts", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "When another VPN app takes over, and when the shield can come back"
        })
        val cm = app.getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching {
            cm.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) { vpnNetworks.add(network) }
                override fun onLost(network: Network) {
                    vpnNetworks.remove(network)
                    if (vpnNetworks.isEmpty() && ZeroLeakage.takenOver.value && !ZeroLeakage.vpnRunning.value &&
                        ZeroLeakage.method.value == ZeroLeakage.Method.FULL) {
                        tryResume(app)
                    }
                }
            })
            registered = true
        }
    }

    /** Called when Android revoked our VPN because another one started. */
    fun onTakenOver(context: Context) {
        ZeroLeakage.setTakenOver(true)
        notify(context, "ZeroLeakage paused: another VPN took over",
            "Android runs one VPN at a time. Tap to turn the shield back on. Using WireGuard often? Lite mode works alongside it.")
    }

    /** The other VPN is gone: come back on our own if Android allows it, otherwise ask with one tap. */
    fun tryResume(context: Context) {
        if (VpnService.prepare(context) == null) {
            ZeroLeakVpnService.start(context)
            cancel(context)
        } else {
            notify(context, "Your other VPN is off", "Tap to turn the ZeroLeakage shield back on.")
        }
    }

    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIF_ID)
    }

    private fun notify(context: Context, title: String, text: String) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val open = PendingIntent.getActivity(
            context, 7,
            Intent(context, MainActivity::class.java).putExtra(EXTRA_RESUME, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(0xFFFFB547.toInt())
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .addAction(0, "Turn shield on", open)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .build()
        NotificationManagerCompat.from(context).notify(NOTIF_ID, n)
    }
}
