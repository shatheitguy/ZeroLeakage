package app.zeroleakage.mobile.vpn

import android.Manifest
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.zeroleakage.mobile.R
import app.zeroleakage.mobile.data.ZeroLeakage

/** Mode 2 "Ask to Connect": a heads-up notification with Allow / Allow Once / Block. */
object PromptNotifier {
    const val EXTRA_PKG = "pkg"
    const val EXTRA_DECISION = "decision"

    fun notificationId(pkg: String) = 10_000 + (pkg.hashCode() and 0x0FFFFFFF) % 100_000

    fun show(context: Context, pkg: String, label: String, domain: String) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ZeroLeakage.pendingPrompts.remove(pkg)
            return
        }
        fun action(decision: String, code: Int) = PendingIntent.getBroadcast(
            context, notificationId(pkg) * 4 + code,
            Intent(context, PromptActionReceiver::class.java).putExtra(EXTRA_PKG, pkg).putExtra(EXTRA_DECISION, decision),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(context, ZeroLeakVpnService.CHANNEL_PROMPT)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(0xFF7B61FF.toInt())
            .setContentTitle("$label wants to connect")
            .setContentText("→ $domain · blocked until you decide")
            .setSubText("Strict Guard")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setAutoCancel(true)
            .setTimeoutAfter(30_000)          // default-deny: no answer = stays blocked
            .setDeleteIntent(action("dismiss", 3))
            .addAction(0, "Allow", action("allow", 0))
            .addAction(0, "Allow once", action("once", 1))
            .addAction(0, "Block", action("block", 2))
            .build()
        NotificationManagerCompat.from(context).notify(notificationId(pkg), n)
    }
}

class PromptActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.getStringExtra(PromptNotifier.EXTRA_PKG) ?: return
        when (intent.getStringExtra(PromptNotifier.EXTRA_DECISION)) {
            "allow" -> ZeroLeakage.updateRule(pkg) { it.copy(approved = true, wifi = true, mobile = true) }
            "once" -> ZeroLeakage.allowedOnce.add(pkg)
            "block" -> ZeroLeakage.updateRule(pkg) { it.copy(approved = false, wifi = false, mobile = false) }
        }
        ZeroLeakage.pendingPrompts.remove(pkg)
        context.getSystemService(NotificationManager::class.java).cancel(PromptNotifier.notificationId(pkg))
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // ZeroLeakage is already initialised by ZeroLeakageApplication.onCreate.
        // Only auto-start when the user opted in and VPN consent is already granted.
        if (ZeroLeakage.startOnBoot.value && VpnService.prepare(context) == null) {
            ZeroLeakVpnService.start(context)
        }
    }
}
