package app.zeroleakage.mobile.vpn

import android.Manifest
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.widget.Toast
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
        val advice = app.zeroleakage.mobile.data.AppAdvice.forPackage(context, pkg)
        fun action(decision: String, code: Int) = PendingIntent.getBroadcast(
            context, notificationId(pkg) * 4 + code,
            Intent(context, PromptActionReceiver::class.java).putExtra(EXTRA_PKG, pkg).putExtra(EXTRA_DECISION, decision),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(context, ZeroLeakVpnService.CHANNEL_PROMPT)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(0xFF7B61FF.toInt())
            .setContentTitle("$label wants to connect")
            .setContentText("${advice.level.label}: ${advice.level.action} · → $domain")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "${advice.level.label.uppercase()} · ${advice.reason}\n→ $domain\n" +
                    "Allow = it works (here and in Total Zero-Leak) and never asks again. Block = cut off for good. " +
                    "Swipe away = stays blocked, asks again in 1 hour."))
            .setOnlyAlertOnce(true)
            .setSubText("Strict Guard")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setAutoCancel(true)
            .setTimeoutAfter(60_000)          // default-deny: no answer = stays blocked (asks again in 10 min)
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
        val label = runCatching {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrDefault(pkg)
        val message = when (intent.getStringExtra(PromptNotifier.EXTRA_DECISION)) {
            "allow" -> {
                ZeroLeakage.updateRule(pkg) { it.copy(approved = true, wifi = true, mobile = true) }
                "$label allowed. It can connect now."
            }
            "once" -> {
                ZeroLeakage.allowOnce(pkg)
                "$label allowed until the shield restarts"
            }
            "block" -> {
                ZeroLeakage.updateRule(pkg) { it.copy(approved = false, wifi = false, mobile = false) }
                "$label blocked"
            }
            else -> {   // swiped away = "not now": stays blocked, quietly, for an hour
                ZeroLeakage.pendingPrompts.remove(pkg)
                ZeroLeakage.snoozePrompts(pkg, 60 * 60_000L)
                ZeroLeakage.releaseDecision(pkg)
                null
            }
        }
        context.getSystemService(NotificationManager::class.java).cancel(PromptNotifier.notificationId(pkg))
        if (message != null) {
            Feedback.confirm(context)
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            ZeroLeakage.say(message)
        }
    }
}

/** A short, crisp vibration so a tap on Allow / Block is felt, even from a notification. */
object Feedback {
    fun confirm(context: Context) {
        runCatching {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                context.getSystemService(VibratorManager::class.java).defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                context.getSystemService(Vibrator::class.java)
            }
            vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK))
        }
    }
}

/** You swiped the running-status notification away (Android 14+): keep it hidden until the shield restarts. */
class StatusDismissedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        ZeroLeakVpnService.statusHiddenBySwipe = true
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
