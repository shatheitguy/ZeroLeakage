package app.zeroleakage.mobile.ui.screens

import androidx.compose.foundation.layout.fillMaxWidth
import app.zeroleakage.mobile.ui.components.formatCount
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import app.zeroleakage.mobile.vpn.ZeroLeakVpnService
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.ShieldController
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.ZlSwitch
import app.zeroleakage.mobile.ui.theme.Zl

@Composable
fun SettingsScreen(shield: ShieldController) {
    val boot by ZeroLeakage.startOnBoot.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    var confirm by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Settings", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary, modifier = Modifier.padding(horizontal = 4.dp))
        }
        item { ProtectionMethodCard(shield) }
        item {
            GlassCard {
                Overline("Shield", color = Zl.TextPrimary)
                SettingRow("Start on boot", "Re-engage the shield after the phone restarts") {
                    ZlSwitch(boot, ZeroLeakage::setStartOnBoot)
                }
                SettingRow("Shield running", if (running) "Encrypted DNS + firewall active" else "Tap to engage") {
                    ZlSwitch(running, { if (it) shield.start() else shield.stop() })
                }
                Text(
                    "Tip: add the \"ZeroLeakage\" (on/off) and \"ZL mode\" tiles to your Quick Settings: pull down twice, tap the pencil, drag them in.",
                    fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 15.sp,
                )
                Spacer(Modifier.height(8.dp))
                val quiet by ZeroLeakage.quietNotification.collectAsStateWithLifecycle()
                SettingRow("Quiet notification", if (quiet) "Silent and minimised: no sound, no status-bar icon" else "Detailed, with a Stop button") {
                    ZlSwitch(quiet, ZeroLeakage::setQuietNotification)
                }
            }
        }
        item { GuardCard() }
        item { NotificationsCard() }
        item {
            GlassCard {
                Overline("Data", color = Zl.TextPrimary)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Reset counters & feed", Zl.TextSecondary) { confirm = "stats" }
                    SmallAction("Restore defaults", Zl.Crimson) { confirm = "defaults" }
                }
            }
        }
        item {
            GlassCard {
                Overline("How it works", color = Zl.TextPrimary)
                Spacer(Modifier.height(8.dp))
                Text(
                    "ZeroLeakage runs a local VPN that only captures DNS. Each lookup is matched to the app that made it, " +
                        "checked against your blocklists and per-app rules, then either dropped on the phone or resolved over " +
                        "encrypted DNS-over-HTTPS. No traffic is sent to any ZeroLeakage server — there isn't one.",
                    fontSize = 12.5.sp, color = Zl.TextSecondary, lineHeight = 18.sp,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Limits: apps that hard-code IP addresses or ship their own encrypted DNS can bypass DNS filtering.",
                    fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 16.sp,
                )
            }
        }
        item {
            Text("ZeroLeakage for Android · v1.0.0", style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted), modifier = Modifier.padding(horizontal = 6.dp))
        }
    }

    confirm?.let { kind ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            containerColor = Zl.SurfaceRaised,
            title = { Text(if (kind == "defaults") "Restore defaults?" else "Reset counters?", color = Zl.TextPrimary) },
            text = {
                Text(
                    if (kind == "defaults") "Clears every app rule, approval, pin and custom domain, and returns to Mode 1: Balanced Shield."
                    else "Sets all counters to zero and clears the live feed.",
                    color = Zl.TextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    if (kind == "defaults") ZeroLeakage.restoreDefaults() else ZeroLeakage.resetStats()
                    confirm = null
                }) { Text(if (kind == "defaults") "Restore" else "Reset", color = Zl.Crimson, fontWeight = FontWeight.Bold) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel", color = Zl.TextSecondary) } },
        )
    }
}

@Composable
private fun SettingRow(title: String, subtitle: String, trailing: @Composable () -> Unit) {
    Row(Modifier.padding(top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
            Text(subtitle, fontSize = 11.5.sp, color = Zl.TextMuted)
        }
        trailing()
    }
}

/**
 * Each ZeroLeakage notification category with its own state and switch, so you can hide just the
 * "running" notice and keep Ask-to-connect prompts and alerts.
 */
@Composable
private fun NotificationsCard() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val quiet by ZeroLeakage.quietNotification.collectAsStateWithLifecycle()
    val tick = app.zeroleakage.mobile.ui.components.rememberVisibleTicker(1_500)
    val nm = ctx.getSystemService(android.app.NotificationManager::class.java)
    val appOn = remember(tick) { androidx.core.app.NotificationManagerCompat.from(ctx).areNotificationsEnabled() }
    fun on(id: String) = nm.getNotificationChannel(id)?.importance?.let { it != android.app.NotificationManager.IMPORTANCE_NONE } ?: true
    val statusId = if (quiet) ZeroLeakVpnService.CHANNEL_QUIET else "shield"
    val statusOn = remember(tick, quiet) { appOn && on(statusId) }
    val promptsOn = remember(tick) { appOn && on(ZeroLeakVpnService.CHANNEL_PROMPT) }
    val alertsOn = remember(tick) { appOn && on(app.zeroleakage.mobile.vpn.OtherVpnWatcher.CHANNEL_ALERTS) }

    fun openChannel(id: String) {
        ZeroLeakVpnService.ensureChannels(ctx)
        app.zeroleakage.mobile.vpn.OtherVpnWatcher.register(ctx)
        val i = android.content.Intent(android.provider.Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
            .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, ctx.packageName)
            .putExtra(android.provider.Settings.EXTRA_CHANNEL_ID, id)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { ctx.startActivity(i) }
    }
    fun openApp() {
        val i = android.content.Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, ctx.packageName)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { ctx.startActivity(i) }
    }

    GlassCard {
        Overline("Notifications", color = Zl.TextPrimary)
        Spacer(Modifier.height(4.dp))
        if (!appOn) {
            Notice(
                "All ZeroLeakage notifications are off, so Ask-to-connect prompts and alerts can't reach you. " +
                    "Turn notifications back on, then switch off only \"Running status\".",
                Zl.Amber, action = "Turn notifications back on",
            ) { openApp() }
            Spacer(Modifier.height(8.dp))
        }
        SettingRow("Running status", if (statusOn) "Shown: \"ZeroLeakage is running\" (silent)" else "Hidden. The shield keeps running.") {
            SmallAction(if (statusOn) "Hide" else "Show", if (statusOn) Zl.Violet else Zl.TextSecondary) {
                if (!appOn) openApp() else openChannel(statusId)
                ZeroLeakage.say(if (statusOn) "Switch off \"Running status\" only" else "Switch \"Running status\" back on")
            }
        }
        SettingRow("Ask to connect", if (promptsOn) "On: Strict Guard asks before new apps go online" else "Off: new apps are blocked silently") {
            SmallAction(if (promptsOn) "Manage" else "Turn on", if (promptsOn) Zl.TextSecondary else Zl.Amber) {
                if (!appOn) openApp() else openChannel(ZeroLeakVpnService.CHANNEL_PROMPT)
            }
        }
        SettingRow("Shield alerts", if (alertsOn) "On: e.g. when WireGuard takes over" else "Off: you won't know when the shield pauses") {
            SmallAction(if (alertsOn) "Manage" else "Turn on", if (alertsOn) Zl.TextSecondary else Zl.Amber) {
                if (!appOn) openApp() else openChannel(app.zeroleakage.mobile.vpn.OtherVpnWatcher.CHANNEL_ALERTS)
            }
        }
        Text(
            "On Android 14 and newer you can also just swipe the running notice away; it stays hidden until the shield restarts. " +
                "Android itself always shows a small key icon while any VPN is on. Apps can't hide that.",
            fontSize = 11.sp, color = Zl.TextMuted, lineHeight = 15.sp,
        )
    }
}

/** Guard: malicious-IP blocking + behaviour alerts (all on the phone). */
@Composable
private fun GuardCard() {
    val st by app.zeroleakage.mobile.data.Guard.status.collectAsStateWithLifecycle()
    val alerts by app.zeroleakage.mobile.data.Guard.alerts.collectAsStateWithLifecycle()
    GlassCard(accent = Zl.Crimson) {
        Overline("Guard", color = Zl.TextPrimary)
        SettingRow(
            "Block malicious IPs",
            if (!st.enabled) "Off" else if (st.ranges == 0) "Downloading threat lists…"
            else "${formatCount(st.ranges.toLong())} known-bad address ranges · updated " +
                (if (st.updatedAt == 0L) "never" else java.text.SimpleDateFormat("dd MMM HH:mm", java.util.Locale.US).format(java.util.Date(st.updatedAt))),
        ) { ZlSwitch(st.enabled, app.zeroleakage.mobile.data.Guard::setEnabled, Zl.Crimson) }
        Text(
            "Blocks apps from reaching botnet servers, malware hosts and hacked machines (FireHOL, abuse.ch, Emerging Threats), " +
                "and warns you when an app's DNS looks like malware (random-name lookups, data tunnelling). Everything is checked on the phone.",
            fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp,
        )
        st.error?.let { Text(it, fontSize = 11.5.sp, color = Zl.Amber) }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SmallAction("Update lists now", Zl.TextSecondary) { app.zeroleakage.mobile.data.Guard.refreshIfStale(force = true); ZeroLeakage.say("Updating threat lists…") }
            if (alerts.isNotEmpty()) SmallAction("Clear alerts", Zl.TextMuted) { app.zeroleakage.mobile.data.Guard.clearAlerts() }
        }
        if (alerts.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Overline("Recent alerts")
            alerts.take(5).forEach { a ->
                Column(Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Text("${a.scenario} · ${a.app}", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Zl.Crimson)
                    Text(a.detail, fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 15.sp)
                    Text(java.text.SimpleDateFormat("dd MMM HH:mm", java.util.Locale.US).format(java.util.Date(a.time)),
                        style = Zl.mono.copy(fontSize = 10.sp, color = Zl.TextMuted))
                    a.pkg?.let { p ->
                        Spacer(Modifier.height(4.dp))
                        SmallAction("Cut off app", Zl.Crimson) {
                            ZeroLeakage.updateRule(p) { it.copy(wifi = false, mobile = false, approved = false, pinned = false) }
                            ZeroLeakage.say("${a.app} cut off from the network")
                        }
                    }
                }
            }
        }
    }
}
