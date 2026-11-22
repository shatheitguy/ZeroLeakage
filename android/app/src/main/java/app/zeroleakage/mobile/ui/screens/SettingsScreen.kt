package app.zeroleakage.mobile.ui.screens

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
            }
        }
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
