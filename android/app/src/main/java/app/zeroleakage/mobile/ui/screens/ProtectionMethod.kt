package app.zeroleakage.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.ShieldController
import app.zeroleakage.mobile.data.PrivateDns
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.delay

/**
 * Choose how ZeroLeakage protects the phone:
 *  - Full Shield: the on-device VPN (per-app firewall, Strict Guard, live feed, DNSSEC).
 *  - Lite: Android's Private DNS points at a filtering resolver. No VPN, nothing has to keep running.
 */
@Composable
fun ProtectionMethodCard(shield: ShieldController) {
    val context = LocalContext.current
    val method by ZeroLeakage.method.collectAsStateWithLifecycle()
    val providerId by ZeroLeakage.liteProvider.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    var status by remember { mutableStateOf(PrivateDns.status(context)) }
    var canAuto by remember { mutableStateOf(PrivateDns.canSwitchAutomatically(context)) }
    LaunchedEffect(Unit) {
        while (true) {
            status = PrivateDns.status(context)
            canAuto = PrivateDns.canSwitchAutomatically(context)
            delay(2_000)
        }
    }
    val lite = method == ZeroLeakage.Method.LITE
    val provider = PrivateDns.PROVIDERS.firstOrNull { it.id == providerId } ?: PrivateDns.PROVIDERS.first()

    GlassCard(accent = if (lite) Zl.Mint else Zl.Violet) {
        Overline("Protection method", color = Zl.TextPrimary)
        Spacer(Modifier.height(10.dp))

        MethodOption(
            title = "Full Shield · local VPN",
            body = "Per-app firewall, Strict Guard prompts, live feed, DNSSEC and packet details. Uses Android's VPN slot, but nothing leaves the phone except encrypted DNS.",
            badge = if (!lite && running) "ACTIVE" else null,
            selected = !lite,
        ) {
            if (!lite) return@MethodOption
            ZeroLeakage.setMethod(ZeroLeakage.Method.FULL)
            if (status.isHostname && PrivateDns.reset(context)) ZeroLeakage.say("Private DNS set back to Automatic")
            shield.start()
            ZeroLeakage.say("Full Shield selected")
        }
        Spacer(Modifier.height(8.dp))
        MethodOption(
            title = "Lite · Private DNS, no VPN",
            body = "Android itself blocks ads, trackers and malware through a filtering DNS, for every app, even when ZeroLeakage is closed. Works alongside another VPN. No per-app control or feed.",
            badge = if (lite && status.active && status.host.equals(provider.host, true)) "ACTIVE" else null,
            selected = lite,
        ) {
            if (lite) return@MethodOption
            ZeroLeakage.setMethod(ZeroLeakage.Method.LITE)
            if (running) shield.stop()
            ZeroLeakage.say("Lite mode selected: pick a provider below")
        }

        if (!lite && status.isHostname) {
            Spacer(Modifier.height(10.dp))
            Notice(
                "Private DNS is set to ${status.host}. That bypasses the Full Shield's filter: set it back to Automatic.",
                Zl.Amber, action = if (canAuto) "Set to Automatic" else "Open settings",
            ) {
                if (canAuto && PrivateDns.reset(context)) ZeroLeakage.say("Private DNS set back to Automatic")
                else PrivateDns.openSettings(context)
            }
        }

        if (lite) {
            Spacer(Modifier.height(14.dp))
            Overline("Filtering DNS provider")
            Spacer(Modifier.height(8.dp))
            PrivateDns.PROVIDERS.forEach { p ->
                val sel = p.id == provider.id
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(bottom = 6.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(if (sel) Zl.Mint.copy(alpha = 0.10f) else Zl.Inset)
                        .border(1.dp, if (sel) Zl.Mint.copy(alpha = 0.55f) else Zl.Border, RoundedCornerShape(10.dp))
                        .clickable { ZeroLeakage.setLiteProvider(p.id) }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Radio(sel, Zl.Mint)
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(p.name, fontSize = 13.5.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                        Text(p.host, style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted))
                        Text(p.note, fontSize = 11.sp, color = Zl.TextSecondary)
                    }
                }
            }

            val ok = status.active && status.host.equals(provider.host, true)
            Spacer(Modifier.height(6.dp))
            Text(
                when {
                    ok -> "✓ Active: Android is filtering through ${provider.host}"
                    status.isHostname -> "Private DNS is currently ${status.host}. Switch it to ${provider.host}."
                    else -> "Not set yet. Private DNS is ${if (status.mode == "off") "off" else "on Automatic"}."
                },
                fontSize = 12.5.sp, fontWeight = FontWeight.SemiBold, color = if (ok) Zl.Mint else Zl.Amber,
            )
            Spacer(Modifier.height(10.dp))
            if (!ok) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (canAuto) {
                        SmallAction("Apply now", Zl.Mint) {
                            if (PrivateDns.apply(context, provider.host)) ZeroLeakage.say("Private DNS set to ${provider.host}")
                            else ZeroLeakage.say("Couldn't change Private DNS")
                        }
                    } else {
                        SmallAction("Copy hostname & open settings", Zl.Mint) {
                            PrivateDns.copyHost(context, provider.host)
                            PrivateDns.openSettings(context)
                            ZeroLeakage.say("Copied ${provider.host}. Paste it under Private DNS → hostname")
                        }
                    }
                }
                if (!canAuto) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "In Settings: Network & internet → Private DNS → “Private DNS provider hostname” → paste → Save. " +
                            "(Samsung: Connections → More connection settings → Private DNS.)",
                        fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 16.sp,
                    )
                }
            }
            if (!canAuto) {
                Spacer(Modifier.height(10.dp))
                Text(
                    "Optional one-tap switching: connect the phone to a computer once and run this command. ZeroLeakage can then change Private DNS for you.",
                    fontSize = 11.sp, color = Zl.TextMuted, lineHeight = 15.sp,
                )
                Spacer(Modifier.height(4.dp))
                Text(PrivateDns.ADB_GRANT, style = Zl.mono.copy(fontSize = 10.sp, color = Zl.TextSecondary))
                Spacer(Modifier.height(6.dp))
                SmallAction("Copy command", Zl.TextSecondary) {
                    PrivateDns.copyAdbCommand(context)
                    ZeroLeakage.say("adb command copied")
                }
            }
        }
    }
}

@Composable
private fun MethodOption(title: String, body: String, badge: String?, selected: Boolean, onClick: () -> Unit) {
    val color = Zl.Violet.takeIf { title.startsWith("Full") } ?: Zl.Mint
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (selected) color.copy(alpha = 0.10f) else Zl.Inset)
            .border(1.dp, if (selected) color.copy(alpha = 0.6f) else Zl.Border, RoundedCornerShape(12.dp))
            .clickable(onClick = withConfirmHaptic(onClick))
            .padding(12.dp),
    ) {
        Box(Modifier.padding(top = 2.dp)) { Radio(selected, color) }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary, modifier = Modifier.weight(1f))
                badge?.let { Badge(it, color) }
            }
            Spacer(Modifier.height(3.dp))
            Text(body, fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 16.sp)
        }
    }
}

@Composable
private fun Radio(selected: Boolean, color: Color) {
    Box(
        Modifier.size(16.dp).clip(CircleShape).border(1.5.dp, if (selected) color else Zl.BorderStrong, CircleShape),
        contentAlignment = Alignment.Center,
    ) { if (selected) Box(Modifier.size(8.dp).clip(CircleShape).background(color)) }
}

@Composable
fun Notice(text: String, color: Color, action: String? = null, onAction: () -> Unit = {}) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.09f))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
            .padding(12.dp),
    ) {
        Text(text, fontSize = 12.sp, color = color, lineHeight = 17.sp)
        if (action != null) {
            Spacer(Modifier.height(8.dp))
            SmallAction(action, color, onAction)
        }
    }
}

/** Dashboard warning when encrypted DNS is failing or a fallback is in use. */
@Composable
fun DnsHealthBanner(onOpenDns: () -> Unit = {}) {
    val health by ZeroLeakage.dnsHealth.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    val fallbackOn by ZeroLeakage.fallbackDns.collectAsStateWithLifecycle()
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { now = System.currentTimeMillis(); delay(5_000) } }
    if (!running || now - health.at > 120_000) return
    when {
        health.failing -> Notice(
            "No DNS server is reachable, so apps can't load anything. ${health.error ?: ""}".trim() +
                if (!fallbackOn) " Turn on “Fall back to network DNS” to keep apps working." else "",
            Zl.Crimson, action = if (!fallbackOn) "Turn on fallback" else null,
        ) { ZeroLeakage.setFallbackDns(true); ZeroLeakage.say("Fallback DNS on") }
        health.fallback && health.via == "Network DNS" -> Notice(
            "Encrypted DNS is blocked on this network. Using the network's own DNS (unencrypted) so apps keep working. Filtering and the firewall still apply.",
            Zl.Amber,
        )
        health.fallback -> Notice("Your DNS provider isn't reachable. Using the backup ${health.via} instead (still encrypted).", Zl.Amber)
    }
}
