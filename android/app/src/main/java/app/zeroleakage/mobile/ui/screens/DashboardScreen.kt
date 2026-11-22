package app.zeroleakage.mobile.ui.screens

import android.os.Build
import android.view.HapticFeedbackConstants
import androidx.compose.ui.platform.LocalView
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.ShieldController
import app.zeroleakage.mobile.data.FeedEvent
import app.zeroleakage.mobile.data.Verdict
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.geo.GeoIp
import app.zeroleakage.mobile.vpn.DnssecStatus
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.Chip
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.MetricTile
import app.zeroleakage.mobile.ui.components.ModeSwitcher
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.ShieldPulse
import app.zeroleakage.mobile.ui.components.formatCount
import app.zeroleakage.mobile.ui.components.verdictColor
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class FeedFilter { ALL, BLOCKED, ALLOWED }

@Composable
fun DashboardScreen(shield: ShieldController) {
    val mode by ZeroLeakage.mode.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    val method by ZeroLeakage.method.collectAsStateWithLifecycle()
    val stats by ZeroLeakage.stats.collectAsStateWithLifecycle()
    val feed by ZeroLeakage.feed.collectAsStateWithLifecycle()
    val rules by ZeroLeakage.rules.collectAsStateWithLifecycle()
    val accent by animateColorAsState(Zl.accent(mode), tween(450), label = "accent")

    var filter by rememberSaveable { mutableStateOf(FeedFilter.ALL) }
    var query by rememberSaveable { mutableStateOf("") }
    var expanded by remember { mutableStateOf<Long?>(null) }
    var inspecting by remember { mutableStateOf<FeedEvent?>(null) }
    inspecting?.let { PacketInspector(it) { inspecting = null } }

    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(running) {
        while (running) { now = System.currentTimeMillis(); delay(1_000) }
    }

    val visible = feed.filter {
        (filter == FeedFilter.ALL || (filter == FeedFilter.BLOCKED && it.verdict != Verdict.ALLOWED) ||
            (filter == FeedFilter.ALLOWED && it.verdict == Verdict.ALLOWED)) &&
            (query.isBlank() || it.domain.contains(query, true) || it.appLabel.contains(query, true) || it.category.contains(query, true))
    }

    LazyColumn(
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ═════ Hero ═════
        item {
            GlassCard(accent = accent) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ShieldPulse(accent, running, Modifier.size(112.dp))
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Overline("Active protection")
                            Spacer(Modifier.width(8.dp))
                            Badge(if (running) "● LIVE" else "○ OFF", if (running) accent else Zl.Amber)
                        }
                        Text(mode.title, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                        Text(
                            if (running) "Bits leaked: 0 · up ${uptime(now - ZeroLeakage.vpnStartedAt)}" else "Shield is off — DNS is unprotected",
                            style = Zl.mono.copy(fontSize = 11.sp, color = if (running) Zl.TextSecondary else Zl.Amber),
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(mode.description, fontSize = 13.sp, color = Zl.TextSecondary, lineHeight = 18.sp)
                Spacer(Modifier.height(14.dp))
                ModeSwitcher(mode, onSelect = ZeroLeakage::setMode)
                Spacer(Modifier.height(12.dp))
                if (method == ZeroLeakage.Method.LITE) {
                    Text(
                        "Lite mode: Android's Private DNS does the blocking, no VPN needed. Manage it below.",
                        fontSize = 12.5.sp, color = Zl.Mint, lineHeight = 17.sp,
                    )
                } else if (running) {
                    OutlinedButton(
                        onClick = shield.stop,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Zl.BorderStrong),
                    ) { Text("Stop shield", color = Zl.TextSecondary) }
                } else {
                    Button(
                        onClick = shield.start,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = Zl.Canvas),
                    ) { Text("ENGAGE SHIELD", fontWeight = FontWeight.Bold, letterSpacing = 1.sp) }
                }
            }
        }

        item { DnsHealthBanner() }
        if (method == ZeroLeakage.Method.LITE) item { ProtectionMethodCard(shield) }

        // ═════ Bento metrics 2×2 ═════
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricTile("Telemetry purged", formatCount(stats.telemetryBlocked), "req", "OS & OEM phone-home", "blocked", Zl.Crimson, Modifier.weight(1f))
                    MetricTile("Trackers dropped", formatCount(stats.trackersBlocked), "dom", "DoH latency", "${stats.dohLatencyMs} ms", Zl.Violet, Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricTile("App firewall", formatCount(stats.appBlocks), "drops", "Rules", "${rules.size}", accent, Modifier.weight(1f))
                    MetricTile("Clean lookups", formatCount(stats.allowed), "ok", "DNSSEC signed",
                        if (stats.dnssecChecked > 0) "${stats.dnssecPercent}%" else "—", Zl.Mint, Modifier.weight(1f))
                }
            }
        }

        // ═════ Live feed header ═════
        item {
            GlassCard(padding = 14.dp) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(50)).background(if (running) accent else Zl.TextMuted))
                    Spacer(Modifier.width(8.dp))
                    Overline("Live DNS feed", color = Zl.TextPrimary)
                    Spacer(Modifier.weight(1f))
                    Text("${feed.size} events", style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted))
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Chip("All", filter == FeedFilter.ALL, accent, { filter = FeedFilter.ALL })
                    Chip("Blocked", filter == FeedFilter.BLOCKED, accent, { filter = FeedFilter.BLOCKED })
                    Chip("Allowed", filter == FeedFilter.ALLOWED, accent, { filter = FeedFilter.ALLOWED })
                }
                Spacer(Modifier.height(10.dp))
                SearchField(query, { query = it }, "Filter app, domain, category…")
            }
        }

        if (visible.isEmpty()) {
            item {
                Text(
                    if (running) "Waiting for DNS lookups…" else "Engage the shield to see every lookup on this phone in real time.",
                    fontSize = 12.sp, color = Zl.TextMuted, modifier = Modifier.padding(horizontal = 8.dp, vertical = 12.dp),
                )
            }
        }

        items(visible, key = { it.id }) { e ->
            FeedRow(e, expanded == e.id, onInspect = { inspecting = e }) { expanded = if (expanded == e.id) null else e.id }
        }
    }
}

private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun FeedRow(e: FeedEvent, isExpanded: Boolean, onInspect: () -> Unit, onClick: () -> Unit) {
    val color = verdictColor(e.verdict)
    val firstIp = e.detail?.answers?.firstOrNull { it.address != null }
    val geo = firstIp?.address?.let { GeoIp.lookup(it) }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Zl.Inset)
            .border(1.dp, if (isExpanded) color.copy(alpha = 0.4f) else Zl.Border, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 9.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(timeFormat.format(Date(e.time)), style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted))
            Spacer(Modifier.width(8.dp))
            Badge(e.verdict.name.replace("PROMPT", "ASK"), color)
            Spacer(Modifier.width(8.dp))
            Text(e.appLabel, fontSize = 12.5.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary,
                maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            Text(e.category, fontSize = 10.5.sp, color = Zl.TextSecondary, maxLines = 1)
        }
        Spacer(Modifier.height(3.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("→ ${e.domain}", style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextSecondary), maxLines = 1,
                overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            e.detail?.let { d ->
                if (d.dnssec == DnssecStatus.SECURE) Text(" 🔒", fontSize = 10.sp)
                if (firstIp != null) {
                    Text(" ${geo?.flag ?: ""} ${firstIp.data}", style = Zl.mono.copy(fontSize = 10.sp, color = Zl.TextMuted), maxLines = 1)
                }
            }
        }
        AnimatedVisibility(isExpanded) {
            Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SmallAction("Details", Zl.Violet, onInspect)
                if (e.verdict == Verdict.ALLOWED) SmallAction("Block domain", Zl.TextSecondary) {
                    Filters.block(e.domain)
                    ZeroLeakage.say("${e.domain} blocked")
                } else SmallAction(allowLabel(e), Zl.Mint) { allowEvent(e) }
                if (e.packageName != null) {
                    SmallAction("Kill app", Zl.Crimson) {
                        ZeroLeakage.updateRule(e.packageName) { it.copy(wifi = false, mobile = false, approved = false) }
                        ZeroLeakage.say("${e.appLabel} cut off from the network")
                    }
                }
            }
        }
    }
}

/** Blocked because of the app (Strict Guard / lockdown / kill switch), not because of the domain. */
private fun isAppBlock(e: FeedEvent) = e.packageName != null &&
    e.category in setOf("Ask to Connect", "Total Lockdown", "App Network Killed")

private fun allowLabel(e: FeedEvent) = if (isAppBlock(e)) "Allow app" else "Allow domain"

/** "Allow" fixes whatever actually blocked the lookup, so it works on the very next request. */
private fun allowEvent(e: FeedEvent) {
    val pkg = e.packageName
    when {
        pkg != null && e.category == "Ask to Connect" -> {
            ZeroLeakage.updateRule(pkg) { it.copy(approved = true, wifi = true, mobile = true) }
            ZeroLeakage.say("${e.appLabel} allowed. It can connect now.")
        }
        pkg != null && e.category == "Total Lockdown" -> {
            ZeroLeakage.updateRule(pkg) { it.copy(pinned = true, wifi = true, mobile = true) }
            ZeroLeakage.say("${e.appLabel} pinned: allowed in Total Zero-Leak")
        }
        pkg != null && e.category == "App Network Killed" -> {
            ZeroLeakage.updateRule(pkg) { it.copy(wifi = true, mobile = true) }
            ZeroLeakage.say("${e.appLabel} back online")
        }
        else -> {
            Filters.allow(e.domain)
            ZeroLeakage.say("${e.domain} allowed for every app")
        }
    }
}

/** Wraps a click so it is felt: a short confirm haptic, then the action. */
@Composable
fun withConfirmHaptic(onClick: () -> Unit): () -> Unit {
    val view = LocalView.current
    return {
        view.performHapticFeedback(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.VIRTUAL_KEY,
        )
        onClick()
    }
}

@Composable
fun SmallAction(text: String, color: Color, onClick: () -> Unit) {
    val click = withConfirmHaptic(onClick)
    Box(
        Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.12f))
            .border(1.dp, color.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
            .clickable(onClick = click)
            .padding(horizontal = 10.dp, vertical = 5.dp),
    ) { Text(text, fontSize = 11.5.sp, fontWeight = FontWeight.SemiBold, color = color) }
}

@Composable
fun SearchField(value: String, onChange: (String) -> Unit, placeholder: String) {
    androidx.compose.foundation.text.BasicTextField(
        value = value,
        onValueChange = onChange,
        singleLine = true,
        textStyle = Zl.mono.copy(fontSize = 12.5.sp),
        cursorBrush = androidx.compose.ui.graphics.SolidColor(Zl.Mint),
        decorationBox = { inner ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(Zl.Inset)
                    .border(1.dp, Zl.Border, RoundedCornerShape(10.dp))
                    .padding(horizontal = 10.dp, vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Search, null, tint = Zl.TextMuted, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Box(Modifier.weight(1f)) {
                    if (value.isEmpty()) Text(placeholder, style = Zl.mono.copy(fontSize = 12.5.sp, color = Zl.TextMuted))
                    inner()
                }
            }
        },
    )
}

private fun uptime(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return String.format(Locale.US, "%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
}
