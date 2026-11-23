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
import app.zeroleakage.mobile.data.FeedHistory
import app.zeroleakage.mobile.data.ProtectionMode
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

    // Uptime clock: ticks only while the dashboard is on screen and the shield is running.
    val now = app.zeroleakage.mobile.ui.components.rememberVisibleTicker(1_000, enabled = running)

    // Live = the in-memory stream; Today / Yesterday / 7 days come from the on-device history.
    var range by rememberSaveable { mutableStateOf(FeedHistory.Range.LIVE) }
    val liveVisible = feed.filter {
        (filter == FeedFilter.ALL || (filter == FeedFilter.BLOCKED && it.verdict != Verdict.ALLOWED) ||
            (filter == FeedFilter.ALLOWED && it.verdict == Verdict.ALLOWED)) &&
            (query.isBlank() || it.domain.contains(query, true) || it.appLabel.contains(query, true) || it.category.contains(query, true))
    }
    // Re-query history when the view changes, and every 25 new lookups while "Today"/"7 days" is open.
    val historyKey = if (range == FeedHistory.Range.TODAY || range == FeedHistory.Range.WEEK) (feed.firstOrNull()?.id ?: 0L) / 25 else 0L
    val history by androidx.compose.runtime.produceState<List<FeedEvent>?>(null, range, filter, query, historyKey) {
        value = if (range == FeedHistory.Range.LIVE) null else FeedHistory.query(
            range, when (filter) { FeedFilter.ALL -> null; FeedFilter.BLOCKED -> true; FeedFilter.ALLOWED -> false }, query,
        )
    }
    val summary by androidx.compose.runtime.produceState<FeedHistory.Summary?>(null, range, historyKey) {
        value = if (range == FeedHistory.Range.LIVE) null else FeedHistory.summary(range)
    }
    val visible = if (range == FeedHistory.Range.LIVE) liveVisible else history ?: emptyList()

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
                    val ctxP = androidx.compose.ui.platform.LocalContext.current
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = shield.stop,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Zl.BorderStrong),
                        ) { Text("Stop shield", color = Zl.TextSecondary) }
                        OutlinedButton(
                            onClick = {
                                ZeroLeakage.pauseForOtherVpn(ctxP)
                                ZeroLeakage.say("Paused. Start your other VPN; the shield comes back when it disconnects.")
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Zl.Violet.copy(alpha = 0.6f)),
                        ) { Text("Pause for VPN", color = Zl.Violet) }
                    }
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
        item { DashboardNotices(shield) }
        if (method == ZeroLeakage.Method.LITE) item { ProtectionMethodCard(shield) }

        // ═════ What was blocked ═════
        item { BlockedBreakdown(stats, feed, rules) }

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
                    Overline(if (range == FeedHistory.Range.LIVE) "Live DNS feed" else "DNS history", color = Zl.TextPrimary)
                    Spacer(Modifier.weight(1f))
                    Text(
                        summary?.let { "${formatCount(it.total)} lookups · ${formatCount(it.blocked)} blocked" } ?: "${feed.size} events",
                        style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted),
                    )
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FeedHistory.Range.entries.forEach { r -> Chip(r.title, range == r, accent, { range = r; expanded = null }) }
                }
                Spacer(Modifier.height(8.dp))
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
                    when {
                        range != FeedHistory.Range.LIVE && history == null -> "Loading…"
                        range != FeedHistory.Range.LIVE -> "No lookups ${range.title.lowercase()}${if (query.isNotBlank() || filter != FeedFilter.ALL) " match this filter" else ""}."
                        running -> "Waiting for DNS lookups…"
                        else -> "Engage the shield to see every lookup on this phone in real time."
                    },
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
private val dayTimeFormat = SimpleDateFormat("EEE HH:mm", Locale.US)

/** Time for today's lookups; weekday + time for older ones (history views). */
private fun feedTime(t: Long): String {
    val startOfToday = FeedHistory.bounds(FeedHistory.Range.TODAY).first
    return if (t >= startOfToday) timeFormat.format(Date(t)) else dayTimeFormat.format(Date(t))
}

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
            Text(feedTime(e.time), style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted))
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
        if (e.packageName != null && e.verdict != Verdict.ALLOWED && e.category in setOf("Ask to Connect", "Total Lockdown")) {
            val ctxA = androidx.compose.ui.platform.LocalContext.current
            val advice = remember(e.packageName) { app.zeroleakage.mobile.data.AppAdvice.forPackage(ctxA, e.packageName) }
            Spacer(Modifier.height(6.dp))
            AdviceLine(advice)
        }
        AnimatedVisibility(isExpanded) {
            Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (e.detail != null) SmallAction("Details", Zl.Violet, onInspect)
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
            ZeroLeakage.updateRule(pkg) { it.copy(approved = true, wifi = true, mobile = true) }
            ZeroLeakage.say("${e.appLabel} allowed. It works in Total Zero-Leak and Strict Guard.")
        }
        pkg != null && e.category == "App Network Killed" -> {
            ZeroLeakage.updateRule(pkg) { it.copy(wifi = true, mobile = true) }
            ZeroLeakage.say("${e.appLabel} back online")
        }
        else -> {
            if (Filters.allow(e.domain) == null && Filters.blockedByAdmin(e.domain))
                ZeroLeakage.say("${e.domain} is blocked by your server's admin")
            else ZeroLeakage.say("${e.domain} allowed for every app")
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

/** Context-aware tips at the top of the dashboard. */
@Composable
fun DashboardNotices(shield: ShieldController) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    val mode by ZeroLeakage.mode.collectAsStateWithLifecycle()
    val method by ZeroLeakage.method.collectAsStateWithLifecycle()
    val takenOver by ZeroLeakage.takenOver.collectAsStateWithLifecycle()
    val resume by ZeroLeakage.resumeRequested.collectAsStateWithLifecycle()
    val rules by ZeroLeakage.rules.collectAsStateWithLifecycle()
    val tips by ZeroLeakage.dismissedTips.collectAsStateWithLifecycle()

    val alwaysOn by ZeroLeakage.alwaysOn.collectAsStateWithLifecycle()

    // Opening the app while the shield is paused for another VPN that has since disconnected: come back now.
    LaunchedEffect(takenOver) {
        if (takenOver && !ZeroLeakage.vpnRunning.value && method == ZeroLeakage.Method.FULL &&
            !app.zeroleakage.mobile.vpn.OtherVpnWatcher.anyVpnActive(context)) {
            shield.start()
        }
    }

    // A tap on "Turn shield on" in a notification lands here.
    LaunchedEffect(resume) {
        if (resume) {
            ZeroLeakage.requestResume(false)
            app.zeroleakage.mobile.vpn.OtherVpnWatcher.cancel(context)
            if (!ZeroLeakage.vpnRunning.value) shield.start()
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (takenOver && !running && method == ZeroLeakage.Method.FULL) {
            Notice(
                "Another VPN (like WireGuard) took Android's VPN slot, so the shield paused. Android runs one VPN at a time. " +
                    "When that VPN turns off, ZeroLeakage offers to come back. Lite mode works alongside it with no conflict.",
                Zl.Amber, action = "Turn shield back on",
            ) { shield.start() }
            SmallAction("Use Lite mode with my VPN", Zl.Mint) {
                ZeroLeakage.setMethod(ZeroLeakage.Method.LITE)
                ZeroLeakage.setTakenOver(false)
                ZeroLeakage.say("Lite mode: pick a filtering DNS below; it works with WireGuard")
            }
        }
        val guardAlerts by app.zeroleakage.mobile.data.Guard.alerts.collectAsStateWithLifecycle()
        guardAlerts.firstOrNull()?.takeIf { System.currentTimeMillis() - it.time < 24 * 3_600_000L && "guard_${it.time}" !in tips }?.let { a ->
            Notice("Guard: ${a.scenario} in ${a.app}. ${a.detail}", Zl.Crimson, action = if (a.pkg != null) "Cut off ${a.app}" else null) {
                a.pkg?.let { p -> ZeroLeakage.updateRule(p) { it.copy(wifi = false, mobile = false, approved = false, pinned = false) } }
                ZeroLeakage.dismissTip("guard_${a.time}")
                ZeroLeakage.say("${a.app} cut off from the network")
            }
            SmallAction("Dismiss", Zl.TextMuted) { ZeroLeakage.dismissTip("guard_${a.time}") }
        }
        if (running && alwaysOn && "always_on" !in tips) {
            Notice(
                "ZeroLeakage is set as Android's Always-on VPN, so Android won't let other VPNs (like WireGuard) start. " +
                    "To switch between them, turn Always-on off for ZeroLeakage, then use \"Pause for VPN\": the shield comes back " +
                    "on its own when your other VPN disconnects.",
                Zl.Amber, action = "Open VPN settings",
            ) {
                runCatching { context.startActivity(android.content.Intent(android.provider.Settings.ACTION_VPN_SETTINGS).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)) }
                ZeroLeakage.say("Tap ⚙ next to ZeroLeakage and switch off Always-on VPN")
            }
            SmallAction("Keep Always-on", Zl.TextMuted) { ZeroLeakage.dismissTip("always_on") }
        }
        val approved = rules.values.count { it.approved }
        if (mode != ProtectionMode.BALANCED && approved < 3 && "strict_setup" !in tips) {
            Notice(
                (if (mode == ProtectionMode.STRICT) "Strict Guard asks before every app goes online" else "Total Zero-Leak blocks every app you haven't allowed") +
                    ", so at first a lot gets blocked. Allow the apps you use every day (Chrome, Google, YouTube, Gmail, Maps, Play Store, WhatsApp…). " +
                    "The same allowed list works in both modes.",
                Zl.Violet, action = "Approve popular apps",
            ) {
                val installed = installedLaunchable(context)
                val n = ZeroLeakage.approveApps(ZeroLeakage.POPULAR_APPS.filter { it in installed })
                ZeroLeakage.say("$n popular apps approved")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SmallAction("Approve all apps I have now", Zl.TextSecondary) {
                    val n = ZeroLeakage.approveApps(installedLaunchable(context))
                    ZeroLeakage.say("$n apps approved. Strict Guard now asks only about new apps.")
                }
                SmallAction("Dismiss", Zl.TextMuted) { ZeroLeakage.dismissTip("strict_setup") }
            }
        }
        if (running && "hide_notification" !in tips) {
            Notice(
                "Android shows a \"running\" notification whenever any VPN is on. You can hide just that one; prompts and alerts keep working, and so does the shield.",
                Zl.TextSecondary, action = "Hide only the running notice",
            ) {
                val i = android.content.Intent(android.provider.Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                    .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, context.packageName)
                    .putExtra(android.provider.Settings.EXTRA_CHANNEL_ID, app.zeroleakage.mobile.vpn.ZeroLeakVpnService.CHANNEL_QUIET)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { context.startActivity(i) }
                ZeroLeakage.dismissTip("hide_notification")
                ZeroLeakage.say("Switch off \"Running status\" only")
            }
        }
    }
}

/** Packages of apps that have a launcher icon (what Strict Guard asks about). */
fun installedLaunchable(context: android.content.Context): Set<String> {
    val pm = context.packageManager
    val intent = android.content.Intent(android.content.Intent.ACTION_MAIN).addCategory(android.content.Intent.CATEGORY_LAUNCHER)
    return pm.queryIntentActivities(intent, 0).map { it.activityInfo.packageName }.filter { it != context.packageName }.toSet()
}

private fun kindColor(k: app.zeroleakage.mobile.data.BlockKind): Color = when (k) {
    app.zeroleakage.mobile.data.BlockKind.TRACKERS -> Zl.Violet
    app.zeroleakage.mobile.data.BlockKind.TELEMETRY -> Zl.Amber
    app.zeroleakage.mobile.data.BlockKind.MALWARE -> Zl.Crimson
    app.zeroleakage.mobile.data.BlockKind.PARENTAL -> Color(0xFFFF7AC6)
    app.zeroleakage.mobile.data.BlockKind.USER -> Zl.TextSecondary
    app.zeroleakage.mobile.data.BlockKind.APPS -> Zl.Mint
    app.zeroleakage.mobile.data.BlockKind.DNSSEC -> Color(0xFF4FC3F7)
}

/** "What ZeroLeakage blocked": totals per kind with bars, top blocked domains and the apps blocked most. */
@Composable
fun BlockedBreakdown(stats: app.zeroleakage.mobile.data.Stats, feed: List<FeedEvent>, rules: Map<String, app.zeroleakage.mobile.data.AppRule>) {
    val total = stats.totalBlocked
    GlassCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Overline("What was blocked", color = Zl.TextPrimary)
            Spacer(Modifier.weight(1f))
            Text(formatCount(total), style = Zl.mono.copy(fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Zl.Crimson))
        }
        Text(
            if (stats.totalQueries > 0) "${"%.1f".format(java.util.Locale.US, total * 100.0 / stats.totalQueries)}% of ${formatCount(stats.totalQueries)} lookups blocked"
            else "Nothing yet: engage the shield and use your phone as normal.",
            fontSize = 11.5.sp, color = Zl.TextMuted,
        )
        Spacer(Modifier.height(12.dp))
        val max = (stats.byKind.values.maxOrNull() ?: 0L).coerceAtLeast(1)
        app.zeroleakage.mobile.data.BlockKind.entries.forEach { k ->
            val n = stats.byKind[k] ?: 0
            if (n == 0L && k in setOf(app.zeroleakage.mobile.data.BlockKind.PARENTAL, app.zeroleakage.mobile.data.BlockKind.DNSSEC, app.zeroleakage.mobile.data.BlockKind.USER)) return@forEach
            val c = kindColor(k)
            Column(Modifier.padding(bottom = 10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(2.dp)).background(c))
                    Spacer(Modifier.width(8.dp))
                    Text(k.title, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary, modifier = Modifier.weight(1f))
                    Text(formatCount(n), style = Zl.mono.copy(fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = if (n > 0) c else Zl.TextMuted))
                }
                Spacer(Modifier.height(5.dp))
                Box(Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)).background(Zl.Inset)) {
                    Box(Modifier.fillMaxWidth((n.toFloat() / max).coerceIn(0f, 1f)).height(5.dp).clip(RoundedCornerShape(3.dp)).background(c))
                }
                Text(k.explain, fontSize = 10.5.sp, color = Zl.TextMuted, modifier = Modifier.padding(top = 3.dp))
            }
        }

        // Top blocked domains (recent feed) and the apps blocked most.
        val topDomains = feed.filter { it.verdict != Verdict.ALLOWED }.groupingBy { it.domain }.eachCount()
            .entries.sortedByDescending { it.value }.take(5)
        val topApps = rules.values.filter { it.blocked > 0 }.sortedByDescending { it.blocked }.take(5)
        val labels = feed.mapNotNull { e -> e.packageName?.let { it to e.appLabel } }.toMap()
        if (topDomains.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Overline("Most-blocked domains (recent)")
            Spacer(Modifier.height(6.dp))
            topDomains.forEach { (d, n) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                    Text(d, style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextSecondary), maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    Text("×$n", style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextMuted))
                }
            }
        }
        if (topApps.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Overline("Apps blocked most")
            Spacer(Modifier.height(6.dp))
            topApps.forEach { r ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                    Text(labels[r.packageName] ?: r.packageName, fontSize = 12.sp, color = Zl.TextSecondary, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    Text(formatCount(r.blocked), style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextMuted))
                }
            }
        }
    }
}
