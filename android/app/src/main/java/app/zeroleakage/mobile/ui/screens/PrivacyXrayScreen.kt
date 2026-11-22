package app.zeroleakage.mobile.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.zeroleakage.mobile.data.AppExposure
import app.zeroleakage.mobile.data.Capability
import app.zeroleakage.mobile.data.PrivacyXray
import app.zeroleakage.mobile.data.Risk
import app.zeroleakage.mobile.data.XrayReport
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.Chip
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/** Quick filter chips. [caps] = match apps holding any of these; null = no capability constraint. */
private enum class XFilter(val label: String, val caps: Set<Capability>?) {
    ALL("All", null),
    CRITICAL("Critical", null),
    MIC("Mic", setOf(Capability.MICROPHONE)),
    CAMERA("Camera", setOf(Capability.CAMERA)),
    LOCATION("Location", setOf(Capability.LOCATION, Capability.LOCATION_BACKGROUND)),
    MESSAGES("Messages", setOf(Capability.SMS, Capability.READ_NOTIFICATIONS, Capability.READ_SCREEN)),
    TYPING("Typing", setOf(Capability.KEYBOARD)),
    CALLS("Calls", setOf(Capability.CALLS)),
    CONTACTS("Contacts", setOf(Capability.CONTACTS)),
    FILES("Files", setOf(Capability.FILES_MEDIA)),
    TRACKING("Usage & overlay", setOf(Capability.USAGE_ACCESS, Capability.DRAW_OVER)),
}

private fun riskColor(r: Risk): Color = when (r) {
    Risk.CRITICAL -> Zl.Crimson
    Risk.HIGH -> Zl.Amber
    Risk.MEDIUM -> Zl.Violet
    Risk.LOW -> Zl.TextMuted
}

/** Full-screen "Privacy X-ray": which installed apps can read, hear or see private data. */
@Composable
fun PrivacyXrayScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    var scanKey by remember { mutableIntStateOf(0) }
    var report by remember { mutableStateOf<XrayReport?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    var filter by rememberSaveable { mutableStateOf(XFilter.ALL) }
    var capFilter by rememberSaveable { mutableStateOf<Capability?>(null) }
    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(scanKey) {
        loading = true
        error = null
        val result = withContext(Dispatchers.Default) {
            runCatching { PrivacyXray.scan(context.applicationContext) }
        }
        result.onSuccess { report = it }.onFailure { error = it.message ?: it.javaClass.simpleName }
        loading = false
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(Zl.Canvas)
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        // ── Top bar ────────────────────────────────────────────────────────
        Row(
            Modifier.fillMaxWidth().padding(start = 4.dp, end = 16.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Close", tint = Zl.TextPrimary)
            }
            Column(Modifier.weight(1f)) {
                Text("Privacy X-ray", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Zl.TextPrimary)
                val r = report
                Text(
                    when {
                        loading -> "Scanning installed apps…"
                        r != null -> "${r.apps.size} apps with access · " +
                            DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(r.scannedAt))
                        else -> "Scan failed"
                    },
                    style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted),
                )
            }
            if (!loading) SmallAction("Rescan", Zl.Mint) { scanKey++ }
        }

        val r = report
        when {
            loading && r == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = Zl.Mint, strokeWidth = 2.dp, modifier = Modifier.size(32.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Checking permissions and special access…", fontSize = 12.sp, color = Zl.TextSecondary)
                }
            }
            r == null -> Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("Couldn't scan installed apps.", color = Zl.TextPrimary, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    Text(error ?: "Unknown error", style = Zl.mono.copy(fontSize = 11.sp, color = Zl.TextMuted))
                    Spacer(Modifier.height(12.dp))
                    SmallAction("Try again", Zl.Mint) { scanKey++ }
                }
            }
            else -> XrayContent(
                report = r,
                filter = filter,
                capFilter = capFilter,
                query = query,
                showSystem = showSystem,
                onFilter = { filter = it; capFilter = null },
                onCapFilter = { cap -> capFilter = if (capFilter == cap) null else cap; filter = XFilter.ALL },
                onQuery = { query = it },
                onShowSystem = { showSystem = it },
                context = context,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun XrayContent(
    report: XrayReport,
    filter: XFilter,
    capFilter: Capability?,
    query: String,
    showSystem: Boolean,
    onFilter: (XFilter) -> Unit,
    onCapFilter: (Capability) -> Unit,
    onQuery: (String) -> Unit,
    onShowSystem: (Boolean) -> Unit,
    context: Context,
) {
    val q = query.trim().lowercase()
    val matching = report.apps.filter { app ->
        val capOk = when {
            capFilter != null -> capFilter in app.capabilities
            filter == XFilter.CRITICAL -> app.hasCritical
            filter.caps != null -> app.capabilities.any { it in filter.caps }
            else -> true
        }
        val queryOk = q.isEmpty() || app.label.lowercase().contains(q) || app.packageName.lowercase().contains(q)
        capOk && queryOk
    }
    val visible = if (showSystem) matching else matching.filter { !it.isSystem || it.hasCritical }
    val hiddenSystem = matching.size - visible.size

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Text(
                "Apps that can read, hear or see your private data. Tap an app to review or revoke in Android settings.",
                fontSize = 13.sp, color = Zl.TextSecondary, lineHeight = 18.sp,
            )
        }

        // ── Honest note ───────────────────────────────────────────────────
        item {
            GlassCard(Modifier.fillMaxWidth(), accent = Zl.Amber, padding = 14.dp) {
                Overline("What this can't see", color = Zl.Amber)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Android doesn't let any app see another app's live microphone or camera use. Watch for the green " +
                        "indicator in the status bar, and open Android's Privacy dashboard for the last 24 h/7 days of " +
                        "mic, camera and location access.",
                    fontSize = 12.5.sp, color = Zl.TextSecondary, lineHeight = 17.sp,
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Privacy dashboard", Zl.Mint) { openPrivacyDashboard(context) }
                }
            }
        }

        // ── Summary grid ──────────────────────────────────────────────────
        item { Overline("Critical access", Modifier.padding(top = 4.dp), color = Zl.Crimson) }
        item {
            val kb = report.defaultKeyboardLabel ?: "Unknown"
            SummaryGrid(
                listOf(
                    Triple(Capability.READ_SCREEN, "Can read your screen", report.count(Capability.READ_SCREEN).toString()),
                    Triple(Capability.READ_NOTIFICATIONS, "Can read notifications", report.count(Capability.READ_NOTIFICATIONS).toString()),
                    Triple(Capability.KEYBOARD, "Sees everything you type", kb),
                    Triple(Capability.DEVICE_ADMIN, "Device admins", report.count(Capability.DEVICE_ADMIN).toString()),
                ),
                accent = Zl.Crimson, selected = capFilter, onSelect = onCapFilter,
            )
        }
        item { Overline("High-risk permissions", Modifier.padding(top = 4.dp), color = Zl.Amber) }
        item {
            SummaryGrid(
                listOf(
                    Capability.MICROPHONE, Capability.CAMERA, Capability.SMS,
                    Capability.CALLS, Capability.LOCATION_BACKGROUND,
                ).map { Triple(it, it.title, report.count(it).toString()) },
                accent = Zl.Amber, selected = capFilter, onSelect = onCapFilter,
            )
        }

        // ── Filters ───────────────────────────────────────────────────────
        item {
            Column(Modifier.padding(top = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    XFilter.entries.forEach { f ->
                        Chip(
                            f.label,
                            selected = capFilter == null && filter == f,
                            accent = if (f == XFilter.CRITICAL) Zl.Crimson else Zl.Mint,
                            onClick = { onFilter(f) },
                        )
                    }
                }
                if (capFilter != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Showing: ", fontSize = 12.sp, color = Zl.TextMuted)
                        Chip("${capFilter.title}  ×", selected = true, accent = riskColor(capFilter.risk), onClick = { onFilter(XFilter.ALL) })
                    }
                }
                SearchField(query, onQuery, "Search apps or packages")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${visible.size} shown" + if (hiddenSystem > 0) " · $hiddenSystem system apps hidden" else "",
                        style = Zl.mono.copy(fontSize = 11.sp, color = Zl.TextMuted),
                        modifier = Modifier.weight(1f),
                    )
                    Chip(
                        if (showSystem) "Hide system apps" else "Show system apps",
                        selected = showSystem, accent = Zl.Violet, onClick = { onShowSystem(!showSystem) },
                    )
                }
            }
        }

        // ── List ──────────────────────────────────────────────────────────
        if (visible.isEmpty()) {
            item {
                GlassCard(Modifier.fillMaxWidth(), padding = 16.dp) {
                    Text(
                        when {
                            report.apps.isEmpty() -> "No installed apps hold any of these permissions or special access. " +
                                "If that seems wrong, Android may be hiding other apps from this one — check the Privacy dashboard."
                            hiddenSystem > 0 -> "Only system apps match. Tap \"Show system apps\" to see them."
                            else -> "No apps match this filter."
                        },
                        fontSize = 12.5.sp, color = Zl.TextSecondary, lineHeight = 17.sp,
                    )
                }
            }
        } else {
            items(visible, key = { it.packageName }) { app -> AppRow(app, context) }
        }
    }
}

@Composable
private fun SummaryGrid(
    tiles: List<Triple<Capability, String, String>>,
    accent: Color,
    selected: Capability?,
    onSelect: (Capability) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        tiles.chunked(2).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                row.forEach { (cap, label, value) ->
                    SummaryTile(label, value, accent, selected == cap, Modifier.weight(1f)) { onSelect(cap) }
                }
                if (row.size == 1) Spacer(Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun SummaryTile(label: String, value: String, accent: Color, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    val isZero = value == "0"
    val tint = if (isZero) Zl.TextMuted else accent
    Column(
        modifier
            .clip(shape)
            .background(if (selected) accent.copy(alpha = 0.12f) else Zl.Surface)
            .border(1.dp, if (selected) accent else Zl.Border, shape)
            .clickable(onClick = onClick)
            .padding(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(tint))
            Spacer(Modifier.width(6.dp))
            Text(label, fontSize = 11.sp, color = Zl.TextSecondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            value,
            style = Zl.mono.copy(
                fontSize = if (value.length > 6) 13.sp else 20.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (isZero) Zl.TextMuted else Zl.TextPrimary,
            ),
            maxLines = 1, overflow = TextOverflow.Ellipsis,
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppRow(app: AppExposure, context: Context) {
    val top = app.topRisk
    val shape = RoundedCornerShape(14.dp)
    Column(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(Zl.Surface)
            .border(1.dp, if (top == Risk.CRITICAL) Zl.Crimson.copy(alpha = 0.35f) else Zl.Border, shape)
            .clickable { openAppDetails(context, app.packageName) }
            .padding(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        app.label, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false),
                    )
                    if (app.isSystem) {
                        Spacer(Modifier.width(6.dp))
                        Text("SYSTEM", style = Zl.overline.copy(fontSize = 9.sp))
                    }
                }
                Text(
                    app.packageName, style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted),
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Badge(top.name, riskColor(top))
        }
        Spacer(Modifier.height(8.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            app.capabilities.sortedWith(compareBy({ app.riskOf(it).ordinal }, { it.ordinal })).forEach { cap ->
                val text = if (cap == Capability.KEYBOARD && app.isDefaultKeyboard) "Keyboard (default)" else cap.title
                Badge(text, riskColor(app.riskOf(cap)))
            }
        }
        val critical = app.capabilities.filter { it.risk == Risk.CRITICAL }
        if (critical.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            critical.forEach { cap ->
                Text("• ${cap.explain}", fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 15.sp)
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(
            Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            SmallAction("App settings", Zl.Mint) { openAppDetails(context, app.packageName) }
            if (Capability.READ_SCREEN in app.capabilities) {
                SmallAction("Accessibility settings", Zl.Crimson) { launch(context, Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
            }
            if (Capability.READ_NOTIFICATIONS in app.capabilities) {
                SmallAction("Notification access", Zl.Crimson) {
                    launch(context, Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))
                        || launch(context, Intent(Settings.ACTION_SETTINGS))
                }
            }
            if (Capability.KEYBOARD in app.capabilities) {
                SmallAction("Keyboard settings", riskColor(app.riskOf(Capability.KEYBOARD))) {
                    launch(context, Intent(Settings.ACTION_INPUT_METHOD_SETTINGS))
                }
            }
            if (Capability.DEVICE_ADMIN in app.capabilities) {
                SmallAction("Device admin apps", Zl.Crimson) {
                    launch(context, Intent("android.settings.DEVICE_ADMIN_SETTINGS"))
                        || launch(context, Intent(Settings.ACTION_SECURITY_SETTINGS))
                }
            }
        }
    }
}

// ── Intents ──────────────────────────────────────────────────────────────

private fun launch(context: Context, intent: Intent): Boolean = runCatching {
    context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}.isSuccess

private fun openAppDetails(context: Context, pkg: String) {
    launch(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null)))
        || launch(context, Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS))
}

private fun openPrivacyDashboard(context: Context) {
    launch(context, Intent("android.intent.action.REVIEW_PERMISSION_USAGE"))
        || launch(context, Intent(Settings.ACTION_PRIVACY_SETTINGS))
        || launch(context, Intent(Settings.ACTION_SETTINGS))
}
