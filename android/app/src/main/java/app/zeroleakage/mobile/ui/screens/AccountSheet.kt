package app.zeroleakage.mobile.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.ServerLink
import app.zeroleakage.mobile.data.Updates
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.BrandMark
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.formatCount
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.launch

/** Round avatar in the top bar; a dot appears when an update is waiting. */
@Composable
fun ProfileButton(accent: Color, onClick: () -> Unit) {
    val update by Updates.state.collectAsStateWithLifecycle()
    Box {
        Box(
            Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(Zl.Surface)
                .border(1.dp, accent.copy(alpha = 0.45f), CircleShape)
                .clickable(onClick = withConfirmHaptic(onClick)),
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Filled.Person, contentDescription = "Profile and settings", tint = accent, modifier = Modifier.size(18.dp)) }
        if (update is Updates.State.Available) {
            Box(Modifier.align(Alignment.TopEnd).size(9.dp).clip(CircleShape).background(Zl.Crimson).border(1.5.dp, Zl.Canvas, CircleShape))
        }
    }
}

enum class AccountDestination { SETTINGS, ABOUT, XRAY, UPDATE, SYNC }

/** Profile menu: account (optional), privacy X-ray, settings, about, updates. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountSheet(onDismiss: () -> Unit, onNavigate: (AccountDestination) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val update by Updates.state.collectAsStateWithLifecycle()
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet, containerColor = Zl.Surface, contentColor = Zl.TextPrimary) {
        Column(Modifier.padding(horizontal = 18.dp).padding(bottom = 24.dp).navigationBarsPadding()) {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(48.dp).clip(CircleShape).background(Zl.Inset).border(1.dp, Zl.Border, CircleShape), contentAlignment = Alignment.Center) {
                    BrandMark(Zl.Mint, Modifier.size(26.dp))
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    val linked by ServerLink.link.collectAsStateWithLifecycle()
                    Text(linked?.username ?: linked?.deviceName ?: "Local profile", fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                    Text(linked?.let { "Synced with ${it.serverName}" } ?: "Not signed in · your rules stay on this phone",
                        fontSize = 12.sp, color = Zl.TextMuted)
                }
            }
            Spacer(Modifier.height(16.dp))

            val link by ServerLink.link.collectAsStateWithLifecycle()
            MenuItem(
                Icons.Filled.Share, "Account & sync",
                link?.let { "Linked to ${it.serverName}" + (it.username?.let { u -> " as $u" } ?: "") }
                    ?: "Optional: link this phone to your ZeroLeakage server",
                badge = if (link != null) "LINKED" else null,
            ) { onNavigate(AccountDestination.SYNC) }
            MenuItem(Icons.Filled.Warning, "Privacy X-ray", "Which apps can read your screen, chats, notifications or hear you") {
                onNavigate(AccountDestination.XRAY)
            }
            MenuItem(Icons.Filled.Settings, "Settings", "Protection method, shield, data") { onNavigate(AccountDestination.SETTINGS) }
            MenuItem(Icons.Filled.Info, "About ZeroLeakage", "Version, device and app details") { onNavigate(AccountDestination.ABOUT) }
            MenuItem(
                Icons.Filled.Refresh, "Check for updates", updateSubtitle(update),
                badge = if (update is Updates.State.Available) "NEW" else null,
            ) {
                // Always open the update screen: it checks, then downloads, verifies and installs in-app.
                onNavigate(AccountDestination.UPDATE)
                if (update !is Updates.State.Available) scope.launch { Updates.check(context, force = true) }
            }
        }
    }
}

fun updateSubtitle(s: Updates.State): String = when (s) {
    Updates.State.Idle -> "Tap to check GitHub for a newer version"
    Updates.State.Checking -> "Checking…"
    is Updates.State.UpToDate -> "You're on the latest version (${s.current})"
    is Updates.State.Available -> "Version ${s.release.version} is available · tap to update"
    is Updates.State.Failed -> "Couldn't check: ${s.message}"
}

@Composable
private fun MenuItem(icon: ImageVector, title: String, subtitle: String, badge: String? = null, enabled: Boolean = true, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(bottom = 6.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Zl.Inset)
            .border(1.dp, Zl.Border, RoundedCornerShape(14.dp))
            .then(if (enabled) Modifier.clickable(onClick = withConfirmHaptic(onClick)) else Modifier)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, null, tint = if (enabled) Zl.Mint else Zl.TextMuted, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 14.5.sp, fontWeight = FontWeight.SemiBold, color = if (enabled) Zl.TextPrimary else Zl.TextSecondary)
            Text(subtitle, fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp)
        }
        badge?.let { Spacer(Modifier.width(8.dp)); Badge(it, if (it == "NEW") Zl.Crimson else Zl.Violet) }
    }
}

/** App details, device details and update check. */
@Composable
fun AboutScreen(onClose: () -> Unit, onOpenUpdate: () -> Unit = {}) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val update by Updates.state.collectAsStateWithLifecycle()
    val method by ZeroLeakage.method.collectAsStateWithLifecycle()
    val mode by ZeroLeakage.mode.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    val rules by Filters.totalRules.collectAsStateWithLifecycle()
    val version = Updates.currentVersion(context)

    val details = listOf(
        "Version" to "$version (build ${Updates.versionCode(context)})",
        "Package" to context.packageName,
        "Protection" to if (method == ZeroLeakage.Method.LITE) "Lite · Private DNS" else "Full Shield · ${if (running) "running" else "stopped"}",
        "Mode" to "${mode.number} · ${mode.title}",
        "Resolver" to ZeroLeakage.resolver().name,
        "Filter rules" to formatCount(rules.toLong()),
        "Android" to "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
        "Device" to "${Build.MANUFACTURER} ${Build.MODEL}",
    )

    Column(Modifier.fillMaxSize().background(Zl.Canvas).statusBarsPadding().navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(44.dp).clip(CircleShape).clickable(onClick = onClose), contentAlignment = Alignment.Center) {
                @Suppress("DEPRECATION")
                Icon(Icons.Filled.ArrowBack, "Back", tint = Zl.TextPrimary)
            }
            Text("About", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
        }
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 14.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            GlassCard(accent = Zl.Mint) {
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(Modifier.size(84.dp).clip(RoundedCornerShape(24.dp)).background(Zl.Surface).border(1.dp, Zl.Border, RoundedCornerShape(24.dp)), contentAlignment = Alignment.Center) {
                        BrandMark(Zl.Mint, Modifier.size(56.dp))
                    }
                    Spacer(Modifier.height(12.dp))
                    Row {
                        Text("Zero", fontSize = 24.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                        Text("Leakage", fontSize = 24.sp, color = Zl.TextSecondary)
                    }
                    Text("Version $version", style = Zl.mono.copy(fontSize = 12.sp, color = Zl.Mint))
                    Spacer(Modifier.height(6.dp))
                    Text("Zero bits leaked. On-device DNS firewall for Android.", fontSize = 12.5.sp, color = Zl.TextSecondary)
                }
            }

            GlassCard {
                Overline("Updates", color = Zl.TextPrimary)
                Spacer(Modifier.height(8.dp))
                Text(updateSubtitle(update), fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                    color = when (update) { is Updates.State.Available -> Zl.Mint; is Updates.State.Failed -> Zl.Amber; else -> Zl.TextPrimary })
                val s = update
                if (s is Updates.State.Available && s.release.notes.isNotBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Text(s.release.notes.take(400), fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 16.sp)
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (s is Updates.State.Available) {
                        SmallAction("Update to ${s.release.version}", Zl.Mint) { onOpenUpdate() }
                        SmallAction("What's new", Zl.TextSecondary) { Updates.open(context, s.release.pageUrl) }
                    } else {
                        SmallAction(if (s is Updates.State.Checking) "Checking…" else "Check for updates", Zl.Mint) {
                            if (s !is Updates.State.Checking) scope.launch { Updates.check(context, force = true) }
                        }
                    }
                }
            }

            GlassCard {
                Overline("App & device details", color = Zl.TextPrimary)
                Spacer(Modifier.height(8.dp))
                details.forEach { (k, v) ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                        Text(k, fontSize = 12.5.sp, color = Zl.TextMuted, modifier = Modifier.width(104.dp))
                        Text(v, style = Zl.mono.copy(fontSize = 12.sp, color = Zl.TextPrimary), modifier = Modifier.weight(1f))
                    }
                }
                Spacer(Modifier.height(8.dp))
                SmallAction("Copy details", Zl.TextSecondary) {
                    val text = details.joinToString("\n") { "${it.first}: ${it.second}" }
                    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("ZeroLeakage", text))
                    ZeroLeakage.say("Details copied")
                }
            }

            GlassCard {
                Overline("Links", color = Zl.TextPrimary)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Website", Zl.Violet) { Updates.open(context, Updates.WEBSITE) }
                    SmallAction("Source code", Zl.Violet) { Updates.open(context, Updates.SOURCE) }
                    SmallAction("All releases", Zl.Violet) { Updates.open(context, Updates.RELEASES_PAGE) }
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    "Privacy: no account, no analytics, no ZeroLeakage servers. The only network requests are the encrypted DNS you choose, " +
                        "filter-list downloads, the optional GeoIP database and this update check (a plain request to GitHub).",
                    fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 16.sp,
                )
            }
        }
    }
}
