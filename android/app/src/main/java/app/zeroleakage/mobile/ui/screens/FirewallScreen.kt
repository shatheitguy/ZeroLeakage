package app.zeroleakage.mobile.ui.screens

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import androidx.compose.foundation.Image
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
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.AppRule
import app.zeroleakage.mobile.data.InstalledApp
import app.zeroleakage.mobile.data.ProtectionMode
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.Chip
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.ZlSwitch
import app.zeroleakage.mobile.ui.components.formatCount
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private enum class AppFilter { ALL, KILLED, APPROVED, PINNED }

@Composable
fun FirewallScreen() {
    val context = LocalContext.current
    val rules by ZeroLeakage.rules.collectAsStateWithLifecycle()
    val mode by ZeroLeakage.mode.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(AppFilter.ALL) }
    val accent = Zl.accent(mode)

    val apps by produceState<List<InstalledApp>?>(null) {
        value = withContext(Dispatchers.IO) { loadLaunchableApps(context) }
    }

    LazyColumn(
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Column(Modifier.padding(horizontal = 4.dp)) {
                Text("App Firewall", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                Text(
                    when (mode) {
                        ProtectionMode.BALANCED -> "Cut any app off Wi-Fi or mobile data instantly. Its lookups are dropped on-device."
                        ProtectionMode.STRICT -> "Strict Guard: apps must be approved (from the Ask-to-Connect prompt or here) before they get online."
                        ProtectionMode.LOCKDOWN -> "Total Zero-Leak: only ★ pinned apps may reach the internet."
                    },
                    fontSize = 13.sp, color = Zl.TextSecondary, lineHeight = 18.sp,
                )
                Spacer(Modifier.height(12.dp))
                SearchField(query, { query = it }, "Search apps…")
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Chip("All", filter == AppFilter.ALL, accent, { filter = AppFilter.ALL })
                    Chip("Killed", filter == AppFilter.KILLED, accent, { filter = AppFilter.KILLED })
                    Chip("Approved", filter == AppFilter.APPROVED, accent, { filter = AppFilter.APPROVED })
                    Chip("★ Pinned", filter == AppFilter.PINNED, accent, { filter = AppFilter.PINNED })
                }
                Spacer(Modifier.height(4.dp))
            }
        }

        val list = apps
        if (list == null) {
            item { Box(Modifier.fillMaxWidth().padding(32.dp), Alignment.Center) { CircularProgressIndicator(color = accent) } }
        } else {
            val shown = list.filter { a ->
                val r = rules[a.packageName] ?: AppRule(a.packageName)
                (query.isBlank() || a.label.contains(query, true) || a.packageName.contains(query, true)) &&
                    when (filter) {
                        AppFilter.ALL -> true
                        AppFilter.KILLED -> !r.wifi || !r.mobile
                        AppFilter.APPROVED -> r.approved
                        AppFilter.PINNED -> r.pinned
                    }
            }
            item {
                Overline("${shown.size} apps · ${rules.values.count { it.isKilled }} killed", Modifier.padding(start = 4.dp, top = 4.dp))
            }
            items(shown, key = { it.packageName }) { app ->
                AppRow(app, rules[app.packageName] ?: AppRule(app.packageName), mode)
            }
        }
    }
}

@Composable
private fun AppRow(app: InstalledApp, rule: AppRule, mode: ProtectionMode) {
    val context = LocalContext.current
    val icon by produceState<ImageBitmap?>(null, app.packageName) {
        value = withContext(Dispatchers.IO) {
            runCatching { context.packageManager.getApplicationIcon(app.packageName).toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    GlassCard(padding = 12.dp) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(40.dp).clip(RoundedCornerShape(11.dp)).background(Zl.SurfaceRaised),
                contentAlignment = Alignment.Center,
            ) {
                icon?.let { Image(it, null, Modifier.size(30.dp)) }
                    ?: Text(app.label.take(1).uppercase(), style = Zl.mono.copy(fontWeight = FontWeight.Bold, fontSize = 15.sp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(app.label, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(app.packageName, style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Box(
                Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .clickable { ZeroLeakage.updateRule(app.packageName) { it.copy(pinned = !it.pinned) } },
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.Star, "Pin for Total Zero-Leak", tint = if (rule.pinned) Zl.Amber else Zl.BorderStrong)
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (rule.isKilled) Badge("KILLED", Zl.Crimson)
                if (rule.approved) Badge("APPROVED", Zl.Violet)
                else if (mode == ProtectionMode.STRICT && !app.isSystem) Badge("NEEDS APPROVAL", Zl.Amber)
                if (rule.blocked > 0) Badge("${formatCount(rule.blocked)} BLOCKED", Zl.TextSecondary)
            }
            NetworkToggle("Wi-Fi", rule.wifi) { v -> ZeroLeakage.updateRule(app.packageName) { it.copy(wifi = v) } }
            Spacer(Modifier.width(8.dp))
            NetworkToggle("Mobile", rule.mobile) { v -> ZeroLeakage.updateRule(app.packageName) { it.copy(mobile = v) } }
        }
        if (mode == ProtectionMode.STRICT && !app.isSystem) {
            Spacer(Modifier.height(8.dp))
            SmallAction(if (rule.approved) "Revoke approval" else "Approve app", if (rule.approved) Zl.TextSecondary else Zl.Violet) {
                ZeroLeakage.updateRule(app.packageName) { it.copy(approved = !it.approved) }
            }
        }
    }
}

@Composable
private fun NetworkToggle(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label.uppercase(), style = Zl.overline.copy(fontSize = 9.sp))
        ZlSwitch(checked, onChange)
    }
}

private fun loadLaunchableApps(context: Context): List<InstalledApp> {
    val pm = context.packageManager
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return pm.queryIntentActivities(intent, 0)
        .map { it.activityInfo.applicationInfo }
        .distinctBy { it.packageName }
        .filter { it.packageName != context.packageName }
        .map {
            InstalledApp(
                packageName = it.packageName,
                label = pm.getApplicationLabel(it).toString(),
                isSystem = (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
            )
        }
        .sortedBy { it.label.lowercase() }
}
