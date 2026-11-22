package app.zeroleakage.mobile.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.Resolver
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.filters.FilterCatalog
import app.zeroleakage.mobile.filters.FilterList
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.filters.ListStatus
import app.zeroleakage.mobile.geo.GeoIp
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.ZlSwitch
import app.zeroleakage.mobile.ui.components.formatCount
import app.zeroleakage.mobile.ui.theme.Zl

private enum class DnsTab(val title: String) { FILTERS("Filters"), RESOLVER("Resolver"), DNSSEC("DNSSEC & Geo"), RULES("My rules") }

@Composable
fun DnsScreen() {
    var tab by rememberSaveable { mutableStateOf(DnsTab.FILTERS) }

    LazyColumn(
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(Modifier.padding(horizontal = 4.dp)) {
                Text("DNS & Filters", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                Text(
                    "Every lookup is checked on-device against your filter lists, then resolved over encrypted DNS-over-HTTPS.",
                    fontSize = 13.sp, color = Zl.TextSecondary, lineHeight = 18.sp,
                )
                Spacer(Modifier.height(10.dp))
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    DnsTab.entries.forEach { t ->
                        app.zeroleakage.mobile.ui.components.Chip(t.title, tab == t, Zl.Violet, { tab = t })
                    }
                }
            }
        }
        when (tab) {
            DnsTab.FILTERS -> filtersTab(this)
            DnsTab.RESOLVER -> item { ResolverCard() }
            DnsTab.DNSSEC -> {
                item { DnssecCard() }
                item { GeoCard() }
            }
            DnsTab.RULES -> {
                item { DomainListCard(allow = true) }
                item { DomainListCard(allow = false) }
            }
        }
    }
}

// ═══════════════════════════ Filters ═══════════════════════════

private fun filtersTab(scope: androidx.compose.foundation.lazy.LazyListScope) = with(scope) {
    item { FiltersHeader() }
    FilterCatalog.GROUP_ORDER.forEach { group ->
        item(key = "g_$group") { FilterGroup(group) }
    }
    item { AddFilterCard() }
}

@Composable
private fun FiltersHeader() {
    val total by Filters.totalRules.collectAsStateWithLifecycle()
    val enabled by Filters.enabled.collectAsStateWithLifecycle()
    val rebuilding by Filters.rebuilding.collectAsStateWithLifecycle()
    val status by Filters.status.collectAsStateWithLifecycle()
    val downloading = status.values.any { it.downloading }
    GlassCard(accent = Zl.Violet) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Overline("Active rules", color = Zl.TextPrimary)
                Text(formatCount(total.toLong()), style = Zl.metric.copy(color = Zl.Violet))
                Text("${enabled.size} lists enabled", fontSize = 12.sp, color = Zl.TextSecondary)
            }
            if (rebuilding || downloading) {
                CircularProgressIndicator(Modifier.size(22.dp), color = Zl.Violet, strokeWidth = 2.dp)
                Spacer(Modifier.width(10.dp))
            }
            SmallAction(if (downloading) "Updating…" else "Update all", Zl.Violet) { if (!downloading) Filters.updateAll() }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Lists use AdGuard / AdBlock (||domain^), hosts and plain-domain formats. Enabled lists refresh every 3 days " +
                "when the shield starts. Very large lists use more RAM — enable one all-in-one list rather than several.",
            fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp,
        )
    }
}

@Composable
private fun FilterGroup(group: String) {
    val lists by Filters.lists.collectAsStateWithLifecycle()
    val enabled by Filters.enabled.collectAsStateWithLifecycle()
    val status by Filters.status.collectAsStateWithLifecycle()
    val inGroup = lists.filter { it.group == group }
    if (inGroup.isEmpty()) return
    GlassCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Overline(group, color = Zl.TextPrimary)
            Spacer(Modifier.weight(1f))
            Text("${inGroup.count { it.id in enabled }}/${inGroup.size}", style = Zl.mono.copy(fontSize = 11.sp, color = Zl.TextMuted))
        }
        Spacer(Modifier.height(10.dp))
        inGroup.forEach { FilterRow(it, it.id in enabled, status[it.id] ?: ListStatus()) }
    }
}

@Composable
private fun FilterRow(list: FilterList, on: Boolean, st: ListStatus) {
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(Zl.Inset)
            .border(1.dp, if (on) Zl.Violet.copy(alpha = 0.35f) else Zl.Border, RoundedCornerShape(12.dp))
            .padding(start = 12.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(list.name, fontSize = 13.5.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    if (list.defaultOn) { Spacer(Modifier.width(6.dp)); Badge("DEFAULT", Zl.Mint) }
                }
                Text(list.description, fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            ZlSwitch(on, { Filters.setEnabled(list.id, it) }, Zl.Violet)
        }
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            val line = when {
                st.downloading -> "downloading…"
                st.error != null -> "⚠ ${st.error}"
                list.isBundled -> if (st.rules > 0) "${formatCount(st.rules.toLong())} rules · bundled" else "bundled"
                st.updatedAt > 0 -> "${formatCount(st.rules.toLong())} rules · " +
                    Formatter.formatShortFileSize(context, st.bytes) + " · updated " +
                    DateUtils.getRelativeTimeSpanString(st.updatedAt, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS)
                else -> "${list.approxRules.ifEmpty { "?" }} rules · not downloaded"
            }
            Text(line, style = Zl.mono.copy(fontSize = 10.5.sp, color = if (st.error != null) Zl.Amber else Zl.TextSecondary),
                modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (!list.isBundled && !st.downloading) {
                MiniLink("Update") { Filters.update(list.id) }
            }
            list.homepage?.let { url ->
                MiniLink("Site") {
                    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                }
            }
            if (list.custom) MiniLink("Remove", Zl.Crimson) { Filters.removeCustom(list.id) }
        }
    }
}

@Composable
private fun AddFilterCard() {
    var url by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    GlassCard {
        Overline("Add a filter list by URL", color = Zl.TextPrimary)
        Spacer(Modifier.height(10.dp))
        InputField(url, { url = it; error = null }, "https://example.com/filter.txt")
        Spacer(Modifier.height(8.dp))
        InputField(name, { name = it }, "Name (optional)")
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(error ?: "Any AdGuard / AdBlock, hosts or domains list works.", fontSize = 11.5.sp,
                color = if (error != null) Zl.Crimson else Zl.TextMuted, modifier = Modifier.weight(1f))
            SmallAction("Add list", Zl.Violet) {
                error = Filters.addCustom(url, name)
                if (error == null) { url = ""; name = "" }
            }
        }
    }
}

// ═══════════════════════════ Resolver ═══════════════════════════

@Composable
private fun ResolverCard() {
    val context = LocalContext.current
    val resolverId by ZeroLeakage.resolverId.collectAsStateWithLifecycle()
    val customUrl by ZeroLeakage.customResolverUrl.collectAsStateWithLifecycle()
    val stats by ZeroLeakage.stats.collectAsStateWithLifecycle()
    var custom by rememberSaveable { mutableStateOf(customUrl) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    GlassCard(accent = Zl.Violet) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Overline("Encrypted DNS", color = Zl.TextPrimary)
            Spacer(Modifier.width(8.dp))
            Badge("DoH · TLS", Zl.Violet)
            Spacer(Modifier.weight(1f))
            Text("${stats.dohLatencyMs} ms", style = Zl.mono.copy(color = Zl.Violet, fontWeight = FontWeight.SemiBold))
        }
        Spacer(Modifier.height(12.dp))
        ZeroLeakage.RESOLVERS.forEach { r -> ResolverRow(r, r.id == resolverId) }
        if (customUrl.isNotEmpty()) {
            ResolverRow(Resolver(ZeroLeakage.CUSTOM_RESOLVER, "Custom DoH", customUrl, customUrl, "Custom"), resolverId == ZeroLeakage.CUSTOM_RESOLVER)
        }
        val fallback by ZeroLeakage.fallbackDns.collectAsStateWithLifecycle()
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Fall back to network DNS", fontSize = 13.5.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                Text(
                    "If every encrypted resolver is blocked on a network, answer through that network's own DNS (unencrypted) instead of breaking all apps. Filters and the firewall still apply.",
                    fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp,
                )
            }
            Spacer(Modifier.width(10.dp))
            ZlSwitch(fallback, ZeroLeakage::setFallbackDns, Zl.Violet)
        }
        Spacer(Modifier.height(4.dp))
        Overline("Custom DoH endpoint")
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { InputField(custom, { custom = it; error = null }, "https://dns.example/dns-query") }
            Spacer(Modifier.width(8.dp))
            SmallAction("Use", Zl.Violet) { error = ZeroLeakage.setCustomResolver(custom) }
        }
        error?.let { Text(it, fontSize = 11.5.sp, color = Zl.Crimson) }
        Spacer(Modifier.height(10.dp))
        Row(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(Zl.Amber.copy(alpha = 0.08f))
                .clickable { context.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                .padding(10.dp),
        ) {
            Text(
                "Tip: set Android “Private DNS” to Off or Automatic — a custom Private DNS host bypasses the on-device filter.",
                fontSize = 11.5.sp, color = Zl.Amber, lineHeight = 16.sp,
            )
        }
    }
}

@Composable
private fun ResolverRow(r: Resolver, selected: Boolean) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(if (selected) Zl.Violet.copy(alpha = 0.12f) else Zl.Inset)
            .border(1.dp, if (selected) Zl.Violet.copy(alpha = 0.6f) else Zl.Border, RoundedCornerShape(12.dp))
            .clickable { ZeroLeakage.setResolver(r.id) }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.size(16.dp).clip(CircleShape).border(1.5.dp, if (selected) Zl.Violet else Zl.BorderStrong, CircleShape),
            contentAlignment = Alignment.Center,
        ) { if (selected) Box(Modifier.size(8.dp).clip(CircleShape).background(Zl.Violet)) }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(r.name, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
            Text(r.note, fontSize = 11.5.sp, color = Zl.TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Badge(r.group.uppercase(), Zl.TextSecondary)
    }
}

// ═══════════════════════════ DNSSEC & GeoIP ═══════════════════════════

@Composable
private fun DnssecCard() {
    val on by ZeroLeakage.dnssec.collectAsStateWithLifecycle()
    val strict by ZeroLeakage.dnssecStrict.collectAsStateWithLifecycle()
    val stats by ZeroLeakage.stats.collectAsStateWithLifecycle()
    GlassCard(accent = Zl.Mint) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Overline("DNSSEC validation", color = Zl.TextPrimary)
                Text("Ask the resolver to verify the signature chain of every answer and flag forged replies.",
                    fontSize = 12.sp, color = Zl.TextSecondary, lineHeight = 16.sp)
            }
            ZlSwitch(on, ZeroLeakage::setDnssec, Zl.Mint)
        }
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatBox("Signed", if (stats.dnssecChecked > 0) "${stats.dnssecPercent}%" else "—", Zl.Mint, Modifier.weight(1f))
            StatBox("Checked", formatCount(stats.dnssecChecked), Zl.TextPrimary, Modifier.weight(1f))
            StatBox("Failed", formatCount(stats.dnssecFailed), Zl.Crimson, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Strict mode: block unsigned domains", fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                    color = if (on) Zl.TextPrimary else Zl.TextMuted)
                Text("Paranoid. Most sites (including many big ones) are not DNSSEC-signed and will stop loading.",
                    fontSize = 11.5.sp, color = Zl.Amber, lineHeight = 15.sp)
            }
            ZlSwitch(strict, ZeroLeakage::setDnssecStrict, Zl.Crimson, enabled = on)
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Answers that fail validation are always refused. The lock 🔒 in the live feed marks validated answers; " +
                "tap any lookup → Details for the full DNSSEC result.",
            fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp,
        )
    }
}

@Composable
private fun GeoCard() {
    val st by GeoIp.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    GlassCard {
        Overline("Country lookup (GeoIP)", color = Zl.TextPrimary)
        Spacer(Modifier.height(4.dp))
        Text(
            "Shows which country every resolved IP address is in. The database is downloaded once and every lookup " +
                "happens on your phone — no IP is ever sent to a geolocation service.",
            fontSize = 12.sp, color = Zl.TextSecondary, lineHeight = 16.sp,
        )
        Spacer(Modifier.height(10.dp))
        when {
            st.busy -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), color = Zl.Mint, strokeWidth = 2.dp)
                Spacer(Modifier.width(10.dp))
                Text(st.progress ?: "Working…", style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextSecondary))
            }
            st.installed -> {
                Text("${st.source} · ${formatCount(st.ranges.toLong())} ranges · ${Formatter.formatShortFileSize(context, st.sizeBytes)}",
                    style = Zl.mono.copy(fontSize = 11.sp, color = Zl.Mint))
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Update", Zl.Mint) { GeoIp.download() }
                    SmallAction("Delete", Zl.TextSecondary) { GeoIp.delete() }
                }
            }
            else -> SmallAction("Download database (5 MB download)", Zl.Mint) { GeoIp.download() }
        }
        st.error?.let { Spacer(Modifier.height(6.dp)); Text("⚠ $it", fontSize = 11.5.sp, color = Zl.Amber) }
        Spacer(Modifier.height(8.dp))
        Text(GeoIp.ATTRIBUTION, fontSize = 10.5.sp, color = Zl.TextMuted, modifier = Modifier.clickable {
            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(GeoIp.ATTRIBUTION_URL)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        })
    }
}

// ═══════════════════════════ My rules ═══════════════════════════

@Composable
private fun DomainListCard(allow: Boolean) {
    val domains by (if (allow) Filters.userAllow else Filters.userBlock).collectAsStateWithLifecycle()
    var input by rememberSaveable(allow) { mutableStateOf("") }
    val color = if (allow) Zl.Mint else Zl.Crimson
    GlassCard {
        Overline(if (allow) "Allowlist — never block" else "Blocklist — always block", color = Zl.TextPrimary)
        Spacer(Modifier.height(4.dp))
        Text(
            if (allow) "Overrides every filter list. Use it when a list breaks an app or site you need."
            else "Your own domains. Each entry also covers all of its subdomains.",
            fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp,
        )
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { InputField(input, { input = it }, if (allow) "bank.example.com" else "tracker.example.com") }
            Spacer(Modifier.width(8.dp))
            SmallAction(if (allow) "Allow" else "Block", color) {
                val ok = if (allow) Filters.allow(input) else Filters.block(input)
                if (ok != null) input = ""
            }
        }
        Spacer(Modifier.height(10.dp))
        if (domains.isEmpty()) {
            Text("None yet — add one here, or tap a row in the live feed.", fontSize = 11.5.sp, color = Zl.TextMuted)
        }
        domains.sorted().forEach { d ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(bottom = 6.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(Zl.Inset)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(if (allow) "✓" else "✕", color = color, fontSize = 11.sp)
                Spacer(Modifier.width(10.dp))
                Text(d, style = Zl.mono, modifier = Modifier.weight(1f))
                SmallAction("Remove", Zl.TextSecondary) { if (allow) Filters.unallow(d) else Filters.unblock(d) }
            }
        }
    }
}

// ═══════════════════════════ bits ═══════════════════════════

@Composable
private fun StatBox(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Column(
        modifier
            .clip(RoundedCornerShape(12.dp))
            .background(Zl.Inset)
            .border(1.dp, Zl.Border, RoundedCornerShape(12.dp))
            .padding(10.dp),
    ) {
        Overline(label)
        Text(value, style = Zl.mono.copy(fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = color))
    }
}

@Composable
private fun MiniLink(text: String, color: Color = Zl.Violet, onClick: () -> Unit) {
    Text(
        text, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = color,
        modifier = Modifier.clip(RoundedCornerShape(6.dp)).clickable(onClick = onClick).padding(horizontal = 6.dp, vertical = 3.dp),
    )
}

@Composable
fun InputField(value: String, onChange: (String) -> Unit, placeholder: String) {
    BasicTextField(
        value = value,
        onValueChange = onChange,
        singleLine = true,
        textStyle = Zl.mono.copy(fontSize = 12.5.sp),
        cursorBrush = SolidColor(Zl.Mint),
        decorationBox = { inner ->
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(Zl.Inset)
                    .border(1.dp, Zl.Border, RoundedCornerShape(10.dp))
                    .padding(horizontal = 10.dp, vertical = 9.dp),
            ) {
                if (value.isEmpty()) Text(placeholder, style = Zl.mono.copy(fontSize = 12.5.sp, color = Zl.TextMuted))
                inner()
            }
        },
    )
}
