package app.zeroleakage.mobile.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.FeedEvent
import app.zeroleakage.mobile.data.PacketDetail
import app.zeroleakage.mobile.data.Verdict
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.geo.GeoIp
import app.zeroleakage.mobile.geo.GeoInfo
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.verdictColor
import app.zeroleakage.mobile.ui.theme.Zl
import app.zeroleakage.mobile.vpn.DnsMessage
import app.zeroleakage.mobile.vpn.DnsRecord
import app.zeroleakage.mobile.vpn.DnssecStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val fullTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

fun dnssecColor(s: DnssecStatus): Color = when (s) {
    DnssecStatus.SECURE -> Zl.Mint
    DnssecStatus.INSECURE -> Zl.Amber
    DnssecStatus.BOGUS -> Zl.Crimson
    else -> Zl.TextMuted
}

/** Full-screen packet inspector for one DNS transaction. */
@Composable
fun PacketInspector(e: FeedEvent, onDismiss: () -> Unit) {
    val geoDb by GeoIp.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(10.dp)
                .clip(RoundedCornerShape(20.dp))
                .background(Zl.Canvas)
                .border(1.dp, Zl.Border, RoundedCornerShape(20.dp)),
        ) {
            // header
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Overline("Packet inspector")
                    Text(e.domain, style = Zl.mono.copy(fontSize = 14.sp, fontWeight = FontWeight.SemiBold), maxLines = 2)
                }
                SmallAction("Close", Zl.TextSecondary, onDismiss)
            }
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                val d = e.detail
                Section("Verdict") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Badge(e.verdict.name.replace("PROMPT", "ASK"), verdictColor(e.verdict))
                        Spacer(Modifier.width(8.dp))
                        Text(e.category, fontSize = 13.sp, color = Zl.TextPrimary, fontWeight = FontWeight.SemiBold)
                    }
                    Kv("Time", fullTime.format(Date(e.time)))
                    Kv("App", e.appLabel)
                    e.packageName?.let { Kv("Package", it) }
                    d?.let { Kv("UID", it.uid.toString()); Kv("Network", it.network) }
                    if (d?.rule != null) {
                        Kv(if (e.verdict == Verdict.ALLOWED) "Allowed by" else "Blocked by", d.ruleList ?: "—")
                        Kv("Rule", d.rule)
                        Kv("Matched", d.ruleMatched ?: e.domain)
                    }
                }
                if (d == null) {
                    Text("No packet details were captured for this event.", fontSize = 12.sp, color = Zl.TextMuted)
                } else {
                    QuerySection(e, d)
                    UpstreamSection(d)
                    AnswersSection(d, geoDb.installed)
                    HexSection("Query bytes (DNS payload)", d.queryBytes, d.querySize)
                    HexSection("Response bytes (DNS payload)", d.responseBytes, d.responseSize)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SmallAction("Copy report", Zl.Violet) { copy(context, report(e, d)) }
                        if (e.verdict == Verdict.ALLOWED) SmallAction("Block domain", Zl.Crimson) { Filters.block(e.domain) }
                        else SmallAction("Allow domain", Zl.Mint) { Filters.allow(e.domain) }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun QuerySection(e: FeedEvent, d: PacketDetail) = Section("Query · app → shield") {
    Kv("Question", "${e.domain}  ${DnsMessage.classname(d.qclass)} ${DnsMessage.typeName(d.qtype)}")
    Kv("Transaction ID", "0x%04x".format(d.txId))
    Kv("Header flags", d.queryFlags)
    Kv("EDNS(0)", d.queryEdns ?: "none")
    Kv("Source", "${d.srcIp}:${d.srcPort}")
    Kv("Destination", "${d.dstIp}:${d.dstPort}  (shield DNS)")
    Kv("IPv4", "TTL ${d.ipTtl} · ID 0x%04x · ${d.ipTotalLen} bytes".format(d.ipId))
    Kv("UDP", "len ${d.udpLen} · checksum " + if (d.udpChecksum == 0) "none" else "0x%04x".format(d.udpChecksum))
    Kv("DNS size", "${d.querySize} bytes")
}

@Composable
private fun UpstreamSection(d: PacketDetail) = Section("Upstream · shield → resolver") {
    if (d.resolverName == null) {
        Kv("Resolver", "not contacted — answered locally")
    } else {
        Kv("Resolver", d.resolverName)
        Kv("Endpoint", d.resolverUrl ?: "")
        Kv("Transport", "DNS-over-HTTPS (RFC 8484) · TLS")
        Kv("Cache", if (d.cached) "served from local cache" else "fresh lookup")
        d.latencyMs?.let { Kv("Round trip", "$it ms") }
        d.error?.let { Kv("Error", it, Zl.Crimson) }
    }
    Row(Modifier.padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("DNSSEC", fontSize = 12.sp, color = Zl.TextMuted, modifier = Modifier.width(110.dp))
        Badge(d.dnssec.label.uppercase(), dnssecColor(d.dnssec))
    }
    Text(d.dnssec.description, fontSize = 11.5.sp, color = Zl.TextSecondary, lineHeight = 15.sp)
    d.ede?.let { Kv("Extended error", it, Zl.Amber) }
}

@Composable
private fun AnswersSection(d: PacketDetail, geoInstalled: Boolean) = Section("Response · shield → app") {
    Kv("Status", DnsMessage.rcodeName(d.rcode), if (d.rcode == 0) Zl.Mint else Zl.Crimson)
    if (d.responseFlags.isNotEmpty()) Kv("Header flags", d.responseFlags)
    Kv("DNS size", "${d.responseSize} bytes")
    if (d.answers.isEmpty()) {
        Text("No answer records.", fontSize = 12.sp, color = Zl.TextMuted)
    } else {
        Spacer(Modifier.height(4.dp))
        Overline("Answers (${d.answers.size})")
        d.answers.forEach { RecordRow(it, geoInstalled) }
    }
    if (d.authority.isNotEmpty()) {
        Spacer(Modifier.height(4.dp))
        Overline("Authority (${d.authority.size})")
        d.authority.forEach { RecordRow(it, geoInstalled) }
    }
    if (geoInstalled && d.answers.any { it.address != null }) {
        Text("Anycast networks (Cloudflare, Google, CDNs) may show the country the block is registered to, not the server you reach.",
            fontSize = 10.5.sp, color = Zl.TextMuted, lineHeight = 14.sp)
    }
    if (!geoInstalled && d.answers.any { it.address != null }) {
        Text("Download the GeoIP database in DNS → Country lookup to see where each IP is located.",
            fontSize = 11.5.sp, color = Zl.Amber, lineHeight = 15.sp)
    }
}

@Composable
private fun RecordRow(r: DnsRecord, geoInstalled: Boolean) {
    val geo: GeoInfo? = r.address?.let { GeoIp.lookup(it) }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Zl.Inset)
            .border(1.dp, Zl.Border, RoundedCornerShape(10.dp))
            .padding(10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Badge(r.typeName, Zl.Violet)
            Spacer(Modifier.width(8.dp))
            Text(r.data, style = Zl.mono.copy(fontSize = 12.sp), modifier = Modifier.weight(1f))
        }
        Text("${r.name} · TTL ${r.ttl}s", style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted))
        if (r.address != null) {
            when {
                geo != null -> {
                    Text(geo.label, fontSize = 12.5.sp, color = Zl.TextPrimary, fontWeight = FontWeight.SemiBold)
                    geo.note?.let { Text(it, fontSize = 11.sp, color = Zl.TextSecondary) }
                }
                geoInstalled -> Text("Unknown location", fontSize = 11.5.sp, color = Zl.TextMuted)
                else -> Text("Location: GeoIP database not downloaded", fontSize = 11.5.sp, color = Zl.TextMuted)
            }
        }
    }
}

@Composable
private fun HexSection(title: String, bytes: ByteArray, total: Int) {
    var open by remember { mutableStateOf(false) }
    Section(title) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("$total bytes", style = Zl.mono.copy(fontSize = 11.sp, color = Zl.TextSecondary), modifier = Modifier.weight(1f))
            SmallAction(if (open) "Hide hex" else "Show hex", Zl.TextSecondary) { open = !open }
        }
        if (open) {
            Box(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                Text(DnsMessage.hexDump(bytes, 1024), style = Zl.mono.copy(fontSize = 10.sp, color = Zl.TextSecondary, lineHeight = 14.sp))
            }
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(Zl.Surface)
            .border(1.dp, Zl.Border, RoundedCornerShape(14.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Overline(title, color = Zl.TextPrimary)
        Spacer(Modifier.height(2.dp))
        content()
    }
}

@Composable
private fun Kv(key: String, value: String, color: Color = Zl.TextPrimary) {
    Row {
        Text(key, fontSize = 12.sp, color = Zl.TextMuted, modifier = Modifier.width(110.dp))
        Text(value, style = Zl.mono.copy(fontSize = 12.sp, color = color), modifier = Modifier.weight(1f))
    }
}

private fun copy(context: Context, text: String) {
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("ZeroLeakage packet", text))
    Toast.makeText(context, "Packet report copied", Toast.LENGTH_SHORT).show()
}

private fun report(e: FeedEvent, d: PacketDetail): String = buildString {
    appendLine("ZeroLeakage packet report")
    appendLine("time      ${fullTime.format(Date(e.time))}")
    appendLine("verdict   ${e.verdict} · ${e.category}")
    appendLine("app       ${e.appLabel} (${e.packageName ?: "-"}, uid ${d.uid}) on ${d.network}")
    appendLine("question  ${e.domain} ${DnsMessage.classname(d.qclass)} ${DnsMessage.typeName(d.qtype)} id=0x%04x flags=[${d.queryFlags}]".format(d.txId))
    appendLine("packet    ${d.srcIp}:${d.srcPort} -> ${d.dstIp}:${d.dstPort} ttl=${d.ipTtl} len=${d.ipTotalLen}")
    d.rule?.let { appendLine("rule      $it (${d.ruleList})") }
    d.resolverName?.let { appendLine("resolver  $it ${d.resolverUrl} ${d.latencyMs?.let { ms -> "${ms}ms" } ?: ""}${if (d.cached) " cached" else ""}") }
    appendLine("dnssec    ${d.dnssec.label}${d.ede?.let { " · $it" } ?: ""}")
    appendLine("rcode     ${DnsMessage.rcodeName(d.rcode)} flags=[${d.responseFlags}] size=${d.responseSize}")
    d.answers.forEach { r ->
        val geo = r.address?.let { GeoIp.lookup(it) }?.let { " [${it.code ?: "-"} ${it.name}]" } ?: ""
        appendLine("answer    ${r.name} ${r.ttl} ${r.typeName} ${r.data}$geo")
    }
}
