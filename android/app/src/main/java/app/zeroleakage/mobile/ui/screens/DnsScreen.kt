package app.zeroleakage.mobile.ui.screens

import android.content.Intent
import android.provider.Settings
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.ui.components.Badge
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.ZlSwitch
import app.zeroleakage.mobile.ui.theme.Zl

@Composable
fun DnsScreen() {
    val context = LocalContext.current
    val resolverId by ZeroLeakage.resolverId.collectAsStateWithLifecycle()
    val enabled by ZeroLeakage.enabledLists.collectAsStateWithLifecycle()
    val custom by ZeroLeakage.customDomains.collectAsStateWithLifecycle()
    val stats by ZeroLeakage.stats.collectAsStateWithLifecycle()
    var newDomain by rememberSaveable { mutableStateOf("") }

    LazyColumn(
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(Modifier.padding(horizontal = 4.dp)) {
                Text("DNS & Trackers", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                Text(
                    "Every lookup is checked on-device, then resolved over encrypted DNS-over-HTTPS. Your carrier and Wi-Fi owner see nothing.",
                    fontSize = 13.sp, color = Zl.TextSecondary, lineHeight = 18.sp,
                )
            }
        }

        // Encrypted resolver
        item {
            GlassCard(accent = Zl.Violet) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Overline("Encrypted DNS", color = Zl.TextPrimary)
                    Spacer(Modifier.width(8.dp))
                    Badge("DoH · TLS 1.3", Zl.Violet)
                    Spacer(Modifier.weight(1f))
                    Text("${stats.dohLatencyMs} ms", style = Zl.mono.copy(color = Zl.Violet, fontWeight = FontWeight.SemiBold))
                }
                Spacer(Modifier.height(12.dp))
                ZeroLeakage.RESOLVERS.forEach { r ->
                    val selected = r.id == resolverId
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
                            Text(r.note, fontSize = 11.5.sp, color = Zl.TextMuted)
                        }
                    }
                }
                // Private DNS overrides any VPN-provided DNS server.
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

        // Blocklists
        item {
            GlassCard {
                Overline("Blocklists", color = Zl.TextPrimary)
                Spacer(Modifier.height(10.dp))
                ZeroLeakage.BLOCKLISTS.forEach { list ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(Zl.Inset)
                            .border(1.dp, Zl.Border, RoundedCornerShape(12.dp))
                            .padding(start = 12.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(list.name, fontSize = 13.5.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                            Text(list.description, fontSize = 11.5.sp, color = Zl.TextMuted, lineHeight = 15.sp)
                            Text("${ZeroLeakage.listSize(list.id)} domains", style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextSecondary))
                        }
                        ZlSwitch(list.id in enabled, { ZeroLeakage.setListEnabled(list.id, it) }, Zl.Violet)
                    }
                }
            }
        }

        // Custom domains
        item {
            GlassCard {
                Overline("Custom blocked domains", color = Zl.TextPrimary)
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f)) { SearchField(newDomain, { newDomain = it }, "tracker.example.com") }
                    Spacer(Modifier.width(8.dp))
                    Button(
                        onClick = { if (ZeroLeakage.addCustomDomain(newDomain) != null) newDomain = "" },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Zl.Crimson, contentColor = Color.White),
                    ) { Text("Block", fontWeight = FontWeight.Bold) }
                }
                Spacer(Modifier.height(10.dp))
                if (custom.isEmpty()) {
                    Text("None yet — add one here, or tap any row in the live feed → Block domain.", fontSize = 11.5.sp, color = Zl.TextMuted)
                }
                custom.sorted().forEach { d ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(bottom = 6.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Zl.Inset)
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("✕", color = Zl.Crimson, fontSize = 11.sp)
                        Spacer(Modifier.width(10.dp))
                        Text(d, style = Zl.mono, modifier = Modifier.weight(1f))
                        SmallAction("Unblock", Zl.TextSecondary) { ZeroLeakage.removeCustomDomain(d) }
                    }
                }
            }
        }
    }
}
