package app.zeroleakage.mobile.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.ShieldPulse
import app.zeroleakage.mobile.ui.theme.Zl

@Composable
fun OnboardingScreen(onEnable: () -> Unit, onSkip: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 22.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(20.dp))
        ShieldPulse(Zl.Mint, active = true, modifier = Modifier.size(170.dp))
        Spacer(Modifier.height(18.dp))
        Text("Leak nothing.", fontSize = 32.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
        Text(
            "ZeroLeakage watches every DNS lookup on this phone and drops the ones that phone home.",
            fontSize = 14.sp, color = Zl.TextSecondary, lineHeight = 20.sp,
            modifier = Modifier.padding(top = 6.dp),
        )
        Spacer(Modifier.height(22.dp))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Point("01", Zl.Mint, "On-device only", "A local VPN filters DNS right on the phone. Nothing is routed to us — there are no ZeroLeakage servers.")
            Point("02", Zl.Violet, "Encrypted DNS", "Allowed lookups go out over DNS-over-HTTPS, so your carrier and Wi-Fi can't read them.")
            Point("03", Zl.Crimson, "You decide", "Kill any app's Wi-Fi or mobile access, or switch to Strict Guard so new apps must ask first.")
        }
        Spacer(Modifier.height(24.dp))
        Text(
            "Android will ask you to allow a VPN connection and notifications next.",
            fontSize = 11.5.sp, color = Zl.TextMuted,
        )
        Spacer(Modifier.height(10.dp))
        Button(
            onClick = onEnable,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Zl.Mint, contentColor = Zl.Canvas),
        ) { Text("ENGAGE SHIELD", fontWeight = FontWeight.Bold, letterSpacing = 1.sp) }
        TextButton(onClick = onSkip) { Text("Not now", color = Zl.TextSecondary) }
    }
}

@Composable
private fun Point(num: String, color: Color, title: String, body: String) {
    GlassCard(Modifier.fillMaxWidth(), accent = color, padding = 14.dp) {
        Row {
            Text("$num //", style = Zl.mono.copy(color = color, fontWeight = FontWeight.Bold))
            Spacer(Modifier.width(10.dp))
            Column {
                Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                Text(body, fontSize = 12.5.sp, color = Zl.TextSecondary, lineHeight = 17.sp)
            }
        }
    }
}
