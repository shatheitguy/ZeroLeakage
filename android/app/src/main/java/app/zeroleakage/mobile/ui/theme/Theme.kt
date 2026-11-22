package app.zeroleakage.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import app.zeroleakage.mobile.data.ProtectionMode

/** Same palette as the Windows app — Dark Glassmorphism / Cyber-Minimalist. */
object Zl {
    val Canvas = Color(0xFF090A0F)
    val Surface = Color(0xFF12151E)
    val SurfaceTop = Color(0xFF161A25)
    val SurfaceRaised = Color(0xFF181C28)
    val Inset = Color(0xFF0C0E14)
    val Border = Color(0xFF1F2433)
    val BorderStrong = Color(0xFF2A3145)

    val Mint = Color(0xFF00F5A0)
    val Violet = Color(0xFF7B61FF)
    val Crimson = Color(0xFFFF2E54)
    val Amber = Color(0xFFFFB547)

    val TextPrimary = Color(0xFFF2F4F8)
    val TextSecondary = Color(0xFF9AA3B5)
    val TextMuted = Color(0xFF5C6478)

    val Mono = FontFamily.Monospace

    fun accent(mode: ProtectionMode) = when (mode) {
        ProtectionMode.BALANCED -> Mint
        ProtectionMode.STRICT -> Violet
        ProtectionMode.LOCKDOWN -> Crimson
    }

    val overline = TextStyle(fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = TextMuted, letterSpacing = 1.2.sp)
    val mono = TextStyle(fontFamily = Mono, fontSize = 12.sp, color = TextPrimary)
    val metric = TextStyle(fontFamily = Mono, fontSize = 26.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
}

@Composable
fun ZeroLeakageTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Zl.Mint,
            onPrimary = Zl.Canvas,
            secondary = Zl.Violet,
            error = Zl.Crimson,
            background = Zl.Canvas,
            onBackground = Zl.TextPrimary,
            surface = Zl.Surface,
            onSurface = Zl.TextPrimary,
            surfaceVariant = Zl.SurfaceRaised,
            onSurfaceVariant = Zl.TextSecondary,
            outline = Zl.BorderStrong,
        ),
        content = content,
    )
}
