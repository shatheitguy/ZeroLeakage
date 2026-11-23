package app.zeroleakage.mobile.ui.components

import androidx.lifecycle.repeatOnLifecycle
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.zeroleakage.mobile.data.ProtectionMode
import app.zeroleakage.mobile.data.Verdict
import app.zeroleakage.mobile.ui.theme.Zl
import kotlin.math.cos
import kotlin.math.sin

/** Frosted-glass card: gradient surface, 1dp hairline border, soft top sheen. */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    accent: Color? = null,
    padding: Dp = 16.dp,
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = RoundedCornerShape(20.dp)
    Box(
        modifier
            .clip(shape)
            .background(Brush.linearGradient(listOf(Zl.SurfaceTop, Zl.Surface, Color(0xFF0F121A))))
            .border(BorderStroke(1.dp, Zl.Border), shape)
            .drawBehind {
                // 1px accent glint along the top edge
                if (accent != null) {
                    drawLine(
                        Brush.horizontalGradient(listOf(Color.Transparent, accent.copy(alpha = 0.8f), Color.Transparent)),
                        Offset(size.width * 0.12f, 0.5f), Offset(size.width * 0.88f, 0.5f), strokeWidth = 1.5f,
                    )
                }
            },
    ) {
        Column(Modifier.padding(padding), content = content)
    }
}

@Composable
fun Overline(text: String, modifier: Modifier = Modifier, color: Color = Zl.TextMuted) =
    Text(text.uppercase(), modifier, style = Zl.overline.copy(color = color))

/** "Negative-space shield" brand mark (see ShieldMark.kt). */
@Composable
fun BrandMark(color: Color, modifier: Modifier = Modifier.size(24.dp)) {
    Canvas(modifier) { drawShieldMarkCentered(color, size.minDimension) }
}

@Suppress("UNUSED_PARAMETER")
private fun DrawScope.drawBrandMark(color: Color, extent: Float, stroke: Float) =
    drawShieldMarkCentered(color, extent)

/** Radial "sonar" pulse showing the shield is live. Rings freeze when [active] is false. */
@Composable
fun ShieldPulse(color: Color, active: Boolean, modifier: Modifier = Modifier.size(128.dp)) {
    val transition = rememberInfiniteTransition(label = "pulse")
    val phase by transition.animateFloat(
        0f, 1f, infiniteRepeatable(tween(2700, easing = LinearEasing), RepeatMode.Restart), label = "phase",
    )
    val breathe by transition.animateFloat(
        0.55f, 1f, infiniteRepeatable(tween(1600, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "breathe",
    )
    val tint by animateColorAsState(color, tween(450), label = "tint")

    Canvas(modifier) {
        val maxR = size.minDimension / 2f
        if (active) {
            for (i in 0 until 3) {
                val p = (phase + i / 3f) % 1f
                val r = maxR * (0.58f + 0.42f * p)
                drawCircle(tint.copy(alpha = 0.7f * (1f - p)), r, style = Stroke(1.5.dp.toPx()))
            }
        }
        val haloR = maxR * 0.8f
        drawCircle(
            Brush.radialGradient(listOf(tint.copy(alpha = if (active) 0.33f * breathe else 0.08f), Color.Transparent), center, haloR),
            haloR,
        )
        drawCircle(Color(0xFF0D1017), maxR * 0.6f)
        drawCircle(tint.copy(alpha = if (active) 1f else 0.4f), maxR * 0.6f, style = Stroke(1.5.dp.toPx()))
        val markSize = maxR * 0.62f
        translate(top = -maxR * 0.06f) {
            drawBrandMark(tint.copy(alpha = if (active) 1f else 0.45f), markSize, stroke = 1.6.dp.toPx())
        }
    }
}

/** Animated 3-segment pill — 1-tap switching between the protection modes. */
@Composable
fun ModeSwitcher(mode: ProtectionMode, onSelect: (ProtectionMode) -> Unit, modifier: Modifier = Modifier) {
    val accent by animateColorAsState(Zl.accent(mode), tween(400), label = "accent")
    val shape = RoundedCornerShape(16.dp)
    BoxWithConstraints(
        modifier
            .fillMaxWidth()
            .height(64.dp)
            .clip(shape)
            .background(Color(0xFF0B0D13))
            .border(1.dp, Zl.Border, shape)
            .padding(4.dp),
    ) {
        val segment = maxWidth / 3
        val offset by animateDpAsState(segment * (mode.number - 1), tween(380, easing = FastOutSlowInEasing), label = "offset")
        Box(
            Modifier
                .offset(x = offset)
                .width(segment)
                .fillMaxHeight()
                .clip(RoundedCornerShape(12.dp))
                .background(accent.copy(alpha = 0.14f))
                .border(1.dp, accent.copy(alpha = 0.6f), RoundedCornerShape(12.dp)),
        )
        Row(Modifier.fillMaxWidth().fillMaxHeight()) {
            ProtectionMode.entries.forEach { m ->
                val selected = m == mode
                Column(
                    Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .clip(RoundedCornerShape(12.dp))
                        .clickable { onSelect(m) },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        "0${m.number} //",
                        style = Zl.mono.copy(fontSize = 11.sp, fontWeight = FontWeight.Bold, color = if (selected) accent else Zl.TextMuted),
                    )
                    Text(
                        m.short,
                        style = Zl.mono.copy(fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = if (selected) Zl.TextPrimary else Zl.TextSecondary),
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

/** Bento metric tile. */
@Composable
fun MetricTile(
    title: String,
    value: String,
    unit: String,
    caption: String,
    secondary: String,
    accent: Color,
    modifier: Modifier = Modifier,
) {
    GlassCard(modifier, accent = accent, padding = 14.dp) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(accent))
            Spacer(Modifier.width(8.dp))
            Overline(title, Modifier.weight(1f))
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.Bottom) {
            Text(value, style = Zl.metric.copy(fontSize = 22.sp), maxLines = 1)
            Spacer(Modifier.width(6.dp))
            Text(unit, style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.TextMuted), modifier = Modifier.padding(bottom = 3.dp))
        }
        Spacer(Modifier.height(10.dp))
        Box(Modifier.fillMaxWidth().height(1.dp).background(Zl.Border))
        Spacer(Modifier.height(8.dp))
        Row {
            Text(caption, fontSize = 11.sp, color = Zl.TextMuted, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(secondary, style = Zl.mono.copy(fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = accent))
        }
    }
}

@Composable
fun Badge(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.14f))
            .border(1.dp, color.copy(alpha = 0.45f), RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(text, style = Zl.mono.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold, color = color), maxLines = 1)
    }
}

fun verdictColor(v: Verdict) = when (v) {
    Verdict.BLOCKED -> Zl.Crimson
    Verdict.ALLOWED -> Zl.Mint
    Verdict.PROMPT -> Zl.Violet
}

@Composable
fun ZlSwitch(checked: Boolean, onChange: (Boolean) -> Unit, color: Color = Zl.Mint, enabled: Boolean = true) {
    val view = androidx.compose.ui.platform.LocalView.current
    Switch(
        checked = checked,
        onCheckedChange = { v ->
            view.performHapticFeedback(
                if (android.os.Build.VERSION.SDK_INT >= 34) android.view.HapticFeedbackConstants.TOGGLE_ON.takeIf { v } ?: android.view.HapticFeedbackConstants.TOGGLE_OFF
                else android.view.HapticFeedbackConstants.VIRTUAL_KEY,
            )
            onChange(v)
        },
        enabled = enabled,
        colors = SwitchDefaults.colors(
            checkedThumbColor = Zl.Canvas,
            checkedTrackColor = color,
            checkedBorderColor = color,
            uncheckedThumbColor = Zl.TextSecondary,
            uncheckedTrackColor = Color(0xFF1A1F2C),
            uncheckedBorderColor = Zl.BorderStrong,
        ),
    )
}

/** Small selectable chip (filters, resolver choice…). */
@Composable
fun Chip(text: String, selected: Boolean, accent: Color, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(10.dp)
    Box(
        modifier
            .clip(shape)
            .background(if (selected) accent.copy(alpha = 0.15f) else Color.Transparent)
            .border(1.dp, if (selected) accent else Zl.Border, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = if (selected) accent else Zl.TextSecondary)
    }
}

fun formatCount(n: Long): String = when {
    n >= 1_000_000 -> String.format("%.1fM", n / 1_000_000.0)
    n >= 10_000 -> String.format("%.1fK", n / 1_000.0)
    else -> String.format("%,d", n)
}


/**
 * A clock that ticks every [periodMs] only while the app is on screen (STARTED); it stops completely in the
 * background, so screens that show live time or status don't wake the phone when you're not looking.
 */
@Composable
fun rememberVisibleTicker(periodMs: Long, enabled: Boolean = true): Long {
    val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
    val now = androidx.compose.runtime.remember { androidx.compose.runtime.mutableLongStateOf(System.currentTimeMillis()) }
    androidx.compose.runtime.LaunchedEffect(lifecycle, periodMs, enabled) {
        if (!enabled) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
            while (true) {
                now.longValue = System.currentTimeMillis()
                kotlinx.coroutines.delay(periodMs)
            }
        }
    }
    return now.longValue
}
