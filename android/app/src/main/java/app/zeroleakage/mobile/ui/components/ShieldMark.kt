package app.zeroleakage.mobile.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.PathMeasure
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * "Negative-space shield" brand mark: a shield with a slashed zero cut out.
 * Geometry lives on a 96-unit grid (same as the launcher icon and the Windows .ico).
 */
object ShieldMarkPaths {
    private const val SHIELD = "M48,16 L74,26 L74,48 C74,64 62,74 48,80 C34,74 22,64 22,48 L22,26 Z"
    private const val OUTER_ZERO = "M35,47 A13,18 0 1,0 61,47 A13,18 0 1,0 35,47 Z"
    private const val INNER_ZERO = "M41,47 A7,12 0 1,0 55,47 A7,12 0 1,0 41,47 Z"
    private const val CLIP_A = "M67.26,23.91 L91.53,41.55 L56.25,90.09 L31.98,72.45 Z"
    private const val CLIP_B = "M64.02,21.55 L28.74,70.09 L4.47,52.45 L39.75,3.91 Z"

    private fun parse(d: String): Path = PathParser().parsePathString(d).toPath()

    val outline: Path = parse(SHIELD)
    val shieldWithHole: Path = parse("$SHIELD $OUTER_ZERO").apply { fillType = PathFillType.EvenOdd }
    val innerZero: Path = parse(INNER_ZERO)
    val clipA: Path = parse(CLIP_A)
    val clipB: Path = parse(CLIP_B)
}

/** Draws the mark so that its 96-unit grid fills a [gridSize] square whose top-left is [topLeft]. */
fun DrawScope.drawShieldMark(color: Color, gridSize: Float, topLeft: Offset) {
    translate(topLeft.x, topLeft.y) {
        scale(gridSize / 96f, gridSize / 96f, pivot = Offset.Zero) {
            drawPath(ShieldMarkPaths.shieldWithHole, color)
            clipPath(ShieldMarkPaths.clipA) { drawPath(ShieldMarkPaths.innerZero, color) }
            clipPath(ShieldMarkPaths.clipB) { drawPath(ShieldMarkPaths.innerZero, color) }
        }
    }
}

/** Draws the mark centred on the current draw area, with the shield about [extent] tall. */
fun DrawScope.drawShieldMarkCentered(color: Color, extent: Float) {
    val grid = extent * 1.45f
    drawShieldMark(color, grid, Offset(center.x - grid / 2f, center.y - grid / 2f))
}

/**
 * Animated launch splash: the shield outline draws itself, the mark springs in,
 * sonar rings pulse out and a scanning bar runs while the app warms up.
 */
@Composable
fun SplashOverlay(onFinished: () -> Unit, modifier: Modifier = Modifier) {
    val finish by rememberUpdatedState(onFinished)
    val outline = remember { Animatable(0f) }
    val markScale = remember { Animatable(0.6f) }
    val markAlpha = remember { Animatable(0f) }
    val words = remember { Animatable(0f) }

    LaunchedEffect(Unit) {
        launch { outline.animateTo(1f, tween(650, delayMillis = 100, easing = CubicBezierEasing(0.65f, 0f, 0.35f, 1f))) }
        launch {
            delay(480)
            launch { markAlpha.animateTo(1f, tween(280)) }
            markScale.animateTo(1f, spring(dampingRatio = 0.55f, stiffness = Spring.StiffnessLow))
        }
        launch { delay(750); words.animateTo(1f, tween(380, easing = FastOutSlowInEasing)) }
        delay(1700)
        finish()
    }

    val loop = rememberInfiniteTransition(label = "splash")
    val ring by loop.animateFloat(0f, 1f, infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Restart), label = "ring")
    val glider by loop.animateFloat(0f, 1f, infiniteRepeatable(tween(1100, easing = FastOutSlowInEasing), RepeatMode.Restart), label = "glider")

    val measure = remember { PathMeasure().apply { setPath(ShieldMarkPaths.outline, false) } }
    val segment = remember { Path() }

    Box(modifier.fillMaxSize().background(Zl.Canvas), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
            Canvas(Modifier.size(200.dp)) {
                val maxR = size.minDimension / 2f
                if (markAlpha.value > 0f) {
                    for ((i, c) in listOf(Zl.Mint, Zl.Violet).withIndex()) {
                        val p = (ring + i * 0.5f) % 1f
                        drawCircle(c.copy(alpha = 0.55f * (1f - p) * markAlpha.value), maxR * (0.45f + 0.55f * p), style = Stroke(1.5.dp.toPx()))
                    }
                }
                val grid = maxR * 1.35f
                val topLeft = Offset(center.x - grid / 2f, center.y - grid / 2f)

                // Outline draw-on
                if (outline.value < 1f || markAlpha.value < 1f) {
                    segment.reset()
                    measure.getSegment(0f, measure.length * outline.value, segment, true)
                    translate(topLeft.x, topLeft.y) {
                        scale(grid / 96f, grid / 96f, pivot = Offset.Zero) {
                            drawPath(segment, Zl.Mint.copy(alpha = 1f - markAlpha.value),
                                style = Stroke(3f, cap = StrokeCap.Round, join = StrokeJoin.Round))
                        }
                    }
                }
                // Filled mark springs in
                scale(markScale.value, markScale.value, pivot = center) {
                    drawShieldMark(Zl.Mint.copy(alpha = markAlpha.value), grid, topLeft)
                }
            }
            Column(
                Modifier.graphicsLayer { alpha = words.value; translationY = (1f - words.value) * 10.dp.toPx() },
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    buildAnnotatedString {
                        withStyle(SpanStyle(fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)) { append("Zero") }
                        withStyle(SpanStyle(fontWeight = FontWeight.Normal, color = Zl.TextSecondary)) { append("Leakage") }
                    },
                    fontSize = 26.sp,
                )
                Spacer(Modifier.height(6.dp))
                Text("ARMING SHIELD · ZERO BITS LEAKED", style = Zl.mono.copy(fontSize = 10.5.sp, color = Zl.Mint, letterSpacing = 1.5.sp))
                Spacer(Modifier.height(22.dp))
                Box(Modifier.width(180.dp).height(3.dp).clip(RoundedCornerShape(2.dp)).background(Zl.Border)) {
                    Canvas(Modifier.fillMaxSize()) {
                        val w = 56.dp.toPx()
                        val x = -w + (size.width + w) * glider
                        drawRect(
                            Brush.horizontalGradient(listOf(Color.Transparent, Zl.Mint, Zl.Violet), startX = x, endX = x + w),
                            topLeft = Offset(x, 0f),
                            size = androidx.compose.ui.geometry.Size(w, size.height),
                        )
                    }
                }
            }
        }
    }
}
