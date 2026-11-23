package app.zeroleakage.mobile.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.Canvas
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.Updates
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.components.drawShieldMark
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.math.cos
import kotlin.math.sin

/** Full-screen in-app update: check → download → verify → install, with the animated update orb. */
@Composable
fun UpdateScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by Updates.state.collectAsStateWithLifecycle()
    val install by Updates.install.collectAsStateWithLifecycle()
    var job by remember { mutableStateOf<Job?>(null) }
    val release = (state as? Updates.State.Available)?.release

    fun start() {
        val r = release ?: return
        job = scope.launch { Updates.downloadAndInstall(context, r) }
    }

    Column(Modifier.fillMaxSize().background(Zl.Canvas).statusBarsPadding().navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(44.dp).clip(CircleShape).clickable { job?.cancel(); Updates.resetInstall(); onClose() }, contentAlignment = Alignment.Center) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Zl.TextPrimary)
            }
            Text("Update ZeroLeakage", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
        }

        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            UpdateOrb(install, Modifier.size(260.dp))

            // Headline under the orb
            val (title, sub) = when (val i = install) {
                is Updates.Install.Downloading -> "${(i.fraction * 100).toInt()}%" to
                    "${mb(i.done)} of ${mb(i.total)} · ${mb(i.bytesPerSec)}/s"
                is Updates.Install.Verifying -> "Verifying" to "Making sure this is the genuine ZeroLeakage"
                Updates.Install.Installing -> "Installing" to "Confirm in Android's dialog. ZeroLeakage restarts on the new version."
                Updates.Install.NeedsPermission -> "One-time permission" to "Allow ZeroLeakage to install its own updates, then tap Continue."
                is Updates.Install.Failed -> "Update stopped" to i.message
                Updates.Install.Idle -> when (state) {
                    is Updates.State.Available -> "Version ${release?.version} is ready" to "You have ${Updates.currentVersion(context)}"
                    Updates.State.Checking -> "Checking…" to "Asking GitHub for the latest release"
                    is Updates.State.UpToDate -> "You're up to date" to "Version ${Updates.currentVersion(context)}"
                    is Updates.State.Failed -> "Couldn't check" to (state as Updates.State.Failed).message
                    Updates.State.Idle -> "Check for updates" to "Version ${Updates.currentVersion(context)}"
                }
            }
            Text(title, style = Zl.mono.copy(fontSize = 30.sp, fontWeight = FontWeight.Bold,
                color = if (install is Updates.Install.Failed) Zl.Crimson else Zl.TextPrimary))
            Text(sub, fontSize = 13.sp, color = Zl.TextSecondary, textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.fillMaxWidth())

            // Verification checklist
            val step = (install as? Updates.Install.Verifying)?.step ?: if (install == Updates.Install.Installing) 5 else -1
            if (step >= 0) {
                GlassCard(Modifier.fillMaxWidth()) {
                    Overline("Security checks", color = Zl.TextPrimary)
                    Spacer(Modifier.height(8.dp))
                    listOf(
                        if (release?.apkSha256 != null) "Matches the SHA-256 GitHub published" else "Download complete (no published hash)",
                        "Same app: ${context.packageName}",
                        "Newer than ${Updates.currentVersion(context)}",
                        "Signed with ZeroLeakage's own key",
                    ).forEachIndexed { i, label -> CheckRow(label, done = step > i, active = step == i) }
                }
            }

            // Actions
            when (install) {
                Updates.Install.Idle, is Updates.Install.Failed -> when {
                    release != null -> Button(
                        onClick = ::start, modifier = Modifier.fillMaxWidth().height(50.dp), shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Zl.Mint, contentColor = Zl.Canvas),
                    ) { Text(if (install is Updates.Install.Failed) "Try again" else "Download & install ${release.version}", fontWeight = FontWeight.Bold) }
                    state !is Updates.State.Checking -> SmallAction("Check again", Zl.Mint) { scope.launch { Updates.check(context, force = true) } }
                }
                Updates.Install.NeedsPermission -> Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Allow installs", Zl.Mint) { Updates.openInstallPermission(context) }
                    SmallAction("Continue", Zl.Violet) { if (Updates.canInstall(context)) start() else Updates.openInstallPermission(context) }
                }
                is Updates.Install.Downloading -> SmallAction("Cancel", Zl.TextSecondary) { job?.cancel(); Updates.resetInstall() }
                else -> Unit
            }

            release?.notes?.takeIf { it.isNotBlank() }?.let { notes ->
                GlassCard(Modifier.fillMaxWidth()) {
                    Overline("What's new in ${release.version}", color = Zl.TextPrimary)
                    Spacer(Modifier.height(8.dp))
                    Text(notes.replace("**", "").replace("### ", "").replace("## ", "").take(1500),
                        fontSize = 12.sp, color = Zl.TextSecondary, lineHeight = 17.sp)
                }
            }
        }
    }
}

private fun mb(bytes: Long) = if (bytes >= 1_048_576) "%.1f MB".format(java.util.Locale.US, bytes / 1_048_576.0) else "${bytes / 1024} KB"

@Composable
private fun CheckRow(label: String, done: Boolean, active: Boolean) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(20.dp).clip(CircleShape)
                .background(if (done) Zl.Mint.copy(alpha = 0.18f) else Zl.Inset)
                .border(1.5.dp, if (done) Zl.Mint else if (active) Zl.Violet else Zl.BorderStrong, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            androidx.compose.animation.AnimatedVisibility(done, enter = scaleIn(spring(dampingRatio = 0.45f)) + fadeIn()) {
                Text("✓", color = Zl.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
        Spacer(Modifier.width(10.dp))
        Text(label, fontSize = 13.sp, color = if (done) Zl.TextPrimary else if (active) Zl.Violet else Zl.TextMuted)
    }
}

/**
 * The update orb: orbiting particles, a gradient progress ring with a glowing head, and the ZeroLeakage
 * shield filling up as the download progresses. While verifying, a scan beam sweeps the shield; while
 * installing, the ring spins.
 */
@Composable
fun UpdateOrb(install: Updates.Install, modifier: Modifier = Modifier) {
    val loop = rememberInfiniteTransition(label = "orb")
    val spin by loop.animateFloat(0f, 360f, infiniteRepeatable(tween(2600, easing = LinearEasing)), label = "spin")
    val orbit by loop.animateFloat(0f, 360f, infiniteRepeatable(tween(9000, easing = LinearEasing)), label = "orbit")
    val pulse by loop.animateFloat(0f, 1f, infiniteRepeatable(tween(1400), RepeatMode.Restart), label = "pulse")
    val scan by loop.animateFloat(0f, 1f, infiniteRepeatable(tween(1100), RepeatMode.Reverse), label = "scan")

    val target = when (install) {
        is Updates.Install.Downloading -> install.fraction
        is Updates.Install.Verifying, Updates.Install.Installing -> 1f
        else -> 0f
    }
    val progress by animateFloatAsState(target, tween(350), label = "progress")
    val failed = install is Updates.Install.Failed
    val busy = install is Updates.Install.Downloading || install is Updates.Install.Verifying || install == Updates.Install.Installing
    val accent = if (failed) Zl.Crimson else Zl.Mint

    Canvas(modifier) {
        val c = center
        val r = size.minDimension / 2f
        val ringR = r * 0.78f
        val stroke = r * 0.055f

        // soft glow
        drawCircle(Brush.radialGradient(listOf(accent.copy(alpha = if (busy) 0.22f else 0.10f), Color.Transparent), c, r), r)

        // orbiting particles
        repeat(10) { i ->
            val a = Math.toRadians((orbit * (if (i % 2 == 0) 1f else -0.7f) + i * 36f).toDouble())
            val pr = r * (0.88f + 0.08f * ((i % 3) / 2f))
            val p = Offset(c.x + cos(a).toFloat() * pr, c.y + sin(a).toFloat() * pr)
            drawCircle((if (i % 3 == 0) Zl.Violet else accent).copy(alpha = if (busy) 0.85f else 0.35f), radius = r * (0.012f + (i % 3) * 0.006f), center = p)
        }

        // pulse ring while busy
        if (busy) drawCircle(accent.copy(alpha = 0.35f * (1f - pulse)), ringR + r * 0.14f * pulse, c, style = Stroke(r * 0.012f))

        // track + progress arc
        val arcTopLeft = Offset(c.x - ringR, c.y - ringR)
        val arcSize = Size(ringR * 2, ringR * 2)
        drawCircle(Zl.Border, ringR, c, style = Stroke(stroke))
        if (install == Updates.Install.Installing) {
            rotate(spin, c) {
                drawArc(Brush.sweepGradient(listOf(Color.Transparent, Zl.Violet, accent), c), 0f, 300f, false, arcTopLeft, arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
            }
        } else if (progress > 0f) {
            rotate(-90f, c) {
                drawArc(Brush.sweepGradient(listOf(Zl.Violet, accent, Zl.Violet), c), 0f, 360f * progress, false, arcTopLeft, arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
            }
            // glowing head
            val ha = Math.toRadians((360.0 * progress) - 90.0)
            val head = Offset(c.x + cos(ha).toFloat() * ringR, c.y + sin(ha).toFloat() * ringR)
            drawCircle(accent.copy(alpha = 0.35f), stroke * 1.6f, head)
            drawCircle(Color.White, stroke * 0.45f, head)
        }

        // shield: faint outline, then mint fill rising with progress
        val grid = ringR * 1.55f
        val tl = Offset(c.x - grid / 2f, c.y - grid / 2f)
        drawShieldMark(Zl.TextMuted.copy(alpha = 0.25f), grid, tl)
        val fill = if (install is Updates.Install.Verifying || install == Updates.Install.Installing) 1f else progress
        val shieldTop = tl.y + grid * 16f / 96f
        val shieldBottom = tl.y + grid * 80f / 96f
        val cut = shieldBottom - (shieldBottom - shieldTop) * fill
        clipRect(top = cut) { drawShieldMark(accent, grid, tl) }

        // verification scan beam
        if (install is Updates.Install.Verifying) {
            val y = shieldTop + (shieldBottom - shieldTop) * scan
            drawLine(Brush.horizontalGradient(listOf(Color.Transparent, Color.White.copy(alpha = 0.9f), Color.Transparent), tl.x, tl.x + grid),
                Offset(tl.x + grid * 0.2f, y), Offset(tl.x + grid * 0.8f, y), strokeWidth = r * 0.02f)
        }
    }
}
