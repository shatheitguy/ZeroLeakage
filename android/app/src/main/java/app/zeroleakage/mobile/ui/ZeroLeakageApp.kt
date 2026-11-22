package app.zeroleakage.mobile.ui

import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.zeroleakage.mobile.data.Updates
import app.zeroleakage.mobile.ui.screens.AboutScreen
import app.zeroleakage.mobile.ui.screens.AccountDestination
import app.zeroleakage.mobile.ui.screens.AccountSheet
import app.zeroleakage.mobile.ui.screens.PrivacyXrayScreen
import app.zeroleakage.mobile.ui.screens.ProfileButton
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import kotlinx.coroutines.launch
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.rememberShieldController
import app.zeroleakage.mobile.ui.components.BrandMark
import app.zeroleakage.mobile.ui.screens.DashboardScreen
import app.zeroleakage.mobile.ui.screens.DnsScreen
import app.zeroleakage.mobile.ui.screens.FirewallScreen
import app.zeroleakage.mobile.ui.screens.OnboardingScreen
import app.zeroleakage.mobile.ui.screens.SettingsScreen
import app.zeroleakage.mobile.ui.theme.Zl

private enum class Tab(val title: String, val icon: ImageVector) {
    DASHBOARD("Shield", Icons.Filled.Home),
    FIREWALL("Firewall", Icons.Filled.Lock),
    DNS("DNS", Icons.AutoMirrored.Filled.List),
    SETTINGS("Settings", Icons.Filled.Settings),
}

@Composable
fun ZeroLeakageApp() {
    val onboarded by ZeroLeakage.onboarded.collectAsStateWithLifecycle()
    val shield = rememberShieldController()

    if (!onboarded) {
        OnboardingScreen(
            onEnable = { shield.start(); ZeroLeakage.setOnboarded() },
            onSkip = { ZeroLeakage.setOnboarded() },
        )
        return
    }

    var tab by rememberSaveable { mutableStateOf(Tab.DASHBOARD) }
    val mode by ZeroLeakage.mode.collectAsStateWithLifecycle()
    val running by ZeroLeakage.vpnRunning.collectAsStateWithLifecycle()
    val accent by animateColorAsState(Zl.accent(mode), tween(450), label = "accent")

    val context = LocalContext.current
    var showAccount by remember { mutableStateOf(false) }
    var overlay by rememberSaveable { mutableStateOf<AccountDestination?>(null) }
    LaunchedEffect(Unit) { Updates.check(context) }      // at most once a day

    // Confirmations ("Chrome allowed") from anywhere in the app, including notification actions.
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        ZeroLeakage.messages.collect { msg ->
            launch {
                snackbar.currentSnackbarData?.dismiss()
                snackbar.showSnackbar(msg, duration = SnackbarDuration.Short)
            }
        }
    }

    Scaffold(
        containerColor = Zl.Canvas,
        snackbarHost = {
            SnackbarHost(snackbar) { data ->
                Snackbar(
                    snackbarData = data,
                    containerColor = Zl.SurfaceRaised,
                    contentColor = Zl.TextPrimary,
                    shape = RoundedCornerShape(12.dp),
                )
            }
        },
        topBar = { TopBar(accent, running, "MODE ${mode.number}: ${mode.short}") { showAccount = true } },
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF0B0C12), tonalElevation = 0.dp) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = t.title) },
                        label = { Text(t.title, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = accent,
                            selectedTextColor = accent,
                            indicatorColor = accent.copy(alpha = 0.14f),
                            unselectedIconColor = Zl.TextMuted,
                            unselectedTextColor = Zl.TextMuted,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
            AnimatedContent(
                targetState = tab,
                transitionSpec = { fadeIn(tween(220)) togetherWith fadeOut(tween(150)) },
                label = "tabs",
            ) { current ->
                when (current) {
                    Tab.DASHBOARD -> DashboardScreen(shield)
                    Tab.FIREWALL -> FirewallScreen()
                    Tab.DNS -> DnsScreen()
                    Tab.SETTINGS -> SettingsScreen(shield)
                }
            }
        }
    }

    if (showAccount) {
        AccountSheet(onDismiss = { showAccount = false }) { dest ->
            showAccount = false
            if (dest == AccountDestination.SETTINGS) tab = Tab.SETTINGS else overlay = dest
        }
    }
    overlay?.let { dest ->
        Dialog(
            onDismissRequest = { overlay = null },
            properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false),
        ) {
            Box(Modifier.fillMaxSize().background(Zl.Canvas)) {
                when (dest) {
                    AccountDestination.ABOUT -> AboutScreen(onClose = { overlay = null })
                    AccountDestination.XRAY -> PrivacyXrayScreen(onClose = { overlay = null })
                    AccountDestination.SETTINGS -> Unit
                }
            }
        }
    }
}

@Composable
private fun TopBar(accent: Color, running: Boolean, modeLabel: String, onProfile: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BrandMark(accent, Modifier.size(22.dp))
        Spacer(Modifier.width(8.dp))
        Text("Zero", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = Zl.TextPrimary)
        Text("Leakage", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = accent)
        Spacer(Modifier.weight(1f))
        // Live status pill
        Row(
            Modifier
                .clip(RoundedCornerShape(50))
                .background(Color(0xFF0F1219))
                .border(1.dp, accent.copy(alpha = 0.3f), RoundedCornerShape(50))
                .padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val dot = if (running) accent else Zl.Amber
            Box(Modifier.size(6.dp).clip(CircleShape).background(dot))
            Spacer(Modifier.width(6.dp))
            Text(
                if (running) "ZERO BITS LEAKED" else "SHIELD OFF",
                style = Zl.mono.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold, color = dot),
            )
            Box(Modifier.padding(horizontal = 7.dp).width(1.dp).height(10.dp).background(Zl.BorderStrong))
            Text(modeLabel.substringBefore(":"), style = Zl.mono.copy(fontSize = 10.sp, color = Zl.TextSecondary))
        }
        Spacer(Modifier.width(10.dp))
        ProfileButton(accent, onProfile)
    }
}
