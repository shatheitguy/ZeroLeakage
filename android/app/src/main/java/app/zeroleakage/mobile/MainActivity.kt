package app.zeroleakage.mobile

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import app.zeroleakage.mobile.ui.ZeroLeakageApp
import app.zeroleakage.mobile.ui.components.SplashOverlay
import app.zeroleakage.mobile.ui.theme.ZeroLeakageTheme
import app.zeroleakage.mobile.vpn.ZeroLeakVpnService

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(0xFF090A0F.toInt()),
            navigationBarStyle = SystemBarStyle.dark(0xFF090A0F.toInt()),
        )
        val coldStart = savedInstanceState == null
        setContent {
            ZeroLeakageTheme {
                var showSplash by rememberSaveable { mutableStateOf(coldStart) }
                Box(Modifier.fillMaxSize()) {
                    ZeroLeakageApp()
                    AnimatedVisibility(showSplash, enter = EnterTransition.None, exit = fadeOut(tween(320))) {
                        SplashOverlay(onFinished = { showSplash = false })
                    }
                }
            }
        }
    }
}

/** Starts/stops the VPN, asking for VPN consent and (Android 13+) notification permission first. */
class ShieldController(val start: () -> Unit, val stop: () -> Unit)

@Composable
fun rememberShieldController(): ShieldController {
    val context = LocalContext.current
    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) ZeroLeakVpnService.start(context)
    }
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    return remember(context) {
        ShieldController(
            start = {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                ) {
                    notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
                val consent = VpnService.prepare(context)
                if (consent != null) vpnConsent.launch(consent) else ZeroLeakVpnService.start(context)
            },
            stop = { ZeroLeakVpnService.stop(context) },
        )
    }
}
