package app.zeroleakage.mobile

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.vpn.ZeroLeakVpnService

class ZeroLeakageApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ZeroLeakage.init(this)
        ZeroLeakVpnService.ensureChannels(this)
        app.zeroleakage.mobile.vpn.OtherVpnWatcher.register(this)
        // Keep the Quick Settings tiles in step with the shield and mode.
        CoroutineScope(SupervisorJob() + Dispatchers.Default).launch {
            combine(ZeroLeakage.vpnRunning, ZeroLeakage.mode, ZeroLeakage.method) { a, b, c -> Triple(a, b, c) }.collect {
                app.zeroleakage.mobile.vpn.ShieldTileService.refreshAll(this@ZeroLeakageApplication)
            }
        }
    }
}
