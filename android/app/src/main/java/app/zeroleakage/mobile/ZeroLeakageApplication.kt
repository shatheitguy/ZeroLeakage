package app.zeroleakage.mobile

import android.app.Application
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.vpn.ZeroLeakVpnService

class ZeroLeakageApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ZeroLeakage.init(this)
        ZeroLeakVpnService.ensureChannels(this)
    }
}
