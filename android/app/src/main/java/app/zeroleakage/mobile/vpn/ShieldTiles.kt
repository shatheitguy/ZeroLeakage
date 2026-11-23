package app.zeroleakage.mobile.vpn

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.zeroleakage.mobile.MainActivity
import app.zeroleakage.mobile.R
import app.zeroleakage.mobile.data.ProtectionMode
import app.zeroleakage.mobile.data.ZeroLeakage

/**
 * Quick Settings ("control centre") tiles:
 *  - "ZeroLeakage": shield on / off in one tap.
 *  - "ZL mode": cycles Balanced → Strict Guard → Total Zero-Leak.
 * Add them from the Quick Settings edit (pencil) screen.
 */
class ShieldTileService : TileService() {

    override fun onStartListening() = refresh()

    override fun onClick() {
        val running = ZeroLeakage.vpnRunning.value
        when {
            ZeroLeakage.method.value == ZeroLeakage.Method.LITE -> openApp(resume = false)   // Lite runs through Private DNS
            running -> ZeroLeakVpnService.stop(this)
            VpnService.prepare(this) == null -> {
                // Consent already given: start straight from the tile.
                if (runCatching { ZeroLeakVpnService.start(this) }.isFailure) openApp(resume = true)
            }
            else -> openApp(resume = true)   // Android needs the VPN consent dialog once
        }
        refresh(optimisticRunning = !running)
    }

    private fun refresh(optimisticRunning: Boolean? = null) {
        val tile = qsTile ?: return
        val lite = ZeroLeakage.method.value == ZeroLeakage.Method.LITE
        val on = optimisticRunning ?: ZeroLeakage.vpnRunning.value
        tile.icon = Icon.createWithResource(this, R.drawable.ic_stat_shield)
        tile.label = "ZeroLeakage"
        tile.state = if (lite || on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.subtitle = when {
            lite -> "Lite · Private DNS"
            on -> "On · ${ZeroLeakage.mode.value.title}"
            else -> "Off"
        }
        tile.updateTile()
    }

    private fun openApp(resume: Boolean) = launchApp(this, resume)

    companion object {
        /** Asks Android to redraw both tiles (call when the shield or mode changes). */
        fun refreshAll(context: Context) {
            runCatching { requestListeningState(context, ComponentName(context, ShieldTileService::class.java)) }
            runCatching { requestListeningState(context, ComponentName(context, ModeTileService::class.java)) }
        }
    }
}

class ModeTileService : TileService() {

    override fun onStartListening() = refresh()

    override fun onClick() {
        val next = when (ZeroLeakage.mode.value) {
            ProtectionMode.BALANCED -> ProtectionMode.STRICT
            ProtectionMode.STRICT -> ProtectionMode.LOCKDOWN
            ProtectionMode.LOCKDOWN -> ProtectionMode.BALANCED
        }
        ZeroLeakage.setMode(next)
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val mode = ZeroLeakage.mode.value
        tile.icon = Icon.createWithResource(this, R.drawable.ic_stat_shield)
        tile.label = "ZL mode"
        tile.subtitle = "${mode.number} · ${mode.title}"
        tile.state = if (mode == ProtectionMode.BALANCED) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        tile.updateTile()
    }
}

private fun TileService.launchAppInternal(intent: Intent) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        startActivityAndCollapse(PendingIntent.getActivity(this, 11, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
    } else {
        @Suppress("DEPRECATION")
        startActivityAndCollapse(intent)
    }
}

private fun launchApp(service: TileService, resume: Boolean) {
    val intent = Intent(service, MainActivity::class.java)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        .putExtra(OtherVpnWatcher.EXTRA_RESUME, resume)
    service.launchAppInternal(intent)
}
