package app.zeroleakage.mobile.data

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings

/**
 * Lite mode: no VPN at all. Android's built-in "Private DNS" (DNS-over-TLS) is pointed at a filtering
 * resolver, which blocks ads / trackers / malware for every app on the phone, even when ZeroLeakage
 * isn't running. Trade-off: no per-app firewall, no Strict Guard prompts and no live feed.
 *
 * Android does not let normal apps change Private DNS. ZeroLeakage either:
 *  - switches it for you, if you granted WRITE_SECURE_SETTINGS once over USB (adb), or
 *  - copies the hostname and opens the Private DNS screen so you can paste it.
 */
object PrivateDns {

    data class Provider(val id: String, val name: String, val host: String, val note: String)

    val PROVIDERS = listOf(
        Provider("adguard", "AdGuard DNS", "dns.adguard-dns.com", "Blocks ads, trackers and phishing"),
        Provider("adguard_family", "AdGuard Family", "family.adguard-dns.com", "Ads + trackers + adult content, safe search"),
        Provider("mullvad_adblock", "Mullvad ad-block", "adblock.dns.mullvad.net", "No-log · blocks ads and trackers"),
        Provider("cf_security", "Cloudflare Security", "security.cloudflare-dns.com", "Blocks malware · very fast"),
        Provider("cf_family", "Cloudflare Family", "family.cloudflare-dns.com", "Malware + adult content"),
        Provider("quad9", "Quad9", "dns.quad9.net", "Blocks malware · Swiss non-profit"),
    )

    const val ADB_GRANT = "adb shell pm grant app.zeroleakage.mobile android.permission.WRITE_SECURE_SETTINGS"

    data class Status(val active: Boolean, val host: String?, val mode: String?) {
        /** True when Private DNS is set to a specific host (strict mode), which also bypasses the VPN's DNS. */
        val isHostname: Boolean get() = mode == "hostname" && !host.isNullOrBlank()
    }

    fun status(context: Context): Status {
        val cr = context.contentResolver
        val mode = runCatching { Settings.Global.getString(cr, "private_dns_mode") }.getOrNull()
        val specifier = runCatching { Settings.Global.getString(cr, "private_dns_specifier") }.getOrNull()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        val lp = cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } == true
        }?.let { cm.getLinkProperties(it) }
        val active = lp?.isPrivateDnsActive == true
        val host = lp?.privateDnsServerName ?: specifier.takeIf { mode == "hostname" }
        return Status(active, host, mode)
    }

    fun canSwitchAutomatically(context: Context): Boolean =
        context.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) == PackageManager.PERMISSION_GRANTED

    /** Sets Private DNS to [host]. Returns false when the one-time adb grant is missing. */
    fun apply(context: Context, host: String): Boolean {
        if (!canSwitchAutomatically(context)) return false
        return runCatching {
            val cr = context.contentResolver
            Settings.Global.putString(cr, "private_dns_specifier", host)
            Settings.Global.putString(cr, "private_dns_mode", "hostname")
        }.getOrDefault(false)
    }

    /** Back to Android's default ("Automatic"), so the full shield's on-device filter sees every lookup. */
    fun reset(context: Context): Boolean {
        if (!canSwitchAutomatically(context)) return false
        return runCatching { Settings.Global.putString(context.contentResolver, "private_dns_mode", "opportunistic") }.getOrDefault(false)
    }

    fun copyHost(context: Context, host: String) {
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Private DNS", host))
    }

    fun copyAdbCommand(context: Context) {
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("adb", ADB_GRANT))
    }

    /** Private DNS lives under Network & internet (Connections → More connection settings on Samsung). */
    fun openSettings(context: Context) {
        val intents = listOf(
            Intent("android.settings.PRIVATE_DNS_SETTINGS"),
            Intent(Settings.ACTION_WIRELESS_SETTINGS),
            Intent(Settings.ACTION_SETTINGS),
        )
        for (i in intents) {
            if (runCatching { context.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }.isSuccess) return
        }
    }
}
