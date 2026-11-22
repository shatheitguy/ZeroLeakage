package app.zeroleakage.mobile.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import app.zeroleakage.mobile.MainActivity
import app.zeroleakage.mobile.R
import app.zeroleakage.mobile.data.ProtectionMode
import app.zeroleakage.mobile.data.Verdict
import app.zeroleakage.mobile.data.ZeroLeakage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Local, on-device "DNS firewall" VPN.
 *
 * Only our virtual DNS server (10.111.222.2) is routed into the tunnel, so ordinary app traffic never
 * passes through it. Every DNS lookup is attributed to the app that made it
 * (ConnectivityManager.getConnectionOwnerUid), checked against blocklists + per-app rules for the
 * active mode, and then either answered NXDOMAIN or forwarded over encrypted DNS-over-HTTPS.
 * Nothing leaves the phone except the encrypted DoH request.
 */
class ZeroLeakVpnService : VpnService() {

    companion object {
        private const val TAG = "ZeroLeakVpn"
        const val ACTION_START = "app.zeroleakage.mobile.START"
        const val ACTION_STOP = "app.zeroleakage.mobile.STOP"
        private const val VPN_ADDRESS = "10.111.222.1"
        private const val DNS_ADDRESS = "10.111.222.2"
        private const val CHANNEL_SHIELD = "shield"
        const val CHANNEL_PROMPT = "ask_to_connect"
        private const val NOTIF_ID = 1

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, ZeroLeakVpnService::class.java).setAction(ACTION_START))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, ZeroLeakVpnService::class.java).setAction(ACTION_STOP))
        }

        fun ensureChannels(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL_SHIELD, "Shield status", NotificationManager.IMPORTANCE_LOW))
            nm.createNotificationChannel(NotificationChannel(CHANNEL_PROMPT, "Ask to connect", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Strict Guard asks before an unapproved app can use the network"
            })
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    @Volatile private var running = false
    private var scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val doh = DohClient()
    private val labels = ConcurrentHashMap<Int, Pair<String?, String>>()   // uid -> (package, label)
    private lateinit var connectivity: ConnectivityManager
    @Volatile private var onWifiCache = true
    @Volatile private var onWifiCheckedAt = 0L

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        ensureChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        startInForeground()
        if (!running) establish()
        return START_STICKY
    }

    private fun startInForeground() {
        val n = buildStatusNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun establish() {
        val builder = Builder()
            .setSession("ZeroLeakage")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            .addRoute(DNS_ADDRESS, 32)
            .setMtu(1500)
            .setBlocking(true)
            .setConfigureIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
        builder.setMetered(false)
        runCatching { builder.addDisallowedApplication(packageName) }   // our own DoH traffic bypasses the tunnel

        val fd = builder.establish()
        if (fd == null) {
            Log.w(TAG, "VPN permission revoked or not granted")
            ZeroLeakage.setVpnRunning(false)
            stopSelf()
            return
        }
        tun = fd
        running = true
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        ZeroLeakage.setVpnRunning(true)

        // Changing resolver or mode invalidates cached answers / temporary allowances.
        scope.launch {
            combine(ZeroLeakage.resolverId, ZeroLeakage.mode) { r, m -> r to m }.drop(1).collect {
                doh.clear()
                refreshNotification()
            }
        }

        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        reader = Thread({
            val buf = ByteArray(32_767)
            while (running) {
                val n = try { input.read(buf) } catch (e: Exception) { if (running) Log.w(TAG, "read", e); break }
                if (n <= 0) continue
                val q = DnsPacket.parse(buf, n) ?: continue
                scope.launch { handle(q, output) }
            }
        }, "zl-tun-reader").apply { start() }
    }

    private fun handle(q: DnsQuery, out: FileOutputStream) {
        val (pkg, label, uid) = attribute(q)
        val isSystem = uid in 0 until Process.FIRST_APPLICATION_UID
        val decision = decide(q.name, pkg, isSystem)

        if (decision.prompt && pkg != null && ZeroLeakage.pendingPrompts.add(pkg)) {
            PromptNotifier.show(this, pkg, label, q.name)
        }

        val response: ByteArray = if (decision.verdict != Verdict.ALLOWED) {
            DnsPacket.errorResponse(q, rcode = 3)
        } else {
            doh.cached(q)?.let { DnsPacket.withId(it, q.id) } ?: try {
                val (bytes, latency) = doh.resolve(ZeroLeakage.resolver().url, q)
                ZeroLeakage.recordLatency(latency)
                bytes
            } catch (e: Exception) {
                Log.w(TAG, "DoH failed for ${q.name}: ${e.message}")
                DnsPacket.errorResponse(q, rcode = 2)
            }
        }

        val packet = DnsPacket.buildIpPacket(q, response)
        synchronized(out) {
            try { out.write(packet) } catch (e: Exception) { if (running) Log.w(TAG, "write", e) }
        }
        ZeroLeakage.record(decision.verdict, label, pkg, q.name, decision.category)
    }

    private data class Decision(val verdict: Verdict, val category: String, val prompt: Boolean = false)

    private fun decide(domain: String, pkg: String?, isSystem: Boolean): Decision {
        ZeroLeakage.matchBlocklist(domain)?.let { return Decision(Verdict.BLOCKED, it) }

        val mode = ZeroLeakage.mode.value
        if (pkg != null) {
            val rule = ZeroLeakage.rule(pkg)
            val allowedOnNetwork = if (onWifi()) rule.wifi else rule.mobile
            if (!allowedOnNetwork) return Decision(Verdict.BLOCKED, "App Network Killed")
            when (mode) {
                ProtectionMode.LOCKDOWN ->
                    if (!rule.pinned) return Decision(Verdict.BLOCKED, "Total Lockdown")
                ProtectionMode.STRICT ->
                    if (!isSystem && !rule.approved && pkg !in ZeroLeakage.allowedOnce)
                        return Decision(Verdict.PROMPT, "Ask to Connect", prompt = true)
                ProtectionMode.BALANCED -> Unit
            }
        } else if (mode == ProtectionMode.LOCKDOWN) {
            return Decision(Verdict.BLOCKED, "Total Lockdown")
        }
        return Decision(Verdict.ALLOWED, if (mode == ProtectionMode.BALANCED) "Encrypted DoH" else "Approved · DoH")
    }

    private data class Owner(val pkg: String?, val label: String, val uid: Int)

    private fun attribute(q: DnsQuery): Owner {
        val uid = try {
            connectivity.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(q.srcIp), q.srcPort),
                InetSocketAddress(InetAddress.getByAddress(q.dstIp), q.dstPort),
            )
        } catch (e: Exception) {
            Process.INVALID_UID
        }
        if (uid == Process.INVALID_UID) return Owner(null, "unknown", uid)
        val (pkg, label) = labels.getOrPut(uid) { lookupLabel(uid) }
        return Owner(pkg, label, uid)
    }

    private fun lookupLabel(uid: Int): Pair<String?, String> {
        val pm = packageManager
        val pkgs = pm.getPackagesForUid(uid)
        if (pkgs.isNullOrEmpty()) return null to (if (uid < Process.FIRST_APPLICATION_UID) "Android system" else "uid $uid")
        val pkg = pkgs.first()
        val label = try {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            pkg
        }
        return pkg to (if (pkgs.size > 1 && uid < Process.FIRST_APPLICATION_UID) "Android system" else label)
    }

    private fun onWifi(): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (now - onWifiCheckedAt > 2_000) {
            onWifiCache = connectivity.activeNetwork?.let { connectivity.getNetworkCapabilities(it) }
                ?.let { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) }
                ?: true
            onWifiCheckedAt = now
        }
        return onWifiCache
    }

    private fun buildStatusNotification(): Notification {
        val mode = ZeroLeakage.mode.value
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, ZeroLeakVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_SHIELD)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("Zero bits leaked")
            .setContentText("Mode ${mode.number}: ${mode.title} · encrypted DNS active")
            .setColor(0xFF00F5A0.toInt())
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Stop shield", stop)
            .build()
    }

    private fun refreshNotification() {
        if (running) getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildStatusNotification())
    }

    private fun shutdown() {
        running = false
        scope.cancel()
        runCatching { tun?.close() }
        tun = null
        reader?.interrupt()
        reader = null
        ZeroLeakage.setVpnRunning(false)
        ZeroLeakage.pendingPrompts.clear()
        ZeroLeakage.persistStats()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        shutdown()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (running) shutdown()
        super.onDestroy()
    }
}
