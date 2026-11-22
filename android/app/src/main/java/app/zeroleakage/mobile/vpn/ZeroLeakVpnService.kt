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
import app.zeroleakage.mobile.data.PacketDetail
import app.zeroleakage.mobile.data.ProtectionMode
import app.zeroleakage.mobile.data.Verdict
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.filters.FilterIndex
import app.zeroleakage.mobile.filters.FilterMatch
import app.zeroleakage.mobile.filters.Filters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import android.content.pm.ApplicationInfo
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
        /** How long a lookup waits for your Allow / Block tap before it is refused. */
        private const val PROMPT_HOLD_MS = 4_500L

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
    private val owners = ConcurrentHashMap<Int, AppInfo>()   // uid -> who owns it
    private lateinit var connectivity: ConnectivityManager
    private lateinit var upstream: Upstream
    @Volatile private var onWifiCache = true
    @Volatile private var onWifiCheckedAt = 0L

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        upstream = Upstream(doh, connectivity)
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
        Filters.autoUpdate()

        // Changing resolver or mode invalidates cached answers / temporary allowances.
        scope.launch {
            combine(ZeroLeakage.resolverId, ZeroLeakage.mode, ZeroLeakage.dnssec, ZeroLeakage.customResolverUrl) { r, m, d, c -> listOf(r, m, d, c) }.drop(1).collect {
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

    private suspend fun handle(q: DnsQuery, out: FileOutputStream) {
        val (pkg, label, uid, isCore) = attribute(q)
        var decision = decide(q.name, pkg, isCore)

        if (decision.prompt && pkg != null) {
            if (ZeroLeakage.pendingPrompts.add(pkg)) PromptNotifier.show(this, pkg, label, q.name)
            // Hold the lookup briefly: if you tap Allow in time, the app gets its answer right away
            // (no error page, no reload). DNS clients wait about 5 s per try, so stay under that.
            withTimeoutOrNull(PROMPT_HOLD_MS) { ZeroLeakage.decisionWaiter(pkg).await() }
            decision = decide(q.name, pkg, isCore)
        }

        val wantDnssec = ZeroLeakage.dnssec.value
        val resolver = ZeroLeakage.resolver()
        var verdict = decision.verdict
        var category = decision.category
        var cached = false
        var latency: Long? = null
        var error: String? = null
        var upstreamInfo: DnsResponseInfo? = null
        var usedResolver: Upstream.Answer? = null

        var response: ByteArray = if (decision.verdict != Verdict.ALLOWED) {
            DnsPacket.errorResponse(q, rcode = 3)
        } else {
            val hit = doh.cached(q)
            if (hit != null) {
                cached = true
                DnsPacket.withId(hit, q.id)
            } else try {
                val message = if (wantDnssec) DnsMessage.withAdBit(q.dns) else q.dns
                val answer = upstream.resolve(q, message)
                if (answer.encrypted) ZeroLeakage.recordLatency(answer.latencyMs)
                latency = answer.latencyMs
                usedResolver = answer
                if (!answer.encrypted) category = "Fallback - network DNS"
                else if (answer.failedOver) category = "Backup DoH - ${answer.resolverName}"
                answer.bytes
            } catch (e: Exception) {
                Log.w(TAG, "DoH failed for ${q.name}: ${e.message}")
                error = e.message ?: e.javaClass.simpleName
                DnsPacket.errorResponse(q, rcode = 2)
            }
        }

        var dnssec = DnssecStatus.NOT_CHECKED
        if (decision.verdict == Verdict.ALLOWED && error == null) {
            upstreamInfo = DnsMessage.parseResponse(response)
            dnssec = if (wantDnssec) DnsMessage.dnssecStatus(upstreamInfo) else DnssecStatus.OFF
            when {
                dnssec == DnssecStatus.BOGUS -> { verdict = Verdict.BLOCKED; category = "DNSSEC Failed" }
                dnssec == DnssecStatus.INSECURE && ZeroLeakage.dnssecStrict.value &&
                    upstreamInfo?.rcode == 0 && upstreamInfo.answers.isNotEmpty() -> {
                    verdict = Verdict.BLOCKED
                    category = "DNSSEC Unsigned"
                    response = DnsPacket.errorResponse(q, rcode = 2)
                }
            }
        }

        val packet = DnsPacket.buildIpPacket(q, response)
        synchronized(out) {
            try { out.write(packet) } catch (e: Exception) { if (running) Log.w(TAG, "write", e) }
        }

        // upstreamInfo describes what the resolver sent; re-parse only if we replaced the answer.
        val info = if (upstreamInfo != null && category != "DNSSEC Unsigned") upstreamInfo else DnsMessage.parseResponse(response)
        val detail = PacketDetail(
            uid = uid,
            network = networkName(),
            srcIp = ip(q.srcIp), srcPort = q.srcPort, dstIp = ip(q.dstIp), dstPort = q.dstPort,
            ipTtl = q.ipTtl, ipId = q.ipId, ipTotalLen = q.ipTotalLen, udpLen = q.udpLen, udpChecksum = q.udpChecksum,
            txId = q.id, qtype = q.qtype, qclass = q.qclass,
            queryFlags = DnsMessage.headerFlags(q.dns).toString(),
            queryEdns = DnsMessage.queryEdns(q.dns, q.questionEnd)?.let { "UDP ${it.udpSize} · v${it.version}" + if (it.dnssecOk) " · DO" else "" },
            querySize = q.dns.size,
            ruleList = decision.match?.listName, rule = decision.match?.rule, ruleMatched = decision.match?.matched,
            resolverName = if (decision.verdict == Verdict.ALLOWED) usedResolver?.resolverName ?: resolver.name else null,
            resolverUrl = if (decision.verdict == Verdict.ALLOWED) usedResolver?.resolverUrl ?: resolver.url else null,
            dnssecRequested = wantDnssec && decision.verdict == Verdict.ALLOWED && !cached,
            dnssec = dnssec,
            cached = cached,
            latencyMs = latency,
            error = error,
            rcode = info?.rcode ?: (response[3].toInt() and 0x0F),
            responseFlags = info?.flags?.toString() ?: "",
            responseSize = response.size,
            answers = info?.answers ?: emptyList(),
            authority = info?.authority ?: emptyList(),
            ede = info?.edns?.ede?.let { code -> DnsMessage.edeName(code) + (info.edns.edeText?.let { " — $it" } ?: "") },
            queryBytes = q.dns.copyOf(minOf(q.dns.size, 512)),
            responseBytes = response.copyOf(minOf(response.size, 1024)),
        )
        ZeroLeakage.record(verdict, label, pkg, q.name, category, byFilter = decision.match != null, detail = detail)
    }

    private data class Decision(
        val verdict: Verdict,
        val category: String,
        val prompt: Boolean = false,
        val match: FilterMatch? = null,
    )

    private fun decide(domain: String, pkg: String?, isCore: Boolean): Decision {
        val match = Filters.match(domain)
        if (match != null && match.blocked) return Decision(Verdict.BLOCKED, match.category, match = match)
        // A domain on your own allowlist is trusted for every app, so it skips the Strict Guard prompt.
        val userAllowed = match != null && match.listId == FilterIndex.USER_ALLOW

        val mode = ZeroLeakage.mode.value
        if (pkg != null) {
            val rule = ZeroLeakage.rule(pkg)
            val allowedOnNetwork = if (onWifi()) rule.wifi else rule.mobile
            if (!allowedOnNetwork) return Decision(Verdict.BLOCKED, "App Network Killed")
            when (mode) {
                ProtectionMode.LOCKDOWN ->
                    if (!rule.pinned) return Decision(Verdict.BLOCKED, "Total Lockdown")
                ProtectionMode.STRICT ->
                    if (!isCore && !userAllowed && !rule.approved && pkg !in ZeroLeakage.allowedOnce)
                        return Decision(Verdict.PROMPT, "Ask to Connect", prompt = true)
                ProtectionMode.BALANCED -> Unit
            }
        } else if (mode == ProtectionMode.LOCKDOWN) {
            return Decision(Verdict.BLOCKED, "Total Lockdown")
        }
        val okCategory = when {
            match != null -> "Allowlisted · DoH"          // an @@ exception or your allowlist
            mode == ProtectionMode.BALANCED -> "Encrypted DoH"
            else -> "Approved · DoH"
        }
        // keep the allow match so the inspector can show which exception let it through
        return Decision(Verdict.ALLOWED, okCategory, match = match)
    }

    private fun ip(b: ByteArray) = b.joinToString(".") { (it.toInt() and 0xFF).toString() }

    private fun networkName(): String {
        val caps = connectivity.activeNetwork?.let { connectivity.getNetworkCapabilities(it) } ?: return "Offline"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
            else -> "Other"
        }
    }

    private data class AppInfo(val pkg: String?, val label: String, val isCore: Boolean)
    private data class Owner(val pkg: String?, val label: String, val uid: Int, val isCore: Boolean)

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
        if (uid == Process.INVALID_UID) return Owner(null, "unknown", uid, isCore = true)
        val info = owners.getOrPut(uid) { lookupOwner(uid) }
        return Owner(info.pkg, info.label, uid, info.isCore)
    }

    /**
     * "Core" means part of Android itself: system uids, and preinstalled system packages with no launcher icon
     * (Google Play services, network stack, captive-portal login). Strict Guard never blocks these, because
     * cutting them off breaks the whole phone. Apps you can open (Chrome, Google, YouTube) still need approval,
     * and the Firewall screen offers Approve for exactly those.
     */
    private fun lookupOwner(uid: Int): AppInfo {
        val pm = packageManager
        val pkgs = pm.getPackagesForUid(uid)
        if (pkgs.isNullOrEmpty()) return AppInfo(null, if (uid < Process.FIRST_APPLICATION_UID) "Android system" else "uid $uid", isCore = true)
        if (uid < Process.FIRST_APPLICATION_UID) return AppInfo(pkgs.first(), "Android system", isCore = true)
        val pkg = pkgs.first()
        val ai = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull()
        val label = ai?.let { pm.getApplicationLabel(it).toString() } ?: pkg
        val allSystem = pkgs.all { p -> runCatching { pm.getApplicationInfo(p, 0).flags and ApplicationInfo.FLAG_SYSTEM != 0 }.getOrDefault(false) }
        val anyLaunchable = pkgs.any { p -> pm.getLaunchIntentForPackage(p) != null }
        return AppInfo(pkg, label, isCore = allSystem && !anyLaunchable)
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
