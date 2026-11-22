package app.zeroleakage.mobile.vpn

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import app.zeroleakage.mobile.data.Resolver
import app.zeroleakage.mobile.data.ZeroLeakage
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Gets an answer for an allowed lookup, without ever leaving the phone offline:
 *  1. your chosen DNS-over-HTTPS resolver,
 *  2. other well-known DoH resolvers (some networks block a particular provider),
 *  3. optionally, the network's own DNS server (unencrypted) when encrypted DNS is blocked entirely.
 * Resolvers that just failed are skipped for a minute so one bad provider doesn't slow every lookup.
 */
class Upstream(private val doh: DohClient, private val connectivity: ConnectivityManager) {

    data class Answer(val bytes: ByteArray, val latencyMs: Long, val resolverName: String, val resolverUrl: String,
                      val encrypted: Boolean, val failedOver: Boolean)

    private val downUntil = ConcurrentHashMap<String, Long>()

    private fun candidates(primary: Resolver): List<Resolver> {
        val backups = listOf("cloudflare", "quad9", "google", "adguard")
            .mapNotNull { id -> ZeroLeakage.RESOLVERS.firstOrNull { it.id == id } }
        val all = (listOf(primary) + backups).distinctBy { it.url }
        val now = SystemClock.elapsedRealtime()
        val healthy = all.filter { (downUntil[it.url] ?: 0L) < now }
        return healthy.ifEmpty { all }        // if everything is marked down, try them all again
    }

    fun resolve(q: DnsQuery, upstream: ByteArray): Answer {
        val primary = ZeroLeakage.resolver()
        var lastError: Exception? = null
        for ((i, r) in candidates(primary).withIndex()) {
            try {
                val (bytes, ms) = doh.resolve(r.url, q, upstream)
                downUntil.remove(r.url)
                ZeroLeakage.reportDns(ok = true, fallback = i > 0 || r.url != primary.url, error = null, via = r.name)
                return Answer(bytes, ms, r.name, r.url, encrypted = true, failedOver = r.url != primary.url)
            } catch (e: Exception) {
                lastError = e
                downUntil[r.url] = SystemClock.elapsedRealtime() + 60_000
            }
        }
        val why = lastError?.message ?: "unreachable"
        if (ZeroLeakage.fallbackDns.value) {
            val started = SystemClock.elapsedRealtime()
            val bytes = plainDns(q)
            if (bytes != null) {
                ZeroLeakage.reportDns(ok = true, fallback = true, error = "Encrypted DNS blocked ($why)", via = "Network DNS")
                return Answer(bytes, SystemClock.elapsedRealtime() - started, "Network DNS (unencrypted)", "udp://network", encrypted = false, failedOver = true)
            }
        }
        ZeroLeakage.reportDns(ok = false, fallback = false, error = why, via = null)
        throw lastError ?: IllegalStateException("No DNS resolver reachable")
    }

    /** Plain UDP DNS to the underlying (non-VPN) network's DNS servers. Our app is excluded from the VPN. */
    private fun plainDns(q: DnsQuery): ByteArray? {
        @Suppress("DEPRECATION")
        val network = connectivity.allNetworks.firstOrNull { n ->
            connectivity.getNetworkCapabilities(n)?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } == true
        } ?: return null
        val servers = connectivity.getLinkProperties(network)?.dnsServers.orEmpty()
            .filterNot { it.hostAddress?.startsWith("10.111.222.") == true }
        for (server in servers) {
            try {
                DatagramSocket().use { socket ->
                    network.bindSocket(socket)
                    socket.soTimeout = 2_500
                    socket.send(DatagramPacket(q.dns, q.dns.size, InetAddress.getByAddress(server.address), 53))
                    val buf = ByteArray(4_096)
                    val p = DatagramPacket(buf, buf.size)
                    socket.receive(p)
                    if (p.length >= 12) return buf.copyOf(p.length)
                }
            } catch (_: Exception) { /* try the next server */ }
        }
        return null
    }
}
