package app.zeroleakage.mobile.vpn

import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.LinkedHashMap

/**
 * RFC 8484 DNS-over-HTTPS client (POST application/dns-message) with a small TTL-bounded cache.
 * The app's own package is excluded from the VPN, so these HTTPS calls go straight out.
 */
class DohClient {

    private class Entry(val response: ByteArray, val expiresAt: Long)

    private val cache = object : LinkedHashMap<String, Entry>(512, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?) = size > 1_000
    }

    fun cached(q: DnsQuery): ByteArray? = synchronized(cache) {
        val e = cache["${q.name}/${q.qtype}"] ?: return null
        if (SystemClock.elapsedRealtime() > e.expiresAt) {
            cache.remove("${q.name}/${q.qtype}")
            null
        } else e.response
    }

    /**
     * Resolves [q] through [endpoint]; returns the raw DNS response and the round-trip latency in ms.
     * [upstream] is the message actually sent (e.g. the query with the DNSSEC AD bit added).
     */
    fun resolve(endpoint: String, q: DnsQuery, upstream: ByteArray = q.dns): Pair<ByteArray, Long> {
        val started = SystemClock.elapsedRealtime()
        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 4_000
            readTimeout = 4_000
            doOutput = true
            useCaches = false
            setRequestProperty("Content-Type", "application/dns-message")
            setRequestProperty("Accept", "application/dns-message")
        }
        try {
            // RFC 8484 §4.1: use id 0 for cache-friendliness; we re-stamp the real id afterwards.
            val body = DnsPacket.withId(upstream, 0)
            conn.outputStream.use { it.write(body) }
            if (conn.responseCode != 200) error("DoH HTTP ${conn.responseCode}")
            val bytes = conn.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                input.copyTo(out)
                out.toByteArray()
            }
            val latency = SystemClock.elapsedRealtime() - started
            val ttl = minTtlSeconds(bytes).coerceIn(10, 300)
            synchronized(cache) {
                cache["${q.name}/${q.qtype}"] = Entry(bytes, SystemClock.elapsedRealtime() + ttl * 1_000L)
            }
            return DnsPacket.withId(bytes, q.id) to latency
        } finally {
            conn.disconnect()
        }
    }

    fun clear() = synchronized(cache) { cache.clear() }

    /** Smallest TTL among answer records (defaults to 60 s when unparsable). */
    private fun minTtlSeconds(msg: ByteArray): Int = runCatching {
        fun u16(o: Int) = ((msg[o].toInt() and 0xFF) shl 8) or (msg[o + 1].toInt() and 0xFF)
        fun skipName(start: Int): Int {
            var p = start
            while (true) {
                val l = msg[p].toInt() and 0xFF
                if (l == 0) return p + 1
                if (l and 0xC0 == 0xC0) return p + 2
                p += 1 + l
            }
        }
        val qd = u16(4)
        val an = u16(6)
        var p = 12
        repeat(qd) { p = skipName(p) + 4 }
        var min = Int.MAX_VALUE
        repeat(an) {
            p = skipName(p)
            val ttl = ((msg[p + 4].toInt() and 0xFF) shl 24) or ((msg[p + 5].toInt() and 0xFF) shl 16) or
                ((msg[p + 6].toInt() and 0xFF) shl 8) or (msg[p + 7].toInt() and 0xFF)
            min = minOf(min, ttl)
            p += 10 + u16(p + 8)
        }
        if (min == Int.MAX_VALUE) 60 else min
    }.getOrDefault(60)
}
