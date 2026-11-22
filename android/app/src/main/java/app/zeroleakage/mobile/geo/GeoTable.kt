package app.zeroleakage.mobile.geo

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.Locale

/** Where an IP address lives. [code] is ISO-3166 alpha-2, or null for special-purpose ranges. */
data class GeoInfo(val code: String?, val name: String, val note: String? = null) {
    val flag: String get() = code?.let(::flagEmoji) ?: "◌"
    val label: String get() = if (code != null) "$flag $name ($code)" else name
}

fun flagEmoji(code: String): String {
    if (code.length != 2 || !code.all { it in 'A'..'Z' }) return "🏳"
    val base = 0x1F1E6 - 'A'.code
    return String(Character.toChars(base + code[0].code)) + String(Character.toChars(base + code[1].code))
}

fun countryName(code: String): String = when (code) {
    "EU" -> "European Union"
    "AP" -> "Asia/Pacific"
    else -> Locale("", code).getDisplayCountry(Locale.ENGLISH).ifEmpty { code }
}

/**
 * Compact, sorted IP-range → country table built from the DB-IP "IP to Country Lite" CSV
 * (`start,end,CC` per line, IPv4 and IPv6). IPv6 ranges are keyed on their upper 64 bits, which is
 * where all routing / allocation boundaries live. Lookups are binary searches — no allocation.
 * Pure JVM so it is unit-tested without a device.
 */
class GeoTable private constructor(
    private val v4Start: IntArray, private val v4End: IntArray, private val v4Cc: ShortArray,
    private val v6Start: LongArray, private val v6End: LongArray, private val v6Cc: ShortArray,
    val builtFrom: String,
) {
    val size: Int get() = v4Start.size + v6Start.size

    fun lookup(ip: ByteArray): GeoInfo {
        special(ip)?.let { return it }
        val cc = when (ip.size) {
            4 -> search4(toUInt(ip))
            16 -> search6(hi64(ip))
            else -> 0
        }
        if (cc == 0) return GeoInfo(null, "Unknown location")
        val code = decode(cc.toShort())
        return GeoInfo(code, countryName(code))
    }

    fun lookup(ip: String): GeoInfo? = parseIp(ip)?.let { lookup(it) }

    private fun search4(ip: Long): Int {
        var lo = 0; var hi = v4Start.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val s = v4Start[mid].toLong() and 0xFFFFFFFFL
            val e = v4End[mid].toLong() and 0xFFFFFFFFL
            when {
                ip < s -> hi = mid - 1
                ip > e -> lo = mid + 1
                else -> return v4Cc[mid].toInt()
            }
        }
        return 0
    }

    private fun search6(ip: Long): Int {
        var lo = 0; var hi = v6Start.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            when {
                java.lang.Long.compareUnsigned(ip, v6Start[mid]) < 0 -> hi = mid - 1
                java.lang.Long.compareUnsigned(ip, v6End[mid]) > 0 -> lo = mid + 1
                else -> return v6Cc[mid].toInt()
            }
        }
        return 0
    }

    fun write(out: OutputStream) {
        val d = DataOutputStream(out.buffered())
        d.writeInt(MAGIC)
        d.writeUTF(builtFrom)
        d.writeInt(v4Start.size)
        for (i in v4Start.indices) { d.writeInt(v4Start[i]); d.writeInt(v4End[i]); d.writeShort(v4Cc[i].toInt()) }
        d.writeInt(v6Start.size)
        for (i in v6Start.indices) { d.writeLong(v6Start[i]); d.writeLong(v6End[i]); d.writeShort(v6Cc[i].toInt()) }
        d.flush()
    }

    /** Accumulates CSV rows (must arrive sorted by start address, as DB-IP ships them). */
    class Builder(private val source: String) {
        private var s4 = IntArray(1 shl 16); private var e4 = IntArray(1 shl 16); private var c4 = ShortArray(1 shl 16); private var n4 = 0
        private var s6 = LongArray(1 shl 15); private var e6 = LongArray(1 shl 15); private var c6 = ShortArray(1 shl 15); private var n6 = 0

        /** Parses one `start,end,CC` line. Returns false if the line was ignored. */
        fun addCsvLine(line: String): Boolean {
            val a = line.indexOf(','); if (a < 0) return false
            val b = line.indexOf(',', a + 1); if (b < 0) return false
            val code = line.substring(b + 1).trim().trim('"').uppercase()
            if (code.length != 2 || code == "ZZ") return false
            val start = line.substring(0, a).trim('"'); val end = line.substring(a + 1, b).trim('"')
            val cc = encode(code)
            if (start.indexOf(':') < 0) {
                val s = parseV4(start) ?: return false
                val e = parseV4(end) ?: return false
                if (n4 > 0 && c4[n4 - 1] == cc && (e4[n4 - 1].toLong() and 0xFFFFFFFFL) + 1 == (s.toLong() and 0xFFFFFFFFL)) {
                    e4[n4 - 1] = e; return true                          // merge adjacent ranges
                }
                if (n4 == s4.size) { s4 = s4.copyOf(n4 * 2); e4 = e4.copyOf(n4 * 2); c4 = c4.copyOf(n4 * 2) }
                s4[n4] = s; e4[n4] = e; c4[n4] = cc; n4++
            } else {
                val s = runCatching { hi64(InetAddress.getByName(start).address) }.getOrNull() ?: return false
                val e = runCatching { hi64(InetAddress.getByName(end).address) }.getOrNull() ?: return false
                if (n6 > 0 && c6[n6 - 1] == cc && java.lang.Long.compareUnsigned(s, e6[n6 - 1]) <= 0) {
                    if (java.lang.Long.compareUnsigned(e, e6[n6 - 1]) > 0) e6[n6 - 1] = e
                    return true
                }
                if (n6 > 0 && c6[n6 - 1] == cc && e6[n6 - 1] + 1 == s) { e6[n6 - 1] = e; return true }
                if (n6 > 0 && java.lang.Long.compareUnsigned(s, e6[n6 - 1]) <= 0) {
                    // a /64-or-smaller block inside the previous key range — keep the coarser entry
                    return true
                }
                if (n6 == s6.size) { s6 = s6.copyOf(n6 * 2); e6 = e6.copyOf(n6 * 2); c6 = c6.copyOf(n6 * 2) }
                s6[n6] = s; e6[n6] = e; c6[n6] = cc; n6++
            }
            return true
        }

        fun build() = GeoTable(s4.copyOf(n4), e4.copyOf(n4), c4.copyOf(n4), s6.copyOf(n6), e6.copyOf(n6), c6.copyOf(n6), source)
    }

    companion object {
        private const val MAGIC = 0x5A4C4731      // "ZLG1"

        fun read(input: InputStream): GeoTable {
            val d = DataInputStream(input.buffered(1 shl 16))
            require(d.readInt() == MAGIC) { "Not a ZeroLeakage GeoIP file" }
            val src = d.readUTF()
            val n4 = d.readInt()
            val s4 = IntArray(n4); val e4 = IntArray(n4); val c4 = ShortArray(n4)
            for (i in 0 until n4) { s4[i] = d.readInt(); e4[i] = d.readInt(); c4[i] = d.readShort() }
            val n6 = d.readInt()
            val s6 = LongArray(n6); val e6 = LongArray(n6); val c6 = ShortArray(n6)
            for (i in 0 until n6) { s6[i] = d.readLong(); e6[i] = d.readLong(); c6[i] = d.readShort() }
            return GeoTable(s4, e4, c4, s6, e6, c6, src)
        }

        private fun encode(code: String): Short = ((code[0].code shl 8) or code[1].code).toShort()
        private fun decode(v: Short): String {
            val i = v.toInt() and 0xFFFF
            return "${(i ushr 8).toChar()}${(i and 0xFF).toChar()}"
        }

        fun parseV4(s: String): Int? {
            var v = 0L; var part = 0; var parts = 0; var digits = 0
            for (ch in s) {
                if (ch == '.') {
                    if (digits == 0 || part > 255) return null
                    v = (v shl 8) or part.toLong(); part = 0; parts++; digits = 0
                } else if (ch in '0'..'9') {
                    part = part * 10 + (ch - '0'); digits++
                    if (digits > 3) return null
                } else return null
            }
            if (digits == 0 || part > 255 || parts != 3) return null
            return ((v shl 8) or part.toLong()).toInt()
        }

        fun parseIp(s: String): ByteArray? {
            parseV4(s)?.let { v -> return byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()) }
            if (s.indexOf(':') < 0) return null
            return runCatching { InetAddress.getByName(s).address }.getOrNull()
        }

        private fun toUInt(ip: ByteArray): Long =
            ((ip[0].toLong() and 0xFF) shl 24) or ((ip[1].toLong() and 0xFF) shl 16) or
                ((ip[2].toLong() and 0xFF) shl 8) or (ip[3].toLong() and 0xFF)

        private fun hi64(ip: ByteArray): Long {
            if (ip.size == 4) return 0
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (ip[i].toLong() and 0xFF)
            return v
        }

        /** Special-purpose ranges that never belong to a country (RFC 6890). Works without a database. */
        fun special(ip: ByteArray): GeoInfo? {
            if (ip.size == 4) {
                val a = ip[0].toInt() and 0xFF; val b = ip[1].toInt() and 0xFF
                return when {
                    ip.all { it.toInt() == 0 } -> GeoInfo(null, "Null route", "0.0.0.0 — sinkholed / blocked answer")
                    a == 10 || (a == 172 && b in 16..31) || (a == 192 && b == 168) -> GeoInfo(null, "Private network", "RFC 1918 — stays on your LAN")
                    a == 100 && b in 64..127 -> GeoInfo(null, "Carrier-grade NAT", "RFC 6598 — inside your ISP")
                    a == 127 -> GeoInfo(null, "Loopback", "This device")
                    a == 169 && b == 254 -> GeoInfo(null, "Link-local", "RFC 3927")
                    a in 224..239 -> GeoInfo(null, "Multicast", null)
                    a >= 240 -> GeoInfo(null, "Reserved", null)
                    else -> null
                }
            }
            if (ip.size == 16) {
                val a = ip[0].toInt() and 0xFF; val b = ip[1].toInt() and 0xFF
                return when {
                    ip.all { it.toInt() == 0 } -> GeoInfo(null, "Null route", ":: — sinkholed / blocked answer")
                    ip.copyOf(15).all { it.toInt() == 0 } && ip[15].toInt() == 1 -> GeoInfo(null, "Loopback", "This device")
                    a and 0xFE == 0xFC -> GeoInfo(null, "Private network", "Unique local (fc00::/7)")
                    a == 0xFE && b and 0xC0 == 0x80 -> GeoInfo(null, "Link-local", "fe80::/10")
                    a == 0xFF -> GeoInfo(null, "Multicast", null)
                    else -> null
                }
            }
            return null
        }
    }
}
