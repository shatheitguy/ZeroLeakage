package app.zeroleakage.mobile.vpn

/** One resource record from an answer / authority section, already decoded for display. */
data class DnsRecord(val name: String, val type: Int, val ttl: Long, val data: String, val raw: ByteArray? = null) {
    val typeName: String get() = DnsMessage.typeName(type)
    /** Address bytes for A / AAAA records (for GeoIP), else null. */
    val address: ByteArray? get() = if (type == 1 || type == 28) raw else null
}

enum class DnssecStatus(val label: String, val description: String) {
    OFF("Off", "DNSSEC checking is turned off."),
    SECURE("Validated", "The resolver verified the DNSSEC signature chain (AD bit set)."),
    INSECURE("Unsigned", "The domain is not DNSSEC-signed, so authenticity can't be proven."),
    BOGUS("Failed", "The signatures did not verify — possible spoofing. The answer was refused."),
    NOT_CHECKED("Not checked", "No upstream answer (blocked or served locally)."),
}

data class DnsHeaderFlags(val qr: Boolean, val opcode: Int, val aa: Boolean, val tc: Boolean, val rd: Boolean, val ra: Boolean,
                          val ad: Boolean, val cd: Boolean, val rcode: Int) {
    override fun toString(): String = buildList {
        if (qr) add("QR"); if (aa) add("AA"); if (tc) add("TC"); if (rd) add("RD"); if (ra) add("RA"); if (ad) add("AD"); if (cd) add("CD")
    }.joinToString(" ").ifEmpty { "—" }
}

data class EdnsInfo(val udpSize: Int, val version: Int, val dnssecOk: Boolean, val ede: Int?, val edeText: String?)

data class DnsResponseInfo(
    val flags: DnsHeaderFlags,
    val qdCount: Int, val anCount: Int, val nsCount: Int, val arCount: Int,
    val answers: List<DnsRecord>,
    val authority: List<DnsRecord>,
    val edns: EdnsInfo?,
) {
    val rcode: Int get() = flags.rcode
    val minTtl: Long? get() = answers.minOfOrNull { it.ttl }
}

/**
 * DNS message decoding beyond what the forwarding path needs: header flags, answer records,
 * EDNS(0) and Extended DNS Errors (RFC 8914). Pure Kotlin, unit-tested.
 */
object DnsMessage {

    fun typeName(t: Int): String = when (t) {
        1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 12 -> "PTR"; 15 -> "MX"; 16 -> "TXT"; 28 -> "AAAA"
        33 -> "SRV"; 35 -> "NAPTR"; 41 -> "OPT"; 43 -> "DS"; 46 -> "RRSIG"; 47 -> "NSEC"; 48 -> "DNSKEY"
        50 -> "NSEC3"; 64 -> "SVCB"; 65 -> "HTTPS"; 255 -> "ANY"; 257 -> "CAA"
        else -> "TYPE$t"
    }

    fun rcodeName(r: Int): String = when (r) {
        0 -> "NOERROR"; 1 -> "FORMERR"; 2 -> "SERVFAIL"; 3 -> "NXDOMAIN"; 4 -> "NOTIMP"; 5 -> "REFUSED"
        else -> "RCODE$r"
    }

    fun classname(c: Int): String = when (c) { 1 -> "IN"; 3 -> "CH"; 4 -> "HS"; 255 -> "ANY"; else -> "CLASS$c" }

    /** RFC 8914 Extended DNS Error codes. */
    fun edeName(code: Int): String = when (code) {
        0 -> "Other"; 1 -> "Unsupported DNSKEY algorithm"; 2 -> "Unsupported DS digest type"; 3 -> "Stale answer"
        4 -> "Forged answer"; 5 -> "DNSSEC indeterminate"; 6 -> "DNSSEC bogus"; 7 -> "Signature expired"
        8 -> "Signature not yet valid"; 9 -> "DNSKEY missing"; 10 -> "RRSIGs missing"; 11 -> "No zone key bit set"
        12 -> "NSEC missing"; 13 -> "Cached error"; 14 -> "Not ready"; 15 -> "Blocked"; 16 -> "Censored"
        17 -> "Filtered"; 18 -> "Prohibited"; 19 -> "Stale NXDOMAIN answer"; 20 -> "Not authoritative"
        21 -> "Not supported"; 22 -> "No reachable authority"; 23 -> "Network error"; 24 -> "Invalid data"
        else -> "EDE $code"
    }

    fun isDnssecEde(code: Int?): Boolean = code != null && (code in 1..2 || code in 5..12)

    fun headerFlags(msg: ByteArray): DnsHeaderFlags {
        val b2 = msg[2].toInt() and 0xFF
        val b3 = msg[3].toInt() and 0xFF
        return DnsHeaderFlags(
            qr = b2 and 0x80 != 0, opcode = (b2 ushr 3) and 0x0F, aa = b2 and 0x04 != 0, tc = b2 and 0x02 != 0,
            rd = b2 and 0x01 != 0, ra = b3 and 0x80 != 0, ad = b3 and 0x20 != 0, cd = b3 and 0x10 != 0, rcode = b3 and 0x0F,
        )
    }

    /** Copy of a query with the AD bit set — asks a validating resolver to report DNSSEC status (RFC 6840 §5.7). */
    fun withAdBit(query: ByteArray): ByteArray = query.copyOf().also { it[3] = (it[3].toInt() or 0x20).toByte() }

    /** EDNS(0) OPT record of a query (after the question section), or null. */
    fun queryEdns(dns: ByteArray, questionEnd: Int): EdnsInfo? = runCatching {
        val an = u16(dns, 6); val ns = u16(dns, 8); val ar = u16(dns, 10)
        var p = questionEnd
        repeat(an + ns) { p = skipRecord(dns, p) }
        var found: EdnsInfo? = null
        repeat(ar) {
            val nameEnd = skipName(dns, p)
            if (u16(dns, nameEnd) == 41) found = decodeOpt(dns, nameEnd)
            p = skipRecord(dns, p)
        }
        found
    }.getOrNull()

    fun parseResponse(msg: ByteArray): DnsResponseInfo? = runCatching {
        if (msg.size < 12) return null
        val qd = u16(msg, 4); val an = u16(msg, 6); val ns = u16(msg, 8); val ar = u16(msg, 10)
        var p = 12
        repeat(qd) { p = skipName(msg, p) + 4 }
        val answers = ArrayList<DnsRecord>(an)
        repeat(an) { val (r, next) = readRecord(msg, p); answers += r; p = next }
        val authority = ArrayList<DnsRecord>(ns)
        repeat(ns) { val (r, next) = readRecord(msg, p); authority += r; p = next }
        var edns: EdnsInfo? = null
        repeat(ar) {
            val nameEnd = skipName(msg, p)
            if (u16(msg, nameEnd) == 41) edns = decodeOpt(msg, nameEnd)
            p = skipRecord(msg, p)
        }
        DnsResponseInfo(headerFlags(msg), qd, an, ns, ar, answers, authority, edns)
    }.getOrNull()

    /** DNSSEC verdict for an upstream answer to a query sent with the AD bit. */
    fun dnssecStatus(info: DnsResponseInfo?): DnssecStatus = when {
        info == null -> DnssecStatus.NOT_CHECKED
        info.rcode == 2 && isDnssecEde(info.edns?.ede) -> DnssecStatus.BOGUS
        info.flags.ad -> DnssecStatus.SECURE
        else -> DnssecStatus.INSECURE
    }

    private fun decodeOpt(msg: ByteArray, typeAt: Int): EdnsInfo {
        val udp = u16(msg, typeAt + 2)
        val version = msg[typeAt + 5].toInt() and 0xFF
        val flags = u16(msg, typeAt + 6)
        val rdlen = u16(msg, typeAt + 8)
        var p = typeAt + 10
        val end = p + rdlen
        var ede: Int? = null
        var edeText: String? = null
        while (p + 4 <= end) {
            val code = u16(msg, p); val len = u16(msg, p + 2)
            if (code == 15 && len >= 2) {
                ede = u16(msg, p + 4)
                if (len > 2) edeText = String(msg, p + 6, len - 2, Charsets.UTF_8)
            }
            p += 4 + len
        }
        return EdnsInfo(udp, version, flags and 0x8000 != 0, ede, edeText)
    }

    private fun readRecord(msg: ByteArray, start: Int): Pair<DnsRecord, Int> {
        val name = readName(msg, start)
        val p = skipName(msg, start)
        val type = u16(msg, p)
        val ttl = ((msg[p + 4].toLong() and 0xFF) shl 24) or ((msg[p + 5].toLong() and 0xFF) shl 16) or
            ((msg[p + 6].toLong() and 0xFF) shl 8) or (msg[p + 7].toLong() and 0xFF)
        val len = u16(msg, p + 8)
        val r = p + 10
        val raw = msg.copyOfRange(r, r + len)
        val data = when (type) {
            1 -> if (len == 4) raw.joinToString(".") { (it.toInt() and 0xFF).toString() } else "?"
            28 -> if (len == 16) ipv6(raw) else "?"
            2, 5, 12, 39 -> readName(msg, r)
            15 -> "${u16(msg, r)} ${readName(msg, r + 2)}"
            16 -> txt(raw)
            6 -> "${readName(msg, r)} ${readName(msg, skipName(msg, r))}"
            33 -> "${u16(msg, r)} ${u16(msg, r + 2)} ${u16(msg, r + 4)} ${readName(msg, r + 6)}"
            64, 65 -> "priority ${u16(msg, r)} → ${readName(msg, r + 2).ifEmpty { "." }}"
            46 -> "signs ${typeName(u16(msg, r))} · alg ${msg[r + 2].toInt() and 0xFF} · key ${u16(msg, r + 16)}"
            else -> "$len bytes"
        }
        return DnsRecord(name, type, ttl, data, raw) to (r + len)
    }

    fun readName(msg: ByteArray, start: Int): String {
        val sb = StringBuilder()
        var p = start
        var jumps = 0
        while (p < msg.size) {
            val l = msg[p].toInt() and 0xFF
            if (l == 0) break
            if (l and 0xC0 == 0xC0) {
                if (++jumps > 16) break
                p = ((l and 0x3F) shl 8) or (msg[p + 1].toInt() and 0xFF)
                continue
            }
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..l) sb.append((msg[p + i].toInt() and 0xFF).toChar())
            p += 1 + l
        }
        return sb.toString()
    }

    fun skipName(msg: ByteArray, start: Int): Int {
        var p = start
        while (true) {
            val l = msg[p].toInt() and 0xFF
            if (l == 0) return p + 1
            if (l and 0xC0 == 0xC0) return p + 2
            p += 1 + l
        }
    }

    private fun skipRecord(msg: ByteArray, start: Int): Int {
        val p = skipName(msg, start)
        return p + 10 + u16(msg, p + 8)
    }

    private fun txt(raw: ByteArray): String {
        val parts = ArrayList<String>()
        var p = 0
        while (p < raw.size) {
            val l = raw[p].toInt() and 0xFF
            parts += "\"" + String(raw, p + 1, minOf(l, raw.size - p - 1), Charsets.UTF_8) + "\""
            p += 1 + l
        }
        return parts.joinToString(" ")
    }

    fun ipv6(b: ByteArray): String {
        val groups = IntArray(8) { ((b[it * 2].toInt() and 0xFF) shl 8) or (b[it * 2 + 1].toInt() and 0xFF) }
        // compress the longest run of zero groups
        var bestStart = -1; var bestLen = 0; var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i; while (j < 8 && groups[j] == 0) j++
                if (j - i > bestLen && j - i > 1) { bestStart = i; bestLen = j - i }
                i = j
            } else i++
        }
        val sb = StringBuilder()
        i = 0
        while (i < 8) {
            if (i == bestStart) { sb.append(if (i == 0) "::" else ":"); i += bestLen; continue }
            sb.append(Integer.toHexString(groups[i]))
            if (i < 7) sb.append(':')
            i++
        }
        return sb.toString()
    }

    /** Classic 16-bytes-per-row hex + ASCII dump. */
    fun hexDump(bytes: ByteArray, limit: Int = 512): String {
        val n = minOf(bytes.size, limit)
        val sb = StringBuilder()
        var off = 0
        while (off < n) {
            sb.append(String.format("%04x  ", off))
            for (i in 0 until 16) {
                if (off + i < n) sb.append(String.format("%02x ", bytes[off + i].toInt() and 0xFF)) else sb.append("   ")
                if (i == 7) sb.append(' ')
            }
            sb.append(' ')
            for (i in 0 until minOf(16, n - off)) {
                val c = bytes[off + i].toInt() and 0xFF
                sb.append(if (c in 0x20..0x7E) c.toChar() else '.')
            }
            sb.append('\n')
            off += 16
        }
        if (bytes.size > limit) sb.append("… ${bytes.size - limit} more bytes")
        return sb.toString().trimEnd()
    }

    private fun u16(b: ByteArray, off: Int) = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
}
