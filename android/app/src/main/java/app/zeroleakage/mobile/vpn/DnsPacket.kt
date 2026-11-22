package app.zeroleakage.mobile.vpn

/**
 * Minimal IPv4/UDP/DNS codec for the DNS-only tunnel.
 * Only queries addressed to our virtual DNS server (UDP :53) are ever routed into the TUN.
 */
class DnsQuery(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    /** Raw DNS message (header + question + any additional records). */
    val dns: ByteArray,
    /** Offset in [dns] right after the question section. */
    val questionEnd: Int,
    val name: String,
    val qtype: Int,
    val qclass: Int = 1,
    /** IPv4 / UDP header fields of the query as it arrived from the app (for the packet inspector). */
    val ipTtl: Int = 0,
    val ipId: Int = 0,
    val ipTotalLen: Int = 0,
    val udpLen: Int = 0,
    val udpChecksum: Int = 0,
) {
    val id: Int get() = ((dns[0].toInt() and 0xFF) shl 8) or (dns[1].toInt() and 0xFF)
}

object DnsPacket {

    private const val IPPROTO_UDP = 17

    fun parse(buf: ByteArray, len: Int): DnsQuery? {
        if (len < 28) return null
        val version = (buf[0].toInt() and 0xF0) ushr 4
        if (version != 4) return null
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (buf[9].toInt() and 0xFF != IPPROTO_UDP) return null
        val totalLen = u16(buf, 2).coerceAtMost(len)
        if (totalLen < ihl + 8 + 12) return null

        val srcIp = buf.copyOfRange(12, 16)
        val dstIp = buf.copyOfRange(16, 20)
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        if (dstPort != 53) return null

        val dns = buf.copyOfRange(ihl + 8, totalLen)
        if ((dns[2].toInt() and 0x80) != 0) return null           // not a query
        if (u16(dns, 4) < 1) return null                          // QDCOUNT

        // QNAME
        val sb = StringBuilder()
        var p = 12
        while (p < dns.size) {
            val labelLen = dns[p].toInt() and 0xFF
            if (labelLen == 0) { p++; break }
            if (labelLen and 0xC0 != 0 || p + 1 + labelLen > dns.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..labelLen) sb.append((dns[p + i].toInt() and 0xFF).toChar())
            p += 1 + labelLen
        }
        if (p + 4 > dns.size) return null
        val qtype = u16(dns, p)
        val qclass = u16(dns, p + 2)
        return DnsQuery(
            srcIp, dstIp, srcPort, dstPort, dns, p + 4, sb.toString().lowercase(), qtype, qclass,
            ipTtl = buf[8].toInt() and 0xFF, ipId = u16(buf, 4), ipTotalLen = totalLen,
            udpLen = u16(buf, ihl + 4), udpChecksum = u16(buf, ihl + 6),
        )
    }

    /** NXDOMAIN (rcode 3) or SERVFAIL (rcode 2) answer that echoes only the question. */
    fun errorResponse(q: DnsQuery, rcode: Int): ByteArray {
        val out = q.dns.copyOf(q.questionEnd)
        out[2] = (0x80 or (q.dns[2].toInt() and 0x79)).toByte()    // QR=1, keep opcode + RD
        out[3] = (0x80 or (rcode and 0x0F)).toByte()                // RA=1
        out[6] = 0; out[7] = 0                                      // ANCOUNT
        out[8] = 0; out[9] = 0                                      // NSCOUNT
        out[10] = 0; out[11] = 0                                    // ARCOUNT
        return out
    }

    /** Re-stamps a cached DNS response with the transaction id of a new query. */
    fun withId(response: ByteArray, id: Int): ByteArray = response.copyOf().also {
        it[0] = (id ushr 8).toByte()
        it[1] = id.toByte()
    }

    /** Wraps a DNS response in an IPv4/UDP packet travelling back to the querying socket. */
    fun buildIpPacket(q: DnsQuery, dnsResponse: ByteArray): ByteArray {
        val ipLen = 20
        val total = ipLen + 8 + dnsResponse.size
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        put16(p, 4, 0)            // identification
        p[6] = 0x40               // don't fragment
        p[8] = 64                 // TTL
        p[9] = IPPROTO_UDP.toByte()
        System.arraycopy(q.dstIp, 0, p, 12, 4)    // swap: from our DNS ...
        System.arraycopy(q.srcIp, 0, p, 16, 4)    // ... back to the app
        put16(p, 10, checksum(p, 0, ipLen))

        put16(p, ipLen, q.dstPort)
        put16(p, ipLen + 2, q.srcPort)
        put16(p, ipLen + 4, 8 + dnsResponse.size)
        put16(p, ipLen + 6, 0)    // UDP checksum optional over IPv4
        System.arraycopy(dnsResponse, 0, p, ipLen + 8, dnsResponse.size)
        return p
    }

    private fun u16(b: ByteArray, off: Int) = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len - 1) {
            sum += u16(b, i)
            i += 2
        }
        if (len % 2 == 1) sum += (b[off + len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }
}
