package app.zeroleakage.mobile.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketTest {

    private val appIp = byteArrayOf(10, 111, 222.toByte(), 1)
    private val dnsIp = byteArrayOf(10, 111, 222.toByte(), 2)

    /** Builds an IPv4/UDP packet carrying a standard A query, as an app's resolver would send it. */
    private fun query(name: String, id: Int = 0xBEEF, qtype: Int = 1, dstPort: Int = 53): ByteArray {
        val q = java.io.ByteArrayOutputStream()
        q.write(byteArrayOf((id ushr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        name.split('.').forEach { label -> q.write(label.length); q.write(label.toByteArray()) }
        q.write(0)
        q.write(byteArrayOf((qtype ushr 8).toByte(), qtype.toByte(), 0, 1))
        val dns = q.toByteArray()
        val total = 28 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total ushr 8).toByte(); p[3] = total.toByte(); p[8] = 64; p[9] = 17
        System.arraycopy(appIp, 0, p, 12, 4); System.arraycopy(dnsIp, 0, p, 16, 4)
        p[20] = (40000 ushr 8).toByte(); p[21] = 40000.toByte()
        p[22] = (dstPort ushr 8).toByte(); p[23] = dstPort.toByte()
        p[24] = ((8 + dns.size) ushr 8).toByte(); p[25] = (8 + dns.size).toByte()
        System.arraycopy(dns, 0, p, 28, dns.size)
        return p
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    @Test fun parsesQuestion() {
        val pkt = query("V10.Events.Data.Microsoft.com", qtype = 28)
        val q = DnsPacket.parse(pkt, pkt.size)
        assertNotNull(q)
        q!!
        assertEquals("v10.events.data.microsoft.com", q.name)
        assertEquals(28, q.qtype)
        assertEquals(0xBEEF, q.id)
        assertEquals(40000, q.srcPort)
    }

    @Test fun ignoresNonDnsAndGarbage() {
        val notDns = query("example.com", dstPort = 443)
        assertNull(DnsPacket.parse(notDns, notDns.size))
        assertNull(DnsPacket.parse(ByteArray(10), 10))
        val v6 = query("example.com").also { it[0] = 0x60 }
        assertNull(DnsPacket.parse(v6, v6.size))
    }

    @Test fun nxdomainEchoesQuestionOnly() {
        val pkt = query("tracker.example.com")
        val q = DnsPacket.parse(pkt, pkt.size)!!
        val r = DnsPacket.errorResponse(q, 3)
        assertEquals(q.questionEnd, r.size)
        assertEquals(0xBEEF, u16(r, 0))
        assertEquals(0x81, r[2].toInt() and 0xFF)        // QR + RD
        assertEquals(0x83, r[3].toInt() and 0xFF)        // RA + NXDOMAIN
        assertEquals(1, u16(r, 4)); assertEquals(0, u16(r, 6))
    }

    @Test fun responsePacketIsAddressedBackWithValidChecksum() {
        val pkt = query("example.com")
        val q = DnsPacket.parse(pkt, pkt.size)!!
        val dns = DnsPacket.errorResponse(q, 3)
        val out = DnsPacket.buildIpPacket(q, dns)
        assertEquals(out.size, u16(out, 2))
        assertArrayEquals(dnsIp, out.copyOfRange(12, 16))
        assertArrayEquals(appIp, out.copyOfRange(16, 20))
        assertEquals(53, u16(out, 20)); assertEquals(40000, u16(out, 22))
        var sum = 0L
        for (i in 0 until 20 step 2) sum += u16(out, i)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        assertEquals(0xFFFF, sum.toInt())                // header checksum verifies
        assertArrayEquals(dns, out.copyOfRange(28, out.size))
    }

    @Test fun restampsTransactionId() {
        val r = DnsPacket.withId(byteArrayOf(0, 0, 1, 2), 0x1234)
        assertEquals(0x1234, u16(r, 0))
    }
}
