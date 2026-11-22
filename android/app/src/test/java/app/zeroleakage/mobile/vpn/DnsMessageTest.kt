package app.zeroleakage.mobile.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsMessageTest {

    private fun name(out: ByteArrayOutputStream, n: String) {
        n.split('.').forEach { out.write(it.length); out.write(it.toByteArray()) }
        out.write(0)
    }

    private fun u16(out: ByteArrayOutputStream, v: Int) { out.write(v ushr 8); out.write(v and 0xFF) }

    /** example.com A response with one answer (compressed name), flags QR RD RA [+AD], optional OPT/EDE. */
    private fun response(ad: Boolean, rcode: Int = 0, ede: Int? = null): ByteArray {
        val o = ByteArrayOutputStream()
        u16(o, 0x1234)
        o.write(0x81)                                   // QR RD
        o.write(0x80 or (if (ad) 0x20 else 0) or rcode) // RA [AD]
        u16(o, 1); u16(o, if (rcode == 0) 1 else 0); u16(o, 0); u16(o, if (ede != null) 1 else 0)
        name(o, "example.com"); u16(o, 1); u16(o, 1)
        if (rcode == 0) {
            u16(o, 0xC00C); u16(o, 1); u16(o, 1)
            o.write(0); o.write(0); u16(o, 300)        // TTL 300
            u16(o, 4); o.write(byteArrayOf(93, 184.toByte(), 216.toByte(), 34))
        }
        if (ede != null) {
            o.write(0); u16(o, 41); u16(o, 1232); o.write(0); o.write(0); u16(o, 0x8000)
            val text = "sig expired".toByteArray()
            u16(o, 4 + 2 + text.size); u16(o, 15); u16(o, 2 + text.size); u16(o, ede); o.write(text)
        }
        return o.toByteArray()
    }

    @Test fun parsesAnswersAndFlags() {
        val info = DnsMessage.parseResponse(response(ad = true))!!
        assertEquals(0, info.rcode)
        assertTrue(info.flags.ad)
        assertEquals(1, info.answers.size)
        assertEquals("93.184.216.34", info.answers[0].data)
        assertEquals("example.com", info.answers[0].name)
        assertEquals(300L, info.answers[0].ttl)
        assertEquals("A", info.answers[0].typeName)
        assertEquals(DnssecStatus.SECURE, DnsMessage.dnssecStatus(info))
    }

    @Test fun dnssecStatuses() {
        assertEquals(DnssecStatus.INSECURE, DnsMessage.dnssecStatus(DnsMessage.parseResponse(response(ad = false))))
        val bogus = DnsMessage.parseResponse(response(ad = false, rcode = 2, ede = 7))!!
        assertEquals(7, bogus.edns!!.ede)
        assertEquals("sig expired", bogus.edns!!.edeText)
        assertTrue(bogus.edns!!.dnssecOk)
        assertEquals(DnssecStatus.BOGUS, DnsMessage.dnssecStatus(bogus))
        // SERVFAIL without a DNSSEC EDE is just a failure, not "bogus"
        assertEquals(DnssecStatus.INSECURE, DnsMessage.dnssecStatus(DnsMessage.parseResponse(response(ad = false, rcode = 2))))
    }

    @Test fun setsAdBitWithoutTouchingOtherFlags() {
        val q = byteArrayOf(0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
        val withAd = DnsMessage.withAdBit(q)
        assertEquals(0x20, withAd[3].toInt())
        assertEquals(0x01, withAd[2].toInt())
        assertEquals(0x00, q[3].toInt())                 // original untouched
    }

    @Test fun formatsIpv6AndHex() {
        val b = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[2] = 0x48; it[3] = 0x60; it[15] = 0x01 }
        assertEquals("2001:4860::1", DnsMessage.ipv6(b))
        assertEquals("::1", DnsMessage.ipv6(ByteArray(16).also { it[15] = 1 }))
        assertTrue(DnsMessage.hexDump(byteArrayOf(0x41, 0x42)).startsWith("0000  41 42"))
    }
}
