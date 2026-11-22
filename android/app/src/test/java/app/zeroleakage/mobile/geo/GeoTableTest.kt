package app.zeroleakage.mobile.geo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class GeoTableTest {

    private fun table(): GeoTable {
        val b = GeoTable.Builder("test")
        listOf(
            "0.0.0.0,0.255.255.255,ZZ",
            "1.0.0.0,1.0.0.255,AU",
            "1.0.1.0,1.0.3.255,CN",
            "8.8.8.0,8.8.8.255,US",
            "200.0.0.0,200.0.0.255,BR",
            "255.255.255.0,255.255.255.255,US",
            "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US",
            "2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,IE",
        ).forEach { b.addCsvLine(it) }
        return b.build()
    }

    @Test fun looksUpIpv4AndIpv6() {
        val t = table()
        assertEquals("AU", t.lookup("1.0.0.1")!!.code)
        assertEquals("CN", t.lookup("1.0.2.200")!!.code)
        assertEquals("US", t.lookup("8.8.8.8")!!.code)
        assertEquals("United States", t.lookup("8.8.8.8")!!.name)
        assertEquals("BR", t.lookup("200.0.0.9")!!.code)
        assertNull(t.lookup("9.9.9.9")!!.code)                 // not in table
        assertEquals("US", t.lookup("2001:4860:4860::8888")!!.code)
        assertEquals("IE", t.lookup("2a00:1450:4001:80b::200e")!!.code)
    }

    @Test fun specialRangesNeedNoDatabase() {
        assertEquals("Private network", GeoTable.special(GeoTable.parseIp("192.168.1.1")!!)!!.name)
        assertEquals("Carrier-grade NAT", GeoTable.special(GeoTable.parseIp("100.70.1.1")!!)!!.name)
        assertEquals("Null route", GeoTable.special(GeoTable.parseIp("0.0.0.0")!!)!!.name)
        assertEquals("Loopback", GeoTable.special(GeoTable.parseIp("::1")!!)!!.name)
        assertNull(GeoTable.special(GeoTable.parseIp("8.8.8.8")!!))
    }

    @Test fun roundTripsBinaryFormat() {
        val out = ByteArrayOutputStream()
        table().write(out)
        val t = GeoTable.read(ByteArrayInputStream(out.toByteArray()))
        assertEquals("test", t.builtFrom)
        assertEquals("CN", t.lookup("1.0.3.1")!!.code)
        assertEquals("IE", t.lookup("2a00:1450::1")!!.code)
    }

    @Test fun flagEmoji() {
        assertEquals("🇺🇸", flagEmoji("US"))
    }
}
