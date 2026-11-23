package app.zeroleakage.mobile

import app.zeroleakage.mobile.data.Guard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GuardParseTest {
    private fun ip(s: String): Long = s.split('.').fold(0L) { acc, p -> (acc shl 8) or p.toLong() }

    @Test fun singleAddress() = assertEquals(ip("8.8.4.4") to ip("8.8.4.4"), Guard.parseRange("8.8.4.4"))

    @Test fun cidrAndComments() {
        assertEquals(ip("45.9.20.0") to ip("45.9.20.255"), Guard.parseRange("45.9.20.0/24 ; SBL123"))
        assertEquals(ip("1.2.3.4") to ip("1.2.3.4"), Guard.parseRange("1.2.3.4 # botnet"))
    }

    @Test fun skipsPrivateReservedAndJunk() {
        assertNull(Guard.parseRange("10.0.0.0/8"))
        assertNull(Guard.parseRange("192.168.1.1"))
        assertNull(Guard.parseRange("100.64.0.1"))
        assertNull(Guard.parseRange("224.0.0.0/4"))
        assertNull(Guard.parseRange("0.0.0.0/0"))
        assertNull(Guard.parseRange("# comment"))
        assertNull(Guard.parseRange("2001:db8::/32"))
        assertNull(Guard.parseRange("not an ip"))
    }
}
