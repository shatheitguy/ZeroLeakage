package app.zeroleakage.mobile.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FilterRulesTest {

    private fun p(s: String, suffix: Boolean = false) = FilterParser.parseLine(s, suffix)

    @Test fun parsesAdblockDnsRules() {
        assertEquals(ParsedRule(RuleKind.BLOCK_SUFFIX, "doubleclick.net"), p("||doubleclick.net^"))
        assertEquals(ParsedRule(RuleKind.BLOCK_SUFFIX, "ads.example.com"), p("||ads.example.com^\$important"))
        assertEquals(ParsedRule(RuleKind.BLOCK_SUFFIX, "x.com"), p("||x.com^\$third-party"))
        assertEquals(ParsedRule(RuleKind.ALLOW_SUFFIX, "good.example.com"), p("@@||good.example.com^"))
        assertEquals(ParsedRule(RuleKind.BLOCK_SUFFIX, "x.com"), p("||X.com^|"))
    }

    @Test fun skipsRulesDnsCannotExpress() {
        assertNull(p("||example.com/ads/*"))
        assertNull(p("||example.com^\$dnstype=AAAA"))
        assertNull(p("||example.com^\$badfilter"))
        assertNull(p("/ads[0-9]+\\.example\\.com/"))
        assertNull(p("||*.example.com^"))
        assertNull(p("example.com##.banner"))
        assertNull(p("! comment"))
        assertNull(p("[Adblock Plus 2.0]"))
        assertNull(p("# comment"))
        assertNull(p(""))
    }

    @Test fun parsesHostsAndPlainDomains() {
        assertEquals(ParsedRule(RuleKind.BLOCK_EXACT, "ads.example.com"), p("0.0.0.0 ads.example.com"))
        assertEquals(ParsedRule(RuleKind.BLOCK_EXACT, "ads.example.com"), p("127.0.0.1\tads.example.com # tracker"))
        assertEquals(ParsedRule(RuleKind.BLOCK_EXACT, "phish.example.org"), p("phish.example.org"))
        assertEquals(ParsedRule(RuleKind.BLOCK_SUFFIX, "phish.example.org"), p("phish.example.org", suffix = true))
        assertNull(p("127.0.0.1 localhost"))
        assertNull(p("0.0.0.0 0.0.0.0"))
        assertNull(p("1.2.3.4"))
        assertNull(p("not a domain"))
    }

    @Test fun indexPrecedenceAndSubdomains() {
        val b = FilterIndex.Builder()
        b.addList(ListLabel("a", "List A", "Ad Tracker"), sequenceOf(
            "||tracker.com^", "0.0.0.0 exact.com", "@@||ok.tracker.com^",
        ))
        b.addList(ListLabel("b", "List B", "Malware"), sequenceOf("||tracker.com^", "||evil.net^"))
        b.user(allow = setOf("evil.net"), block = setOf("ok.tracker.com"))
        val idx = b.build()

        val m = idx.match("cdn.tracker.com")!!
        assertTrue(m.blocked); assertEquals("a", m.listId); assertEquals("||tracker.com^", m.rule)

        assertNotNull(idx.match("exact.com")); assertNull(idx.match("sub.exact.com"))   // hosts = exact
        assertNull(idx.match("com"))
        assertNull(idx.match("nottracker.com"))

        // user block beats a list exception; user allow beats list blocks
        assertTrue(idx.match("ok.tracker.com")!!.blocked)
        assertFalse(idx.match("x.evil.net")!!.blocked)

        assertEquals(mapOf("a" to 3, "b" to 2), idx.counts)
        assertEquals(4, idx.totalRules)        // tracker.com deduped across lists

        val updated = idx.withUser(emptySet(), emptySet())
        assertFalse(updated.match("ok.tracker.com")!!.blocked)   // list @@ exception now applies
        assertTrue(updated.match("evil.net")!!.blocked)
    }
}
