package app.zeroleakage.mobile.filters

/**
 * DNS-level filter rule parsing, AdGuard Home style. Pure Kotlin (no Android) so it is unit-tested on the JVM.
 *
 * Supported syntaxes:
 *  - hosts files:        `0.0.0.0 ads.example.com`, `127.0.0.1 x`, `:: x`          → exact domain
 *  - domain lists:       `ads.example.com`                                           → exact (or suffix for curated lists)
 *  - AdBlock DNS rules:  `||example.com^`, `||example.com^$important`               → domain + all subdomains
 *  - exceptions:         `@@||example.com^`                                          → allow domain + subdomains
 * Anything that can't be expressed as a domain decision (paths, regex, wildcards, cosmetic rules,
 * `$dnstype`, `$client`, `$badfilter`, …) is skipped, exactly like a DNS filter would.
 */
enum class RuleKind { BLOCK_EXACT, BLOCK_SUFFIX, ALLOW_EXACT, ALLOW_SUFFIX }

data class ParsedRule(val kind: RuleKind, val domain: String)

object FilterParser {

    private val HOST_IPS = setOf("0.0.0.0", "127.0.0.1", "::", "::0", "::1", "0", "0:0:0:0:0:0:0:0")
    private val SKIP_HOSTS = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    )
    private val OK_MODIFIERS = setOf("important", "third-party", "3p", "all", "document", "doc")

    /** @param plainIsSuffix treat bare domains / hosts entries as "domain + subdomains" (curated bundled lists). */
    fun parseLine(raw: String, plainIsSuffix: Boolean = false): ParsedRule? {
        var line = raw.trim()
        if (line.isEmpty()) return null
        val c = line[0]
        if (c == '!' || c == '#' || c == '[') return null
        if (line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#")) return null

        var allow = false
        if (line.startsWith("@@")) { allow = true; line = line.substring(2) }

        if (line.startsWith("||")) {
            val body = line.substring(2)
            val caret = body.indexOf('^')
            val domainPart: String
            val rest: String
            if (caret >= 0) {
                domainPart = body.substring(0, caret)
                rest = body.substring(caret + 1)
            } else {
                val dollar = body.indexOf('$')
                domainPart = if (dollar >= 0) body.substring(0, dollar) else body.trimEnd('|')
                rest = if (dollar >= 0) body.substring(dollar) else ""
            }
            val r = rest.removePrefix("|")
            if (r.isNotEmpty()) {
                if (!r.startsWith("$")) return null                         // path after ^
                val mods = r.substring(1).split(',').map { it.trim().lowercase() }
                if (mods.any { it !in OK_MODIFIERS }) return null
            }
            val d = cleanDomain(domainPart) ?: return null
            return ParsedRule(if (allow) RuleKind.ALLOW_SUFFIX else RuleKind.BLOCK_SUFFIX, d)
        }
        if (allow) {
            // `@@domain` without anchors — treat like `@@||domain^`
            val d = cleanDomain(line.trimEnd('^', '|')) ?: return null
            return ParsedRule(RuleKind.ALLOW_SUFFIX, d)
        }
        if (line[0] == '|' || line[0] == '/' || line.contains('$') || line.contains('*')) return null

        // hosts / plain domain; drop trailing comments
        val hash = line.indexOf('#')
        if (hash >= 0) line = line.substring(0, hash).trim()
        if (line.isEmpty()) return null
        val tokens = line.split(' ', '\t').filter { it.isNotEmpty() }
        val host = when {
            tokens.size >= 2 && tokens[0] in HOST_IPS -> tokens[1]
            tokens.size == 1 -> tokens[0]
            else -> return null
        }
        if (host.lowercase() in SKIP_HOSTS) return null
        val d = cleanDomain(host) ?: return null
        return ParsedRule(if (plainIsSuffix) RuleKind.BLOCK_SUFFIX else RuleKind.BLOCK_EXACT, d)
    }

    fun cleanDomain(raw: String): String? {
        val d = raw.trim().trimEnd('.').lowercase()
        if (d.length < 3 || d.length > 253 || !d.contains('.')) return null
        if (d.startsWith('.') || d.startsWith('-')) return null
        for (ch in d) {
            if (!(ch in 'a'..'z' || ch in '0'..'9' || ch == '.' || ch == '-' || ch == '_')) return null
        }
        if (d.contains("..")) return null
        // a bare IPv4 literal is not a domain rule
        if (d.all { it.isDigit() || it == '.' }) return null
        return d
    }
}

/** Why a lookup was blocked or allowed by the filter engine. */
data class FilterMatch(
    val blocked: Boolean,
    val listId: String,
    val listName: String,
    val category: String,
    /** The rule as it would appear in the list, e.g. `||doubleclick.net^` or `0.0.0.0 ads.x.com`. */
    val rule: String,
    /** The domain (or parent domain) that matched. */
    val matched: String,
)

/** Source metadata used to label matches. */
data class ListLabel(val id: String, val name: String, val category: String)

/**
 * Immutable in-memory index over every enabled list. Duplicates across lists are stored once
 * (first list wins), so enabling overlapping lists costs little memory.
 */
class FilterIndex private constructor(
    private val labels: List<ListLabel>,
    private val blockExact: HashMap<String, Short>,
    private val blockSuffix: HashMap<String, Short>,
    private val allowExact: HashMap<String, Short>,
    private val allowSuffix: HashMap<String, Short>,
    private val userAllow: Set<String>,
    private val userBlock: Set<String>,
    val counts: Map<String, Int>,
) {
    val totalRules: Int get() = blockExact.size + blockSuffix.size + allowExact.size + allowSuffix.size

    fun match(domain: String): FilterMatch? {
        val d = domain.lowercase().trimEnd('.')
        // Precedence: your allowlist > your blocklist > list exceptions (@@) > list blocks.
        walk(d) { s -> if (s in userAllow) return FilterMatch(false, USER_ALLOW, "Your allowlist", "Allowlisted", "@@||$s^", s) }
        walk(d) { s -> if (s in userBlock) return FilterMatch(true, USER_BLOCK, "Your blocklist", "User Blocklist", "||$s^", s) }
        allowExact[d]?.let { return hit(false, it, "@@|$d^", d) }
        walk(d) { s -> allowSuffix[s]?.let { return hit(false, it, "@@||$s^", s) } }
        blockExact[d]?.let { return hit(true, it, "0.0.0.0 $d", d) }
        walk(d) { s -> blockSuffix[s]?.let { return hit(true, it, "||$s^", s) } }
        return null
    }

    private inline fun walk(domain: String, f: (String) -> Unit) {
        var d = domain
        while (true) {
            f(d)
            val dot = d.indexOf('.')
            if (dot < 0 || dot == d.length - 1) return
            d = d.substring(dot + 1)
            if (!d.contains('.')) return          // never match a bare TLD
        }
    }

    private fun hit(blocked: Boolean, idx: Short, rule: String, matched: String): FilterMatch {
        val l = labels[idx.toInt()]
        return FilterMatch(blocked, l.id, l.name, l.category, rule, matched)
    }

    class Builder {
        private val labels = ArrayList<ListLabel>()
        private val blockExact = HashMap<String, Short>()
        private val blockSuffix = HashMap<String, Short>()
        private val allowExact = HashMap<String, Short>()
        private val allowSuffix = HashMap<String, Short>()
        private val counts = HashMap<String, Int>()

        /** Adds every rule from [lines]; returns how many usable rules the list contained. */
        fun addList(label: ListLabel, lines: Sequence<String>, plainIsSuffix: Boolean = false): Int {
            if (labels.size >= Short.MAX_VALUE) return 0
            val idx = labels.size.toShort()
            labels += label
            var n = 0
            for (line in lines) {
                val r = FilterParser.parseLine(line, plainIsSuffix) ?: continue
                n++
                val map = when (r.kind) {
                    RuleKind.BLOCK_EXACT -> blockExact
                    RuleKind.BLOCK_SUFFIX -> blockSuffix
                    RuleKind.ALLOW_EXACT -> allowExact
                    RuleKind.ALLOW_SUFFIX -> allowSuffix
                }
                map.putIfAbsent(r.domain, idx)
            }
            counts[label.id] = n
            return n
        }

        private var userAllow: Set<String> = emptySet()
        private var userBlock: Set<String> = emptySet()

        /** Your own allow / block domains (each covers the domain and all of its subdomains). */
        fun user(allow: Set<String>, block: Set<String>) = apply { userAllow = allow; userBlock = block }

        fun build() = FilterIndex(labels, blockExact, blockSuffix, allowExact, allowSuffix, userAllow, userBlock, counts)
    }

    /** Same list rules, new user allow/block sets — no re-parsing. */
    fun withUser(allow: Set<String>, block: Set<String>) =
        FilterIndex(labels, blockExact, blockSuffix, allowExact, allowSuffix, allow, block, counts)

    companion object {
        const val USER_ALLOW = "user_allow"
        const val USER_BLOCK = "user_block"
        val EMPTY: FilterIndex = Builder().build()
    }
}
