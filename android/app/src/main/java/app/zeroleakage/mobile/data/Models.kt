package app.zeroleakage.mobile.data

enum class ProtectionMode(val number: Int, val title: String, val short: String, val description: String) {
    BALANCED(
        1, "Balanced Shield", "BALANCED",
        "Telemetry, ad trackers and analytics SDKs are silently dropped. Your apps keep working exactly as before.",
    ),
    STRICT(
        2, "Strict Guard", "STRICT GUARD",
        "Everything in Balanced, plus default-deny: any app you haven't approved must ask before it can resolve a single domain.",
    ),
    LOCKDOWN(
        3, "Total Zero-Leak", "TOTAL ZERO-LEAK",
        "Hard lockdown. Only apps you pin may reach the internet — every other lookup on the device is dropped.",
    ),
}

enum class Verdict { BLOCKED, ALLOWED, PROMPT }

data class FeedEvent(
    val id: Long,
    val time: Long,
    val verdict: Verdict,
    val appLabel: String,
    val packageName: String?,
    val domain: String,
    val category: String,
    val detail: PacketDetail? = null,
)

/** Everything the packet inspector shows for one DNS transaction. */
data class PacketDetail(
    // who
    val uid: Int,
    val network: String,
    // query packet (app → shield)
    val srcIp: String, val srcPort: Int,
    val dstIp: String, val dstPort: Int,
    val ipTtl: Int, val ipId: Int, val ipTotalLen: Int, val udpLen: Int, val udpChecksum: Int,
    val txId: Int,
    val qtype: Int, val qclass: Int,
    val queryFlags: String,
    val queryEdns: String?,
    val querySize: Int,
    // decision
    val ruleList: String?, val rule: String?, val ruleMatched: String?,
    // upstream
    val resolverName: String?, val resolverUrl: String?,
    val dnssecRequested: Boolean,
    val dnssec: app.zeroleakage.mobile.vpn.DnssecStatus,
    val cached: Boolean,
    val latencyMs: Long?,
    val error: String?,
    // response packet (shield → app)
    val rcode: Int,
    val responseFlags: String,
    val responseSize: Int,
    val answers: List<app.zeroleakage.mobile.vpn.DnsRecord>,
    val authority: List<app.zeroleakage.mobile.vpn.DnsRecord>,
    val ede: String?,
    val queryBytes: ByteArray,
    val responseBytes: ByteArray,
)

/** Per-app firewall rule. Absent rule = defaults (all networks allowed, not approved, not pinned). */
data class AppRule(
    val packageName: String,
    val wifi: Boolean = true,
    val mobile: Boolean = true,
    val approved: Boolean = false,
    val pinned: Boolean = false,
    val blocked: Long = 0,
) {
    val isKilled: Boolean get() = !wifi && !mobile
}

data class Stats(
    val telemetryBlocked: Long = 0,
    val trackersBlocked: Long = 0,
    val appBlocks: Long = 0,
    val allowed: Long = 0,
    val totalQueries: Long = 0,
    val dohLatencyMs: Int = 0,
    val dnssecChecked: Long = 0,
    val dnssecSecure: Long = 0,
    val dnssecFailed: Long = 0,
    /** Blocked lookups per kind (see [BlockKind]), since the counters were last reset. */
    val byKind: Map<BlockKind, Long> = emptyMap(),
) {
    val totalBlocked: Long get() = byKind.values.sum()
    val dnssecPercent: Int get() = if (dnssecChecked == 0L) 0 else ((dnssecSecure * 100) / dnssecChecked).toInt()
}

/** What a blocked lookup was, for the dashboard breakdown. */
enum class BlockKind(val title: String, val explain: String) {
    TRACKERS("Ads & trackers", "Ad networks, analytics SDKs, tracking pixels"),
    TELEMETRY("Telemetry", "Phone-home from Android, Google, Samsung, Xiaomi, Meta…"),
    MALWARE("Malware, phishing & scams", "Virus, phishing, scam and crypto-mining sites"),
    PARENTAL("Adult, gambling & social", "Parental-control lists you enabled"),
    USER("Your blocklist", "Domains you blocked yourself"),
    APPS("App firewall", "Strict Guard, lockdown and per-app kill switches"),
    DNSSEC("DNSSEC failures", "Answers that failed signature checks (possible spoofing)");

    companion object {
        /** Maps a feed category to a kind (null = not a block). */
        fun of(category: String, byFilter: Boolean): BlockKind = when {
            category.startsWith("DNSSEC") -> DNSSEC
            category == "User Blocklist" -> USER
            category == "Telemetry" -> TELEMETRY
            category == "Malware" -> MALWARE
            category in setOf("Adult", "Gambling", "Social") -> PARENTAL
            byFilter -> TRACKERS
            else -> APPS
        }
    }
}

data class Resolver(val id: String, val name: String, val url: String, val note: String, val group: String = "Privacy")

data class InstalledApp(val packageName: String, val label: String, val isSystem: Boolean)
