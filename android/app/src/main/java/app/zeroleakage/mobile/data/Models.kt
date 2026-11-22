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
)

data class Blocklist(
    val id: String,
    val name: String,
    val description: String,
    val asset: String,
    val category: String,
)

data class Resolver(val id: String, val name: String, val url: String, val note: String)

data class InstalledApp(val packageName: String, val label: String, val isSystem: Boolean)
