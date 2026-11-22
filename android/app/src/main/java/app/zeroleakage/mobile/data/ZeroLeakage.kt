package app.zeroleakage.mobile.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Single source of truth shared by the VPN service and the Compose UI.
 * Everything here is thread-safe: the VPN writes from IO threads, the UI collects StateFlows.
 */
object ZeroLeakage {

    val BLOCKLISTS = listOf(
        Blocklist("telemetry", "OS & OEM Telemetry", "Google, Samsung, Xiaomi, Huawei & Meta phone-home endpoints.", "blocklist_telemetry.txt", "Telemetry"),
        Blocklist("trackers", "Ad & Tracker Mesh", "Ad networks, attribution SDKs, pixels and fingerprinting.", "blocklist_trackers.txt", "Ad Tracker"),
        Blocklist("analytics", "App Analytics SDKs", "Crash reporters and product analytics: Sentry, Mixpanel, Amplitude…", "blocklist_analytics.txt", "Analytics"),
        Blocklist("malware", "Malware & Phishing", "Known stalkerware, cryptojacking and phishing hosts.", "blocklist_malware.txt", "Malware"),
    )

    val RESOLVERS = listOf(
        Resolver("cloudflare", "Cloudflare", "https://1.1.1.1/dns-query", "No-log · fastest anycast"),
        Resolver("quad9", "Quad9", "https://dns.quad9.net/dns-query", "Malware filtering · Swiss"),
        Resolver("mullvad", "Mullvad", "https://dns.mullvad.net/dns-query", "No-log · ad-blocking"),
    )

    private const val FEED_LIMIT = 300
    private lateinit var prefs: SharedPreferences
    private val feedIds = AtomicLong()

    private val _mode = MutableStateFlow(ProtectionMode.BALANCED)
    val mode: StateFlow<ProtectionMode> = _mode.asStateFlow()

    private val _vpnRunning = MutableStateFlow(false)
    val vpnRunning: StateFlow<Boolean> = _vpnRunning.asStateFlow()
    @Volatile var vpnStartedAt: Long = 0L
        private set

    private val _stats = MutableStateFlow(Stats())
    val stats: StateFlow<Stats> = _stats.asStateFlow()

    private val _feed = MutableStateFlow<List<FeedEvent>>(emptyList())
    val feed: StateFlow<List<FeedEvent>> = _feed.asStateFlow()

    private val _rules = MutableStateFlow<Map<String, AppRule>>(emptyMap())
    val rules: StateFlow<Map<String, AppRule>> = _rules.asStateFlow()

    private val _enabledLists = MutableStateFlow(setOf("telemetry", "trackers", "analytics", "malware"))
    val enabledLists: StateFlow<Set<String>> = _enabledLists.asStateFlow()

    private val _customDomains = MutableStateFlow<Set<String>>(emptySet())
    val customDomains: StateFlow<Set<String>> = _customDomains.asStateFlow()

    private val _resolverId = MutableStateFlow(RESOLVERS.first().id)
    val resolverId: StateFlow<String> = _resolverId.asStateFlow()

    private val _startOnBoot = MutableStateFlow(false)
    val startOnBoot: StateFlow<Boolean> = _startOnBoot.asStateFlow()

    private val _onboarded = MutableStateFlow(false)
    val onboarded: StateFlow<Boolean> = _onboarded.asStateFlow()

    /** Apps the user tapped "Allow once" for — cleared whenever the shield restarts. */
    val allowedOnce: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /** Packages with an "Ask to connect" notification already showing. */
    val pendingPrompts: MutableSet<String> = ConcurrentHashMap.newKeySet()

    private val domainSets = ConcurrentHashMap<String, Set<String>>()

    fun init(context: Context) {
        prefs = context.getSharedPreferences("zeroleakage", Context.MODE_PRIVATE)
        _mode.value = runCatching { ProtectionMode.valueOf(prefs.getString("mode", null) ?: "") }.getOrDefault(ProtectionMode.BALANCED)
        _enabledLists.value = prefs.getStringSet("lists", null)?.toSet() ?: _enabledLists.value
        _customDomains.value = prefs.getStringSet("custom", null)?.toSet() ?: emptySet()
        _resolverId.value = prefs.getString("resolver", null) ?: RESOLVERS.first().id
        _startOnBoot.value = prefs.getBoolean("boot", false)
        _onboarded.value = prefs.getBoolean("onboarded", false)
        _rules.value = decodeRules(prefs.getString("rules", null))
        _stats.value = Stats(
            telemetryBlocked = prefs.getLong("s_tel", 0),
            trackersBlocked = prefs.getLong("s_trk", 0),
            appBlocks = prefs.getLong("s_app", 0),
            allowed = prefs.getLong("s_ok", 0),
            totalQueries = prefs.getLong("s_all", 0),
        )
        // Load blocklists off the main thread.
        Thread { BLOCKLISTS.forEach { loadList(context, it) } }.start()
    }

    // ───────────────────────── settings ─────────────────────────
    fun setMode(mode: ProtectionMode) {
        _mode.value = mode
        allowedOnce.clear()
        prefs.edit().putString("mode", mode.name).apply()
    }

    fun setVpnRunning(running: Boolean) {
        if (running && !_vpnRunning.value) vpnStartedAt = System.currentTimeMillis()
        _vpnRunning.value = running
        if (!running) allowedOnce.clear()
    }

    fun setListEnabled(id: String, enabled: Boolean) {
        _enabledLists.update { if (enabled) it + id else it - id }
        prefs.edit().putStringSet("lists", _enabledLists.value).apply()
    }

    fun addCustomDomain(raw: String): String? {
        val d = normalizeDomain(raw) ?: return null
        _customDomains.update { it + d }
        prefs.edit().putStringSet("custom", _customDomains.value).apply()
        return d
    }

    fun removeCustomDomain(domain: String) {
        _customDomains.update { it - domain }
        prefs.edit().putStringSet("custom", _customDomains.value).apply()
    }

    fun setResolver(id: String) {
        _resolverId.value = id
        prefs.edit().putString("resolver", id).apply()
    }

    fun resolver(): Resolver = RESOLVERS.firstOrNull { it.id == _resolverId.value } ?: RESOLVERS.first()

    fun setStartOnBoot(value: Boolean) {
        _startOnBoot.value = value
        prefs.edit().putBoolean("boot", value).apply()
    }

    fun setOnboarded() {
        _onboarded.value = true
        prefs.edit().putBoolean("onboarded", true).apply()
    }

    fun restoreDefaults() {
        setMode(ProtectionMode.BALANCED)
        _rules.value = emptyMap()
        _customDomains.value = emptySet()
        _enabledLists.value = BLOCKLISTS.map { it.id }.toSet()
        _resolverId.value = RESOLVERS.first().id
        allowedOnce.clear()
        prefs.edit()
            .remove("rules").remove("custom").remove("lists").remove("resolver")
            .apply()
    }

    fun resetStats() {
        _stats.value = Stats(dohLatencyMs = _stats.value.dohLatencyMs)
        _feed.value = emptyList()
        persistStats()
    }

    // ───────────────────────── app rules ─────────────────────────
    fun rule(pkg: String): AppRule = _rules.value[pkg] ?: AppRule(pkg)

    fun updateRule(pkg: String, transform: (AppRule) -> AppRule) {
        _rules.update { it + (pkg to transform(it[pkg] ?: AppRule(pkg))) }
        prefs.edit().putString("rules", encodeRules(_rules.value)).apply()
    }

    private fun encodeRules(rules: Map<String, AppRule>): String = JSONArray().apply {
        rules.values.forEach {
            put(JSONObject().put("p", it.packageName).put("w", it.wifi).put("m", it.mobile)
                .put("a", it.approved).put("pin", it.pinned).put("b", it.blocked))
        }
    }.toString()

    private fun decodeRules(json: String?): Map<String, AppRule> {
        if (json.isNullOrBlank()) return emptyMap()
        return runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).associate { i ->
                val o = arr.getJSONObject(i)
                val pkg = o.getString("p")
                pkg to AppRule(pkg, o.optBoolean("w", true), o.optBoolean("m", true),
                    o.optBoolean("a", false), o.optBoolean("pin", false), o.optLong("b", 0))
            }
        }.getOrDefault(emptyMap())
    }

    // ───────────────────────── blocklists ─────────────────────────
    private fun loadList(context: Context, list: Blocklist) {
        val set = HashSet<String>()
        runCatching {
            context.assets.open(list.asset).bufferedReader().useLines { lines ->
                lines.map { it.substringBefore('#').trim().lowercase() }
                    .filter { it.isNotEmpty() }
                    .forEach { set.add(it.removePrefix("0.0.0.0 ").removePrefix("127.0.0.1 ").trim()) }
            }
        }
        domainSets[list.id] = set
    }

    fun listSize(id: String): Int = domainSets[id]?.size ?: 0

    /** Returns the category of the first matching list (domain or any parent domain), or null. */
    fun matchBlocklist(domain: String): String? {
        if (matchesSet(domain, _customDomains.value)) return "User Blocklist"
        val enabled = _enabledLists.value
        for (list in BLOCKLISTS) {
            if (list.id !in enabled) continue
            val set = domainSets[list.id] ?: continue
            if (matchesSet(domain, set)) return list.category
        }
        return null
    }

    private fun matchesSet(domain: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        var d = domain
        while (true) {
            if (d in set) return true
            val dot = d.indexOf('.')
            if (dot < 0 || dot == d.length - 1) return false
            d = d.substring(dot + 1)
            if (!d.contains('.')) return false   // never match a bare TLD
        }
    }

    fun normalizeDomain(raw: String): String? {
        var d = raw.trim().lowercase().removePrefix("http://").removePrefix("https://")
        d = d.substringBefore('/').substringBefore(':').trimEnd('.')
        return if (d.length > 3 && d.contains('.') && d.none { it.isWhitespace() }) d else null
    }

    // ───────────────────────── live data from the VPN ─────────────────────────
    fun record(verdict: Verdict, appLabel: String, pkg: String?, domain: String, category: String) {
        val event = FeedEvent(feedIds.incrementAndGet(), System.currentTimeMillis(), verdict, appLabel, pkg, domain, category)
        _feed.update { (listOf(event) + it).take(FEED_LIMIT) }
        _stats.update { s ->
            when {
                verdict == Verdict.ALLOWED -> s.copy(allowed = s.allowed + 1, totalQueries = s.totalQueries + 1)
                category == "Telemetry" -> s.copy(telemetryBlocked = s.telemetryBlocked + 1, totalQueries = s.totalQueries + 1)
                category in setOf("Ad Tracker", "Analytics", "Malware", "User Blocklist") ->
                    s.copy(trackersBlocked = s.trackersBlocked + 1, totalQueries = s.totalQueries + 1)
                else -> s.copy(appBlocks = s.appBlocks + 1, totalQueries = s.totalQueries + 1)
            }
        }
        if (verdict != Verdict.ALLOWED && pkg != null) {
            _rules.update { m -> m[pkg]?.let { m + (pkg to it.copy(blocked = it.blocked + 1)) } ?: m }
        }
        if (_stats.value.totalQueries % 25 == 0L) persistStats()
    }

    fun recordLatency(ms: Long) {
        _stats.update { s ->
            val ema = if (s.dohLatencyMs == 0) ms.toInt() else ((s.dohLatencyMs * 4 + ms) / 5).toInt()
            s.copy(dohLatencyMs = ema)
        }
    }

    fun persistStats() {
        val s = _stats.value
        prefs.edit().putLong("s_tel", s.telemetryBlocked).putLong("s_trk", s.trackersBlocked)
            .putLong("s_app", s.appBlocks).putLong("s_ok", s.allowed).putLong("s_all", s.totalQueries).apply()
        prefs.edit().putString("rules", encodeRules(_rules.value)).apply()
    }
}
