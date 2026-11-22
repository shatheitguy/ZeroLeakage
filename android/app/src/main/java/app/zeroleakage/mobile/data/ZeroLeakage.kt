package app.zeroleakage.mobile.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.geo.GeoIp
import app.zeroleakage.mobile.vpn.DnssecStatus
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Single source of truth shared by the VPN service and the Compose UI.
 * Everything here is thread-safe: the VPN writes from IO threads, the UI collects StateFlows.
 */
object ZeroLeakage {

    val RESOLVERS = listOf(
        Resolver("cloudflare", "Cloudflare", "https://1.1.1.1/dns-query", "No-log · fastest anycast · DNSSEC", "Privacy"),
        Resolver("quad9", "Quad9", "https://dns.quad9.net/dns-query", "Malware filtering · Swiss · DNSSEC", "Security"),
        Resolver("mullvad", "Mullvad", "https://dns.mullvad.net/dns-query", "No-log · Swedish · DNSSEC", "Privacy"),
        Resolver("adguard", "AdGuard DNS", "https://dns.adguard-dns.com/dns-query", "Blocks ads & trackers upstream too", "Filtering"),
        Resolver("adguard_family", "AdGuard Family", "https://family.adguard-dns.com/dns-query", "Ads + adult content + safe search", "Filtering"),
        Resolver("cf_security", "Cloudflare Security", "https://security.cloudflare-dns.com/dns-query", "1.1.1.2 · blocks malware", "Security"),
        Resolver("cf_family", "Cloudflare Family", "https://family.cloudflare-dns.com/dns-query", "1.1.1.3 · malware + adult", "Filtering"),
        Resolver("google", "Google Public DNS", "https://dns.google/dns-query", "Fast & reliable · logs kept 24–48 h", "Mainstream"),
        Resolver("controld", "Control D (free)", "https://freedns.controld.com/p0", "Unfiltered · no-log · Canada", "Privacy"),
        Resolver("dnssb", "DNS.SB", "https://doh.dns.sb/dns-query", "No-log · Germany", "Privacy"),
    )
    const val CUSTOM_RESOLVER = "custom"

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

    private val _resolverId = MutableStateFlow(RESOLVERS.first().id)
    val resolverId: StateFlow<String> = _resolverId.asStateFlow()

    private val _customResolverUrl = MutableStateFlow("")
    val customResolverUrl: StateFlow<String> = _customResolverUrl.asStateFlow()

    /** Ask the resolver to validate DNSSEC and report it (AD bit). */
    private val _dnssec = MutableStateFlow(true)
    val dnssec: StateFlow<Boolean> = _dnssec.asStateFlow()

    /** Paranoid: refuse answers for domains that aren't DNSSEC-signed. Breaks much of the web. */
    private val _dnssecStrict = MutableStateFlow(false)
    val dnssecStrict: StateFlow<Boolean> = _dnssecStrict.asStateFlow()

    private val _startOnBoot = MutableStateFlow(false)
    val startOnBoot: StateFlow<Boolean> = _startOnBoot.asStateFlow()

    private val _onboarded = MutableStateFlow(false)
    val onboarded: StateFlow<Boolean> = _onboarded.asStateFlow()

    /** Apps the user tapped "Allow once" for — cleared whenever the shield restarts. */
    val allowedOnce: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /** Packages with an "Ask to connect" notification already showing. */
    val pendingPrompts: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun init(context: Context) {
        prefs = context.getSharedPreferences("zeroleakage", Context.MODE_PRIVATE)
        _mode.value = runCatching { ProtectionMode.valueOf(prefs.getString("mode", null) ?: "") }.getOrDefault(ProtectionMode.BALANCED)
        _resolverId.value = prefs.getString("resolver", null) ?: RESOLVERS.first().id
        _customResolverUrl.value = prefs.getString("custom_doh", "") ?: ""
        _dnssec.value = prefs.getBoolean("dnssec", true)
        _dnssecStrict.value = prefs.getBoolean("dnssec_strict", false)
        _startOnBoot.value = prefs.getBoolean("boot", false)
        _onboarded.value = prefs.getBoolean("onboarded", false)
        _rules.value = decodeRules(prefs.getString("rules", null))
        _stats.value = Stats(
            telemetryBlocked = prefs.getLong("s_tel", 0),
            trackersBlocked = prefs.getLong("s_trk", 0),
            appBlocks = prefs.getLong("s_app", 0),
            allowed = prefs.getLong("s_ok", 0),
            totalQueries = prefs.getLong("s_all", 0),
            dnssecChecked = prefs.getLong("s_dsc", 0),
            dnssecSecure = prefs.getLong("s_dss", 0),
            dnssecFailed = prefs.getLong("s_dsf", 0),
        )
        Filters.init(context, prefs)
        GeoIp.init(context)
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

    fun setResolver(id: String) {
        _resolverId.value = id
        prefs.edit().putString("resolver", id).apply()
    }

    fun resolver(): Resolver {
        if (_resolverId.value == CUSTOM_RESOLVER && _customResolverUrl.value.startsWith("https://")) {
            return Resolver(CUSTOM_RESOLVER, "Custom DoH", _customResolverUrl.value, _customResolverUrl.value, "Custom")
        }
        return RESOLVERS.firstOrNull { it.id == _resolverId.value } ?: RESOLVERS.first()
    }

    /** Saves and selects a custom DoH endpoint. Returns an error, or null on success. */
    fun setCustomResolver(raw: String): String? {
        val url = raw.trim()
        if (!url.startsWith("https://")) return "DoH endpoints must start with https://"
        if (runCatching { java.net.URL(url) }.isFailure) return "That URL isn't valid"
        _customResolverUrl.value = url
        prefs.edit().putString("custom_doh", url).apply()
        setResolver(CUSTOM_RESOLVER)
        return null
    }

    fun setDnssec(on: Boolean) {
        _dnssec.value = on
        if (!on) setDnssecStrict(false)
        prefs.edit().putBoolean("dnssec", on).apply()
    }

    fun setDnssecStrict(on: Boolean) {
        _dnssecStrict.value = on
        prefs.edit().putBoolean("dnssec_strict", on).apply()
    }

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
        _resolverId.value = RESOLVERS.first().id
        _dnssec.value = true
        _dnssecStrict.value = false
        allowedOnce.clear()
        Filters.restoreDefaults()
        prefs.edit()
            .remove("rules").remove("resolver").remove("dnssec").remove("dnssec_strict")
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

    // ───────────────────────── live data from the VPN ─────────────────────────
    /**
     * @param byFilter true when a filter list (or your blocklist) made the decision, so it counts as a
     *                 tracker/telemetry drop rather than an app-firewall drop.
     */
    fun record(verdict: Verdict, appLabel: String, pkg: String?, domain: String, category: String,
               byFilter: Boolean = false, detail: PacketDetail? = null) {
        val event = FeedEvent(feedIds.incrementAndGet(), System.currentTimeMillis(), verdict, appLabel, pkg, domain, category, detail)
        _feed.update { (listOf(event) + it).take(FEED_LIMIT) }
        _stats.update { s0 ->
            val s = s0.copy(totalQueries = s0.totalQueries + 1).let { d ->
                if (detail == null || !detail.dnssecRequested || detail.dnssec == DnssecStatus.NOT_CHECKED) d
                else d.copy(
                    dnssecChecked = d.dnssecChecked + 1,
                    dnssecSecure = d.dnssecSecure + if (detail.dnssec == DnssecStatus.SECURE) 1 else 0,
                    dnssecFailed = d.dnssecFailed + if (detail.dnssec == DnssecStatus.BOGUS) 1 else 0,
                )
            }
            when {
                verdict == Verdict.ALLOWED -> s.copy(allowed = s.allowed + 1)
                byFilter && category == "Telemetry" -> s.copy(telemetryBlocked = s.telemetryBlocked + 1)
                byFilter -> s.copy(trackersBlocked = s.trackersBlocked + 1)
                else -> s.copy(appBlocks = s.appBlocks + 1)
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
            .putLong("s_app", s.appBlocks).putLong("s_ok", s.allowed).putLong("s_all", s.totalQueries)
            .putLong("s_dsc", s.dnssecChecked).putLong("s_dss", s.dnssecSecure).putLong("s_dsf", s.dnssecFailed).apply()
        prefs.edit().putString("rules", encodeRules(_rules.value)).apply()
    }
}
