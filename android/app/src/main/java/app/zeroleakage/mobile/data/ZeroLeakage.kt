package app.zeroleakage.mobile.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
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

    /**
     * Everyday apps Strict Guard can approve in one tap: browsers, Google's core apps and the main messengers.
     * (Only ones actually installed are approved.)
     */
    val POPULAR_APPS = setOf(
        "com.android.chrome", "com.google.android.googlequicksearchbox", "com.google.android.youtube",
        "com.google.android.apps.youtube.music", "com.google.android.gm", "com.google.android.apps.maps",
        "com.android.vending", "com.google.android.apps.photos", "com.google.android.calendar",
        "com.google.android.apps.docs", "com.google.android.keep", "com.google.android.apps.messaging",
        "com.google.android.dialer", "com.google.android.contacts", "com.google.android.apps.translate",
        "com.google.android.apps.nbu.files", "com.google.android.apps.authenticator2",
        "org.mozilla.firefox", "com.brave.browser", "com.microsoft.emmx", "com.sec.android.app.sbrowser",
        "com.opera.browser", "com.duckduckgo.mobile.android",
        "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "org.thoughtcrime.securesms",
        "com.microsoft.teams", "com.microsoft.office.outlook", "us.zoom.videomeetings",
        "com.samsung.android.messaging", "com.samsung.android.dialer",
    )

    /** Approves many apps at once (Strict Guard quick setup). Returns how many changed. */
    fun approveApps(pkgs: Collection<String>): Int {
        var n = 0
        _rules.update { m ->
            val out = m.toMutableMap()
            for (p in pkgs) {
                val r = out[p] ?: AppRule(p)
                if (!r.approved) { out[p] = r.copy(approved = true, wifi = true, mobile = true); n++ }
            }
            out
        }
        prefs.edit().putString("rules", encodeRules(_rules.value)).apply()
        pkgs.forEach { promptQuietUntil.remove(it); pendingPrompts.remove(it); releaseDecision(it) }
        return n
    }

    /** Another VPN app (e.g. WireGuard) took the VPN slot, so the shield was switched off by Android. */
    private val _takenOver = MutableStateFlow(false)
    val takenOver: StateFlow<Boolean> = _takenOver.asStateFlow()
    fun setTakenOver(v: Boolean) {
        _takenOver.value = v
        prefs.edit().putBoolean("taken_over", v).apply()
    }

    /** Set by a notification tap: the UI turns the shield back on (with Android's consent prompt if needed). */
    private val _resumeRequested = MutableStateFlow(false)
    val resumeRequested: StateFlow<Boolean> = _resumeRequested.asStateFlow()
    fun requestResume(v: Boolean) { _resumeRequested.value = v }

    /** One-time dashboard tips the user has dismissed. */
    private val _dismissedTips = MutableStateFlow<Set<String>>(emptySet())
    val dismissedTips: StateFlow<Set<String>> = _dismissedTips.asStateFlow()
    fun dismissTip(id: String) {
        _dismissedTips.update { it + id }
        prefs.edit().putStringSet("tips_dismissed", _dismissedTips.value).apply()
    }

    /** The shield's required notification: quiet (silent, minimised, no icon) by default. */
    private val _quietNotification = MutableStateFlow(true)
    val quietNotification: StateFlow<Boolean> = _quietNotification.asStateFlow()

    fun setQuietNotification(on: Boolean) {
        _quietNotification.value = on
        prefs.edit().putBoolean("quiet_notif", on).apply()
    }

    private val _startOnBoot = MutableStateFlow(false)
    val startOnBoot: StateFlow<Boolean> = _startOnBoot.asStateFlow()

    private val _onboarded = MutableStateFlow(false)
    val onboarded: StateFlow<Boolean> = _onboarded.asStateFlow()

    /** FULL = local VPN shield (per-app firewall, feed). LITE = Android Private DNS only, no VPN. */
    enum class Method { FULL, LITE }
    private val _method = MutableStateFlow(Method.FULL)
    val method: StateFlow<Method> = _method.asStateFlow()
    private val _liteProvider = MutableStateFlow(PrivateDns.PROVIDERS.first().id)
    val liteProvider: StateFlow<String> = _liteProvider.asStateFlow()

    fun setMethod(m: Method) {
        _method.value = m
        prefs.edit().putString("method", m.name).apply()
    }

    fun setLiteProvider(id: String) {
        _liteProvider.value = id
        prefs.edit().putString("lite_provider", id).apply()
    }

    fun liteProvider(): PrivateDns.Provider = PrivateDns.PROVIDERS.firstOrNull { it.id == _liteProvider.value } ?: PrivateDns.PROVIDERS.first()

    /** When every encrypted resolver is unreachable, answer through the network's own DNS instead of failing. */
    private val _fallbackDns = MutableStateFlow(true)
    val fallbackDns: StateFlow<Boolean> = _fallbackDns.asStateFlow()

    /** Live health of the upstream DNS path, shown as a banner on the dashboard. */
    data class DnsHealth(val failing: Boolean = false, val fallback: Boolean = false, val error: String? = null,
                         val via: String? = null, val at: Long = 0)
    private val _dnsHealth = MutableStateFlow(DnsHealth())
    val dnsHealth: StateFlow<DnsHealth> = _dnsHealth.asStateFlow()

    /** Short confirmations ("Chrome allowed") shown as a snackbar in the app. */
    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages.asSharedFlow()
    fun say(message: String) { _messages.tryEmit(message) }

    /**
     * Lookups from an app that is waiting on an "Ask to connect" decision are held here (a few seconds)
     * so that tapping Allow answers them immediately: the page loads without a reload.
     */
    private val decisionWaiters = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
    fun decisionWaiter(pkg: String): CompletableDeferred<Unit> = decisionWaiters.getOrPut(pkg) { CompletableDeferred() }
    fun releaseDecision(pkg: String) { decisionWaiters.remove(pkg)?.complete(Unit) }

    fun allowOnce(pkg: String) {
        allowedOnce.add(pkg)
        pendingPrompts.remove(pkg)
        releaseDecision(pkg)
    }

    /** Apps the user tapped "Allow once" for — cleared whenever the shield restarts. */
    val allowedOnce: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /**
     * "Ask to connect" pacing: a package is not asked again before this time (epoch ms).
     * Shown prompt = 10 min; swiped away ("not now") = 1 h. Allow / Block clears it (no more prompts anyway).
     */
    val promptQuietUntil: ConcurrentHashMap<String, Long> = ConcurrentHashMap()

    fun canPrompt(pkg: String): Boolean = System.currentTimeMillis() >= (promptQuietUntil[pkg] ?: 0L)

    fun snoozePrompts(pkg: String, millis: Long) {
        promptQuietUntil[pkg] = System.currentTimeMillis() + millis
    }

    /** Packages with an "Ask to connect" notification already showing. */
    val pendingPrompts: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun init(context: Context) {
        prefs = context.getSharedPreferences("zeroleakage", Context.MODE_PRIVATE)
        _mode.value = runCatching { ProtectionMode.valueOf(prefs.getString("mode", null) ?: "") }.getOrDefault(ProtectionMode.BALANCED)
        _resolverId.value = prefs.getString("resolver", null) ?: RESOLVERS.first().id
        _customResolverUrl.value = prefs.getString("custom_doh", "") ?: ""
        _dnssec.value = prefs.getBoolean("dnssec", true)
        _dnssecStrict.value = prefs.getBoolean("dnssec_strict", false)
        _fallbackDns.value = prefs.getBoolean("fallback_dns", true)
        _method.value = runCatching { Method.valueOf(prefs.getString("method", null) ?: "") }.getOrDefault(Method.FULL)
        _liteProvider.value = prefs.getString("lite_provider", null) ?: PrivateDns.PROVIDERS.first().id
        _startOnBoot.value = prefs.getBoolean("boot", false)
        _quietNotification.value = prefs.getBoolean("quiet_notif", true)
        _takenOver.value = prefs.getBoolean("taken_over", false)
        _dismissedTips.value = prefs.getStringSet("tips_dismissed", null)?.toSet() ?: emptySet()
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
            byKind = BlockKind.entries.associateWith { prefs.getLong("s_k_" + it.name, 0) }.filterValues { it > 0 },
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
        if (running && _takenOver.value) setTakenOver(false)
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

    fun setFallbackDns(on: Boolean) {
        _fallbackDns.value = on
        prefs.edit().putBoolean("fallback_dns", on).apply()
    }

    fun reportDns(ok: Boolean, fallback: Boolean, error: String?, via: String?) {
        val next = DnsHealth(failing = !ok, fallback = fallback, error = error, via = via, at = System.currentTimeMillis())
        val cur = _dnsHealth.value
        // Only publish changes (or refresh a stale warning) so the UI isn't flooded on every lookup.
        if (cur.failing != next.failing || cur.fallback != next.fallback || cur.via != next.via ||
            (!ok || fallback) && next.at - cur.at > 5_000) _dnsHealth.value = next
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
        pendingPrompts.remove(pkg)
        promptQuietUntil.remove(pkg)
        releaseDecision(pkg)          // any lookup held for an "Ask to connect" decision re-checks now
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
        if (verdict != Verdict.ALLOWED) {
            val kind = BlockKind.of(category, byFilter)
            _stats.update { it.copy(byKind = it.byKind + (kind to ((it.byKind[kind] ?: 0) + 1))) }
        }
        if (verdict != Verdict.ALLOWED && pkg != null) {
            _rules.update { m -> m[pkg]?.let { m + (pkg to it.copy(blocked = it.blocked + 1)) } ?: m }
        }
        if (_stats.value.totalQueries % 200 == 0L) persistStats(saveRules = false)   // battery: few disk writes
    }

    fun recordLatency(ms: Long) {
        _stats.update { s ->
            val ema = if (s.dohLatencyMs == 0) ms.toInt() else ((s.dohLatencyMs * 4 + ms) / 5).toInt()
            s.copy(dohLatencyMs = ema)
        }
    }

    fun persistStats(saveRules: Boolean = true) {
        val s = _stats.value
        prefs.edit().putLong("s_tel", s.telemetryBlocked).putLong("s_trk", s.trackersBlocked)
            .putLong("s_app", s.appBlocks).putLong("s_ok", s.allowed).putLong("s_all", s.totalQueries)
            .putLong("s_dsc", s.dnssecChecked).putLong("s_dss", s.dnssecSecure).putLong("s_dsf", s.dnssecFailed)
            .apply { BlockKind.entries.forEach { putLong("s_k_" + it.name, s.byKind[it] ?: 0) } }
            .apply()
        if (saveRules) prefs.edit().putString("rules", encodeRules(_rules.value)).apply()
    }
}
