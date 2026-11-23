package app.zeroleakage.mobile.filters

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** Download / rule state of one filter list. */
data class ListStatus(
    val rules: Int = 0,
    val updatedAt: Long = 0,
    val bytes: Long = 0,
    val downloading: Boolean = false,
    val error: String? = null,
)

/**
 * Filter subscriptions (AdGuard-style), user allow/block lists and the live [FilterIndex] the VPN queries.
 * Lists are downloaded into `filesDir/filters/<id>.txt`; the index is rebuilt off the main thread whenever
 * the enabled set or a list file changes, and swapped in atomically.
 */
object Filters {

    private const val TAG = "ZlFilters"
    private const val MAX_BYTES = 64L * 1024 * 1024
    const val AUTO_UPDATE_MS = 3L * 24 * 60 * 60 * 1000

    private lateinit var app: Context
    private lateinit var prefs: SharedPreferences
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val rebuilds = Channel<Unit>(Channel.CONFLATED)

    private val _lists = MutableStateFlow(FilterCatalog.LISTS)
    val lists: StateFlow<List<FilterList>> = _lists.asStateFlow()

    private val _enabled = MutableStateFlow(FilterCatalog.DEFAULT_ON)
    val enabled: StateFlow<Set<String>> = _enabled.asStateFlow()

    private val _status = MutableStateFlow<Map<String, ListStatus>>(emptyMap())
    val status: StateFlow<Map<String, ListStatus>> = _status.asStateFlow()

    private val _userBlock = MutableStateFlow<Set<String>>(emptySet())
    val userBlock: StateFlow<Set<String>> = _userBlock.asStateFlow()

    private val _userAllow = MutableStateFlow<Set<String>>(emptySet())
    val userAllow: StateFlow<Set<String>> = _userAllow.asStateFlow()

    private val _totalRules = MutableStateFlow(0)
    val totalRules: StateFlow<Int> = _totalRules.asStateFlow()

    private val _rebuilding = MutableStateFlow(false)
    val rebuilding: StateFlow<Boolean> = _rebuilding.asStateFlow()

    @Volatile private var index: FilterIndex = FilterIndex.EMPTY

    fun init(context: Context, sharedPrefs: SharedPreferences) {
        app = context.applicationContext
        prefs = sharedPrefs
        _lists.value = FilterCatalog.LISTS + decodeCustom(prefs.getString("custom_lists", null))
        _enabled.value = prefs.getStringSet("lists", null)?.toSet() ?: FilterCatalog.defaultsForDevice()
        // One-time privacy upgrade for existing installs: add the stronger anti-tracking defaults
        // (EasyPrivacy, TikTok + phone-maker telemetry lists). Lists you switched off later stay off.
        if (!prefs.getBoolean("privacy_defaults_v2", false)) {
            _enabled.value = _enabled.value + (FilterCatalog.defaultsForDevice() - FilterCatalog.DEFAULT_ON) + "easyprivacy"
            prefs.edit().putStringSet("lists", _enabled.value).putBoolean("privacy_defaults_v2", true).apply()
        }
        _userBlock.value = prefs.getStringSet("custom", null)?.toSet() ?: emptySet()
        _userAllow.value = prefs.getStringSet("allow", null)?.toSet() ?: emptySet()
        _status.value = decodeMeta(prefs.getString("filter_meta", null)).mapValues { (id, s) ->
            s.copy(bytes = fileFor(id).takeIf { it.exists() }?.length() ?: 0)
        }
        scope.launch { for (u in rebuilds) rebuildNow() }
        requestRebuild()
        // Fetch enabled lists that were never downloaded (e.g. AdGuard DNS filter on first run).
        scope.launch { enabledMissing().forEach { download(it) } }
    }

    // ───────────────────────── matching ─────────────────────────
    fun match(domain: String): FilterMatch? = index.match(domain)

    // ───────────────────────── subscriptions ─────────────────────────
    /** Lists and blocked domains enforced by your server's admin (linked devices only): can't be weakened here. */
    @Volatile var lockedLists: Set<String> = emptySet()
    @Volatile var lockedBlock: Set<String> = emptySet()

    /** True when [domain] (or a parent) is blocked by your server's admin. */
    fun blockedByAdmin(domain: String): Boolean {
        var d = domain.lowercase().trimEnd('.')
        while (true) {
            if (d in lockedBlock) return true
            val dot = d.indexOf('.')
            if (dot < 0 || dot == d.length - 1) return false
            d = d.substring(dot + 1)
            if (!d.contains('.')) return false
        }
    }

    fun setEnabled(id: String, on: Boolean) {
        if (!on && id in lockedLists) return          // set by your admin
        _enabled.update { if (on) it + id else it - id }
        onListChange?.invoke()
        prefs.edit().putStringSet("lists", _enabled.value).apply()
        val list = _lists.value.firstOrNull { it.id == id }
        if (on && list != null && !list.isBundled && !fileFor(id).exists()) {
            scope.launch { download(list) }
        } else {
            requestRebuild()
        }
    }

    fun update(id: String) {
        val list = _lists.value.firstOrNull { it.id == id } ?: return
        if (!list.isBundled) scope.launch { download(list) }
    }

    /** Re-downloads every enabled remote list. */
    fun updateAll() {
        scope.launch { enabledRemote().forEach { download(it, rebuild = false) }; requestRebuild() }
    }

    /** Called when the shield starts: refreshes enabled lists older than 3 days. */
    fun autoUpdate() {
        val now = System.currentTimeMillis()
        scope.launch {
            val stale = enabledRemote().filter { now - (_status.value[it.id]?.updatedAt ?: 0) > AUTO_UPDATE_MS }
            stale.forEach { download(it, rebuild = false) }
            if (stale.isNotEmpty()) requestRebuild()
        }
    }

    /** Adds a custom filter subscription. Returns an error message, or null on success. */
    fun addCustom(rawUrl: String, rawName: String): String? {
        val url = rawUrl.trim()
        if (!url.startsWith("https://")) return "Use an https:// URL (plain http lists could be tampered with on the way)"
        if (runCatching { URL(url) }.isFailure) return "That URL isn't valid"
        if (_lists.value.any { it.url == url }) return "That list is already in the catalog"
        val id = "custom_" + Integer.toHexString(url.hashCode())
        val name = rawName.trim().ifEmpty { URL(url).host }
        val list = FilterList(id, name, url, FilterCatalog.G_CUSTOM, "Custom List", url = url, custom = true)
        _lists.update { it + list }
        persistCustom()
        setEnabled(id, true)
        return null
    }

    fun removeCustom(id: String) {
        _lists.update { l -> l.filterNot { it.id == id && it.custom } }
        persistCustom()
        _enabled.update { it - id }
        prefs.edit().putStringSet("lists", _enabled.value).apply()
        fileFor(id).delete()
        _status.update { it - id }
        persistMeta()
        requestRebuild()
    }

    // ───────────────────────── your own allow / block lists ─────────────────────────
    fun block(raw: String): String? {
        val d = normalize(raw) ?: return null
        _userBlock.update { it + d }
        _userAllow.update { it - d }
        persistUser()
        return d
    }

    fun unblock(domain: String) { _userBlock.update { it - domain }; persistUser() }

    fun allow(raw: String): String? {
        val d = normalize(raw) ?: return null
        if (blockedByAdmin(d)) return null           // your admin blocked it; users can't unblock
        _userAllow.update { it + d }
        _userBlock.update { it - d }
        persistUser()
        return d
    }

    fun unallow(domain: String) { _userAllow.update { it - domain }; persistUser() }

    fun restoreDefaults() {
        _enabled.value = FilterCatalog.defaultsForDevice()
        _userBlock.value = emptySet()
        _userAllow.value = emptySet()
        prefs.edit().remove("lists").remove("custom").remove("allow").apply()
        requestRebuild()
        scope.launch { enabledMissing().forEach { download(it) } }
    }

    private fun persistUser(notify: Boolean = true) {
        prefs.edit().putStringSet("custom", _userBlock.value).putStringSet("allow", _userAllow.value).apply()
        index = index.withUser(_userAllow.value, _userBlock.value)    // instant, no re-parse
        if (notify) onUserChange?.invoke()
    }

    // ───────────────────────── server sync (exact clone) ─────────────────────────
    /** Called after you edit your own allow / block lists, so a linked device can push the change. */
    @Volatile var onUserChange: (() -> Unit)? = null
    /** Called after you switch a filter list on or off. */
    @Volatile var onListChange: (() -> Unit)? = null

    /** Replaces your allow / block lists with the server's (no push back). */
    fun replaceUser(allow: Set<String>, block: Set<String>) {
        _userAllow.value = allow.mapNotNull { normalize(it) }.toSet()
        _userBlock.value = block.mapNotNull { normalize(it) }.toSet() - _userAllow.value
        persistUser(notify = false)
    }

    /** Makes the enabled lists exactly [ids] (ids this app doesn't know are ignored). */
    fun setEnabledExact(ids: Set<String>) {
        val known = _lists.value.map { it.id }.toSet()
        val next = ids.filter { it in known }.toSet()
        if (next == _enabled.value) return
        _enabled.value = next
        prefs.edit().putStringSet("lists", next).apply()
        scope.launch { enabledMissing().forEach { download(it) } }
        requestRebuild()
    }

    /** Makes the custom lists match the server's (by URL); returns the ids they have here. */
    fun syncCustomLists(lists: List<Pair<String, String>>): Set<String> {
        val wanted = lists.filter { it.second.startsWith("https://") }
        val wantedUrls = wanted.map { it.second }.toSet()
        _lists.value.filter { it.custom && it.url !in wantedUrls }.forEach { removeCustom(it.id) }
        for ((name, url) in wanted) if (_lists.value.none { it.url == url }) addCustom(url, name)
        return _lists.value.filter { it.custom && it.url in wantedUrls }.map { it.id }.toSet()
    }

    fun normalize(raw: String): String? {
        var d = raw.trim().lowercase().removePrefix("http://").removePrefix("https://")
        d = d.removePrefix("||").substringBefore('^').substringBefore('/').substringBefore(':').trimEnd('.')
        return FilterParser.cleanDomain(d)
    }

    // ───────────────────────── download ─────────────────────────
    private fun fileFor(id: String) = File(File(app.filesDir, "filters").apply { mkdirs() }, "$id.txt")

    private fun enabledRemote() = _lists.value.filter { it.id in _enabled.value && !it.isBundled && it.url != null }
    private fun enabledMissing() = enabledRemote().filter { !fileFor(it.id).exists() }

    private fun setStatus(id: String, f: (ListStatus) -> ListStatus) =
        _status.update { it + (id to f(it[id] ?: ListStatus())) }

    private fun download(list: FilterList, rebuild: Boolean = true) {
        val url = list.url ?: return
        setStatus(list.id) { it.copy(downloading = true, error = null) }
        val target = fileFor(list.id)
        val tmp = File(target.parentFile, "${list.id}.tmp")
        try {
            var conn = URL(url).openConnection() as HttpURLConnection
            var redirects = 0
            while (true) {
                conn.connectTimeout = 15_000
                conn.readTimeout = 60_000
                conn.instanceFollowRedirects = true
                conn.setRequestProperty("User-Agent", "ZeroLeakage-Android")
                val code = conn.responseCode
                if (code in 301..308 && redirects < 5) {          // also follow http→https hops
                    val next = conn.getHeaderField("Location") ?: break
                    conn.disconnect()
                    conn = URL(URL(url), next).openConnection() as HttpURLConnection
                    redirects++
                    continue
                }
                if (code != 200) error("HTTP $code")
                break
            }
            var total = 0L
            conn.inputStream.use { input ->
                tmp.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_BYTES) error("List is larger than 64 MB")
                        out.write(buf, 0, n)
                    }
                }
            }
            conn.disconnect()
            val rules = tmp.bufferedReader().useLines { s -> s.count { FilterParser.parseLine(it) != null } }
            if (rules == 0) error("No usable DNS rules in this list")
            if (!tmp.renameTo(target)) { target.delete(); tmp.renameTo(target) }
            setStatus(list.id) { ListStatus(rules = rules, updatedAt = System.currentTimeMillis(), bytes = total) }
            persistMeta()
            if (rebuild) requestRebuild()
        } catch (e: Exception) {
            Log.w(TAG, "download ${list.id} failed", e)
            tmp.delete()
            setStatus(list.id) { it.copy(downloading = false, error = e.message ?: e.javaClass.simpleName) }
        }
    }

    // ───────────────────────── index ─────────────────────────
    fun requestRebuild() { rebuilds.trySend(Unit) }

    private fun rebuildNow() {
        _rebuilding.value = true
        try {
            val b = FilterIndex.Builder()
            val enabledIds = _enabled.value
            for (list in _lists.value) {
                if (list.id !in enabledIds) continue
                val label = ListLabel(list.id, list.name, list.category)
                val count = when {
                    list.asset != null -> runCatching {
                        app.assets.open(list.asset).bufferedReader().useLines { b.addList(label, it, plainIsSuffix = true) }
                    }.getOrDefault(0)
                    fileFor(list.id).exists() -> runCatching {
                        fileFor(list.id).bufferedReader().useLines { b.addList(label, it) }
                    }.getOrDefault(0)
                    else -> continue
                }
                setStatus(list.id) { it.copy(rules = count) }
            }
            b.user(_userAllow.value, _userBlock.value)
            val built = b.build()
            index = built
            _totalRules.value = built.totalRules
        } catch (oom: OutOfMemoryError) {
            Log.e(TAG, "Out of memory building filter index — too many large lists enabled", oom)
            index = FilterIndex.EMPTY.withUser(_userAllow.value, _userBlock.value)
            _totalRules.value = 0
        } finally {
            _rebuilding.value = false
        }
    }

    // ───────────────────────── persistence ─────────────────────────
    private fun persistCustom() {
        val arr = JSONArray()
        _lists.value.filter { it.custom }.forEach { arr.put(JSONObject().put("id", it.id).put("n", it.name).put("u", it.url)) }
        prefs.edit().putString("custom_lists", arr.toString()).apply()
    }

    private fun decodeCustom(json: String?): List<FilterList> = runCatching {
        val arr = JSONArray(json ?: return emptyList())
        (0 until arr.length()).map {
            val o = arr.getJSONObject(it)
            val url = o.getString("u")
            FilterList(o.getString("id"), o.getString("n"), url, FilterCatalog.G_CUSTOM, "Custom List", url = url, custom = true)
        }
    }.getOrDefault(emptyList())

    private fun persistMeta() {
        val o = JSONObject()
        _status.value.forEach { (id, s) -> if (s.updatedAt > 0) o.put(id, JSONObject().put("t", s.updatedAt).put("r", s.rules)) }
        prefs.edit().putString("filter_meta", o.toString()).apply()
    }

    private fun decodeMeta(json: String?): Map<String, ListStatus> = runCatching {
        val o = JSONObject(json ?: return emptyMap())
        o.keys().asSequence().associateWith { k ->
            val v = o.getJSONObject(k)
            ListStatus(rules = v.optInt("r"), updatedAt = v.optLong("t"))
        }
    }.getOrDefault(emptyMap())
}
