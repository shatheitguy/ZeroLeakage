package app.zeroleakage.mobile.data

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.zeroleakage.mobile.MainActivity
import app.zeroleakage.mobile.R
import app.zeroleakage.mobile.vpn.OtherVpnWatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.ln

/**
 * Guard: a small, local, CrowdSec-style protection layer on the phone. No account, no cloud.
 *
 *  1. Malicious-IP blocking: if a DNS answer points to an address on a public threat list
 *     (botnet C2, malware hosting, compromised hosts), the lookup is blocked.
 *  2. Behaviour alerts per app, from DNS patterns only:
 *     - DGA: lots of random names that don't exist (malware hunting for its control server),
 *     - tunnelling: long, random-looking subdomains used to smuggle data out through DNS,
 *     - infected: repeated hits on malware / phishing domains.
 *     You get a notification naming the app, with "Cut off app".
 */
object Guard {

    data class Feed(val id: String, val name: String, val url: String)

    /** Small, high-confidence lists (a few hundred KB in total), refreshed once a day. */
    val FEEDS = listOf(
        Feed("firehol1", "FireHOL Level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
        Feed("feodo", "abuse.ch Feodo Tracker (botnet C2)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
        Feed("et_compromised", "Emerging Threats compromised hosts", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    )

    data class Alert(val time: Long, val pkg: String?, val app: String, val scenario: String, val detail: String)
    data class Status(val enabled: Boolean = true, val ranges: Int = 0, val updatedAt: Long = 0, val error: String? = null)

    private lateinit var prefs: SharedPreferences
    private lateinit var dir: File
    private lateinit var app: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status.asStateFlow()
    private val _alerts = MutableStateFlow<List<Alert>>(emptyList())
    val alerts: StateFlow<List<Alert>> = _alerts.asStateFlow()

    // IPv4 threat ranges, merged and sorted: starts[i]..ends[i] (inclusive), with the feed index per range.
    @Volatile private var starts = LongArray(0)
    @Volatile private var ends = LongArray(0)
    @Volatile private var feedOf = IntArray(0)

    fun init(context: Context, sharedPrefs: SharedPreferences) {
        app = context.applicationContext
        prefs = sharedPrefs
        dir = File(app.filesDir, "guard").apply { mkdirs() }
        _status.update { it.copy(enabled = prefs.getBoolean("guard_on", true), updatedAt = prefs.getLong("guard_updated", 0)) }
        _alerts.value = decodeAlerts(prefs.getString("guard_alerts", null))
        scope.launch { load() }
    }

    fun setEnabled(on: Boolean) {
        _status.update { it.copy(enabled = on) }
        prefs.edit().putBoolean("guard_on", on).apply()
        if (on) refreshIfStale()
    }

    // ───────────────────────── threat feeds ─────────────────────────

    /** Called when the shield starts: downloads the lists if they're older than a day. */
    fun refreshIfStale(force: Boolean = false) {
        if (!::prefs.isInitialized || !_status.value.enabled) return
        val age = System.currentTimeMillis() - prefs.getLong("guard_updated", 0)
        if (!force && age < 24 * 3_600_000L && starts.isNotEmpty()) return
        scope.launch {
            var failures = 0
            for (f in FEEDS) {
                runCatching { download(f) }.onFailure { failures++ }
            }
            if (failures < FEEDS.size) prefs.edit().putLong("guard_updated", System.currentTimeMillis()).apply()
            load()
            _status.update {
                it.copy(updatedAt = prefs.getLong("guard_updated", 0),
                    error = if (failures == FEEDS.size) "Couldn't download threat lists" else null)
            }
        }
    }

    private fun download(f: Feed) {
        val conn = (URL(f.url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000; readTimeout = 30_000
            setRequestProperty("User-Agent", "ZeroLeakage-Guard")
        }
        try {
            if (conn.responseCode != 200) error("HTTP ${conn.responseCode}")
            val tmp = File(dir, f.id + ".tmp")
            conn.inputStream.use { input -> tmp.outputStream().use { input.copyTo(it) } }
            tmp.renameTo(File(dir, f.id + ".txt"))
        } finally {
            conn.disconnect()
        }
    }

    private fun load() {
        val ranges = ArrayList<Triple<Long, Long, Int>>()
        FEEDS.forEachIndexed { idx, f ->
            val file = File(dir, f.id + ".txt")
            if (!file.exists()) return@forEachIndexed
            file.forEachLine { raw ->
                parseRange(raw)?.let { (a, b) -> ranges += Triple(a, b, idx) }
            }
        }
        ranges.sortBy { it.first }
        // merge overlaps (keep the first feed's label)
        val s = ArrayList<Long>(ranges.size); val e = ArrayList<Long>(ranges.size); val fi = ArrayList<Int>(ranges.size)
        for ((a, b, idx) in ranges) {
            if (s.isNotEmpty() && a <= e.last() + 1) { if (b > e.last()) e[e.size - 1] = b }
            else { s += a; e += b; fi += idx }
        }
        starts = s.toLongArray(); ends = e.toLongArray(); feedOf = fi.toIntArray()
        _status.update { it.copy(ranges = starts.size) }
    }

    /** "1.2.3.4", "1.2.3.0/24", "1.2.3.4 ; comment" → inclusive IPv4 range; private/reserved space is skipped. */
    fun parseRange(raw: String): Pair<Long, Long>? {
        val line = raw.substringBefore('#').substringBefore(';').trim().split(' ', '\t').firstOrNull()?.trim() ?: return null
        if (line.isEmpty() || ':' in line) return null
        val ipPart = line.substringBefore('/')
        val prefix = if ('/' in line) line.substringAfter('/').toIntOrNull() ?: return null else 32
        if (prefix !in 8..32) return null                       // never accept huge /0–/7 blocks
        val ip = ipv4(ipPart) ?: return null
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        val start = ip and mask
        val end = start or (mask.inv() and 0xFFFFFFFFL)
        if (isPrivate(start) || isPrivate(end)) return null
        return start to end
    }

    private fun ipv4(s: String): Long? {
        val p = s.split('.')
        if (p.size != 4) return null
        var v = 0L
        for (x in p) { val n = x.toIntOrNull() ?: return null; if (n !in 0..255) return null; v = (v shl 8) or n.toLong() }
        return v
    }

    private fun isPrivate(v: Long): Boolean {
        val a = (v shr 24).toInt(); val b = ((v shr 16) and 0xFF).toInt()
        return a == 10 || a == 127 || a == 0 || (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
            (a == 169 && b == 254) || (a == 100 && b in 64..127) || a >= 224
    }

    /** The feed that lists [addr] (4-byte IPv4), or null. */
    fun threatFor(addr: ByteArray?): String? {
        if (!_status.value.enabled || addr == null || addr.size != 4) return null
        val s = starts
        if (s.isEmpty()) return null
        val v = ((addr[0].toLong() and 0xFF) shl 24) or ((addr[1].toLong() and 0xFF) shl 16) or
            ((addr[2].toLong() and 0xFF) shl 8) or (addr[3].toLong() and 0xFF)
        var lo = 0; var hi = s.size - 1; var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (s[mid] <= v) { found = mid; lo = mid + 1 } else hi = mid - 1
        }
        return if (found >= 0 && v <= ends[found]) FEEDS[feedOf[found]].name else null
    }

    // ───────────────────────── behaviour ─────────────────────────

    private class Window {
        var start = System.currentTimeMillis()
        var total = 0; var nx = 0; var malware = 0; var odd = 0
        val names = HashSet<String>()
        val oddParents = HashMap<String, Int>()
    }
    private val windows = ConcurrentHashMap<String, Window>()
    private val lastAlert = ConcurrentHashMap<String, Long>()
    private const val WINDOW_MS = 10 * 60_000L

    /** Feeds one finished lookup into the per-app behaviour window. Cheap: a few counters per query. */
    /** @param upstreamNx the resolver said the name doesn't exist. @param malware blocked as malware / malicious IP. */
    fun observe(pkg: String?, label: String, name: String, upstreamNx: Boolean, malware: Boolean) {
        if (!_status.value.enabled || pkg == null) return
        val w = windows.getOrPut(pkg) { Window() }
        synchronized(w) {
            val now = System.currentTimeMillis()
            if (now - w.start > WINDOW_MS) {
                w.start = now; w.total = 0; w.nx = 0; w.malware = 0; w.odd = 0; w.names.clear(); w.oddParents.clear()
            }
            w.total++
            if (w.names.size < 500) w.names.add(name)
            if (upstreamNx) w.nx++
            if (malware) w.malware++
            val first = name.substringBefore('.')
            if (first.length >= 40 && entropy(first) >= 3.8) {
                w.odd++
                val parent = name.substringAfter('.')
                w.oddParents[parent] = (w.oddParents[parent] ?: 0) + 1
            }
            when {
                w.malware >= 3 -> raise(pkg, label, "Possibly infected app",
                    "${w.malware} connections to known malware or phishing in 10 minutes.")
                w.total >= 30 && w.nx * 2 >= w.total && w.names.size >= 20 -> raise(pkg, label, "Malware-like lookups (DGA)",
                    "${w.nx} of ${w.total} lookups were random names that don't exist, typical of malware searching for its server.")
                (w.oddParents.values.maxOrNull() ?: 0) >= 15 -> raise(pkg, label, "Possible DNS tunnelling",
                    "Many long, random-looking subdomains of ${w.oddParents.maxByOrNull { it.value }?.key}: a way to sneak data out through DNS.")
            }
        }
    }

    private fun entropy(s: String): Double {
        val counts = IntArray(128)
        var n = 0
        for (c in s) if (c.code < 128) { counts[c.code]++; n++ }
        if (n == 0) return 0.0
        var h = 0.0
        for (k in counts) if (k > 0) { val p = k.toDouble() / n; h -= p * ln(p) / ln(2.0) }
        return h
    }

    private fun raise(pkg: String, label: String, scenario: String, detail: String) {
        val key = "$pkg/$scenario"
        val now = System.currentTimeMillis()
        if (now - (lastAlert[key] ?: 0) < 3_600_000L) return          // at most once an hour per app + scenario
        lastAlert[key] = now
        val alert = Alert(now, pkg, label, scenario, detail)
        _alerts.update { (listOf(alert) + it).take(50) }
        prefs.edit().putString("guard_alerts", encodeAlerts(_alerts.value)).apply()
        notify(alert)
    }

    fun clearAlerts() {
        _alerts.value = emptyList()
        prefs.edit().remove("guard_alerts").apply()
    }

    private fun notify(a: Alert) {
        if (ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val id = 20_000 + ((a.pkg ?: a.app).hashCode() and 0xFFFF)
        val open = PendingIntent.getActivity(app, id, Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE)
        val cut = PendingIntent.getBroadcast(app, id, Intent(app, GuardActionReceiver::class.java).putExtra("pkg", a.pkg).putExtra("id", id),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(app, OtherVpnWatcher.CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(0xFFFF2E54.toInt())
            .setContentTitle("Guard: ${a.scenario} in ${a.app}")
            .setContentText(a.detail)
            .setStyle(NotificationCompat.BigTextStyle().bigText(a.detail + "\nCut it off if you don't trust this app."))
            .setContentIntent(open)
            .addAction(0, "Cut off app", cut)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(app).notify(id, n)
    }

    private fun encodeAlerts(list: List<Alert>) = JSONArray().apply {
        list.forEach { put(JSONObject().put("t", it.time).put("p", it.pkg).put("a", it.app).put("s", it.scenario).put("d", it.detail)) }
    }.toString()

    private fun decodeAlerts(json: String?): List<Alert> = runCatching {
        val arr = JSONArray(json ?: return emptyList())
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Alert(o.getLong("t"), o.optString("p").ifBlank { null }, o.getString("a"), o.getString("s"), o.getString("d"))
        }
    }.getOrDefault(emptyList())
}

/** "Cut off app" from a Guard alert: blocks the app on Wi-Fi and mobile data. */
class GuardActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.getStringExtra("pkg") ?: return
        ZeroLeakage.updateRule(pkg) { it.copy(wifi = false, mobile = false, approved = false, pinned = false) }
        NotificationManagerCompat.from(context).cancel(intent.getIntExtra("id", 0))
        ZeroLeakage.say("App cut off from the network")
    }
}
