package app.zeroleakage.mobile.geo

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Calendar
import java.util.Locale
import java.util.zip.GZIPInputStream

data class GeoDbState(
    val installed: Boolean = false,
    val source: String = "",
    val ranges: Int = 0,
    val sizeBytes: Long = 0,
    val updatedAt: Long = 0,
    val busy: Boolean = false,
    val progress: String? = null,
    val error: String? = null,
)

/**
 * Offline IP → country lookup. The database is downloaded only when the user asks for it
 * (DB-IP "IP to Country Lite", CC BY 4.0), converted to a compact binary table, and every lookup
 * afterwards happens on the phone — no IP address is ever sent to a geolocation service.
 */
object GeoIp {

    private const val TAG = "ZlGeoIp"
    const val ATTRIBUTION = "IP geolocation by DB-IP.com (CC BY 4.0)"
    const val ATTRIBUTION_URL = "https://db-ip.com"

    private lateinit var file: File
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var table: GeoTable? = null

    private val _state = MutableStateFlow(GeoDbState())
    val state: StateFlow<GeoDbState> = _state.asStateFlow()

    fun init(context: Context) {
        file = File(File(context.filesDir, "geoip").apply { mkdirs() }, "country.bin")
        if (file.exists()) scope.launch { load() }
    }

    /** Country for [ip] (4 or 16 bytes). Special ranges resolve even without the database; otherwise null. */
    fun lookup(ip: ByteArray): GeoInfo? = GeoTable.special(ip) ?: table?.lookup(ip)

    fun lookup(ip: String): GeoInfo? = GeoTable.parseIp(ip)?.let { lookup(it) }

    private fun load() {
        runCatching {
            val t = file.inputStream().use { GeoTable.read(it) }
            table = t
            _state.value = GeoDbState(true, t.builtFrom, t.size, file.length(), file.lastModified())
        }.onFailure {
            Log.w(TAG, "GeoIP file unreadable", it)
            file.delete()
            _state.value = GeoDbState(error = "Database file was corrupt — download it again")
        }
    }

    fun delete() {
        table = null
        file.delete()
        _state.value = GeoDbState()
    }

    fun download() {
        if (_state.value.busy) return
        _state.value = _state.value.copy(busy = true, progress = "Connecting…", error = null)
        scope.launch {
            val cal = Calendar.getInstance()
            var lastError: String? = null
            // DB-IP publishes monthly; early in a month the new file may not exist yet.
            for (back in 0..2) {
                val c = (cal.clone() as Calendar).apply { add(Calendar.MONTH, -back) }
                val stamp = String.format(Locale.US, "%04d-%02d", c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1)
                val url = "https://download.db-ip.com/free/dbip-country-lite-$stamp.csv.gz"
                try {
                    fetch(url, "DB-IP Country Lite $stamp")
                    return@launch
                } catch (e: Exception) {
                    Log.w(TAG, "GeoIP $stamp failed", e)
                    lastError = e.message ?: e.javaClass.simpleName
                }
            }
            _state.value = _state.value.copy(busy = false, progress = null, error = lastError ?: "Download failed")
        }
    }

    private fun fetch(url: String, source: String) {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            setRequestProperty("User-Agent", "ZeroLeakage-Android")
        }
        try {
            if (conn.responseCode != 200) error("HTTP ${conn.responseCode}")
            val builder = GeoTable.Builder(source)
            var lines = 0
            GZIPInputStream(conn.inputStream, 1 shl 16).bufferedReader().useLines { seq ->
                for (line in seq) {
                    builder.addCsvLine(line)
                    if (++lines % 50_000 == 0) {
                        _state.value = _state.value.copy(progress = "Indexing ${lines / 1000}K ranges…")
                    }
                }
            }
            val t = builder.build()
            if (t.size < 10_000) error("Database looks incomplete ($lines lines)")
            val tmp = File(file.parentFile, "country.tmp")
            tmp.outputStream().use { t.write(it) }
            file.delete()
            tmp.renameTo(file)
            table = t
            _state.value = GeoDbState(true, source, t.size, file.length(), System.currentTimeMillis())
        } finally {
            conn.disconnect()
        }
    }
}
