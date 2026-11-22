package app.zeroleakage.mobile.data

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * "Check for updates": asks GitHub for the latest ZeroLeakage release and compares it with this build.
 * Sends nothing about you: a plain GET with a generic User-Agent. The download opens in your browser,
 * so Android's own installer verifies and installs it.
 */
object Updates {
    private const val API = "https://api.github.com/repos/shatheitguy/ZeroLeakage/releases/latest"
    const val RELEASES_PAGE = "https://github.com/shatheitguy/ZeroLeakage/releases"
    const val WEBSITE = "https://shatheitguy.github.io/ZeroLeakage/"
    const val SOURCE = "https://github.com/shatheitguy/ZeroLeakage"

    data class Release(val version: String, val notes: String, val apkUrl: String?, val apkSize: Long, val pageUrl: String)

    sealed interface State {
        data object Idle : State
        data object Checking : State
        data class UpToDate(val current: String, val checkedAt: Long) : State
        data class Available(val current: String, val release: Release) : State
        data class Failed(val message: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    fun currentVersion(context: Context): String = runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName
    }.getOrNull() ?: "0"

    fun versionCode(context: Context): Long = runCatching {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }.getOrDefault(0)

    /** Checks at most once a day on its own; [force] for the "Check now" button. */
    suspend fun check(context: Context, force: Boolean = false): State {
        val prefs = context.getSharedPreferences("zeroleakage", Context.MODE_PRIVATE)
        if (!force && System.currentTimeMillis() - prefs.getLong("update_checked", 0) < 24 * 3_600_000L && _state.value !is State.Idle) {
            return _state.value
        }
        _state.value = State.Checking
        val current = currentVersion(context)
        val result = withContext(Dispatchers.IO) {
            runCatching { fetch() }.fold(
                onSuccess = { r ->
                    if (isNewer(r.version, current)) State.Available(current, r)
                    else State.UpToDate(current, System.currentTimeMillis())
                },
                onFailure = { State.Failed(it.message ?: "Couldn't reach GitHub") },
            )
        }
        if (result !is State.Failed) prefs.edit().putLong("update_checked", System.currentTimeMillis()).apply()
        _state.value = result
        return result
    }

    fun lastChecked(prefs: SharedPreferences): Long = prefs.getLong("update_checked", 0)

    private fun fetch(): Release {
        val conn = (URL(API).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 8_000
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "ZeroLeakage-Updater")
        }
        try {
            if (conn.responseCode != 200) error("GitHub answered HTTP ${conn.responseCode}")
            val json = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
            val tag = json.optString("tag_name").removePrefix("v").ifBlank { error("No release found") }
            val assets = json.optJSONArray("assets")
            var apkUrl: String? = null
            var size = 0L
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.getJSONObject(i)
                    if (a.optString("name").endsWith("-release.apk")) {
                        apkUrl = a.optString("browser_download_url"); size = a.optLong("size"); break
                    }
                }
            }
            return Release(tag, json.optString("body").trim(), apkUrl, size, json.optString("html_url", RELEASES_PAGE))
        } finally {
            conn.disconnect()
        }
    }

    /** Numeric, dot-separated comparison: 1.10.0 > 1.9.3. */
    fun isNewer(candidate: String, current: String): Boolean {
        fun parts(v: String) = v.split('.', '-').mapNotNull { it.toIntOrNull() }
        val a = parts(candidate); val b = parts(current)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }; val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    fun open(context: Context, url: String) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
    }
}
