package app.zeroleakage.mobile.data

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Updates: checks GitHub for the latest ZeroLeakage release, downloads the APK inside the app, verifies it
 * and hands it to Android's installer (you confirm). Nothing about you is sent: plain HTTPS GETs with a
 * generic User-Agent.
 *
 * Before an update is installed, ZeroLeakage checks that:
 *  1. its SHA-256 matches the digest GitHub publishes for the release asset (when available),
 *  2. it is the same app (package name) and a newer version,
 *  3. it is signed with the same key as the installed app, so only the real ZeroLeakage can update it.
 */
object Updates {
    private const val API = "https://api.github.com/repos/shatheitguy/ZeroLeakage/releases/latest"
    const val RELEASES_PAGE = "https://github.com/shatheitguy/ZeroLeakage/releases"
    const val WEBSITE = "https://shatheitguy.github.io/ZeroLeakage/"
    const val SOURCE = "https://github.com/shatheitguy/ZeroLeakage"

    data class Release(
        val version: String, val notes: String, val apkUrl: String?, val apkSize: Long,
        val apkSha256: String?, val pageUrl: String,
    )

    sealed interface State {
        data object Idle : State
        data object Checking : State
        data class UpToDate(val current: String, val checkedAt: Long) : State
        data class Available(val current: String, val release: Release) : State
        data class Failed(val message: String) : State
    }

    /** The download → verify → install flow, drawn by the update screen. */
    sealed interface Install {
        data object Idle : Install
        data class Downloading(val done: Long, val total: Long, val bytesPerSec: Long) : Install {
            val fraction: Float get() = if (total > 0) (done.toFloat() / total).coerceIn(0f, 1f) else 0f
        }
        /** [step] 0..4 = hash, package, version, signature, done. */
        data class Verifying(val step: Int) : Install
        data object NeedsPermission : Install
        data object Installing : Install
        data class Failed(val message: String) : Install
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    private val _install = MutableStateFlow<Install>(Install.Idle)
    val install: StateFlow<Install> = _install.asStateFlow()

    fun currentVersion(context: Context): String = runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName
    }.getOrNull() ?: "0"

    fun versionCode(context: Context): Long = runCatching {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }.getOrDefault(0)

    // ───────────────────────── check ─────────────────────────

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
            var sha: String? = null
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.getJSONObject(i)
                    if (a.optString("name").endsWith("-release.apk")) {
                        apkUrl = a.optString("browser_download_url"); size = a.optLong("size")
                        sha = a.optString("digest").takeIf { it.startsWith("sha256:") }?.substring(7)
                        break
                    }
                }
            }
            return Release(tag, json.optString("body").trim(), apkUrl, size, sha, json.optString("html_url", RELEASES_PAGE))
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

    // ───────────────────────── download + verify + install ─────────────────────────

    fun canInstall(context: Context): Boolean = context.packageManager.canRequestPackageInstalls()

    /** Android's "Install unknown apps" switch for ZeroLeakage (asked once). */
    fun openInstallPermission(context: Context) {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    fun resetInstall() { _install.value = Install.Idle }

    /** Downloads, verifies and installs [release]. Progress is published on [install]. */
    suspend fun downloadAndInstall(context: Context, release: Release) {
        val url = release.apkUrl ?: run { _install.value = Install.Failed("This release has no APK"); return }
        if (!url.startsWith("https://github.com/shatheitguy/ZeroLeakage/releases/download/")) {
            _install.value = Install.Failed("Unexpected download address"); return
        }
        if (!canInstall(context)) { _install.value = Install.NeedsPermission; return }
        val dir = File(context.cacheDir, "updates").apply { mkdirs(); listFiles()?.forEach { it.delete() } }
        val apk = File(dir, "ZeroLeakage-${release.version}.apk")
        try {
            val sha = withContext(Dispatchers.IO) { download(url, apk, release.apkSize) }
            withContext(Dispatchers.IO) { verify(context, apk, release, sha) }
            _install.value = Install.Installing
            withContext(Dispatchers.IO) { installWithPackageInstaller(context, apk) }
        } catch (e: kotlinx.coroutines.CancellationException) {
            apk.delete(); _install.value = Install.Idle; throw e
        } catch (e: Exception) {
            apk.delete()
            _install.value = Install.Failed(e.message ?: "Update failed")
        }
    }

    private suspend fun download(url: String, target: File, expectedSize: Long): String {
        val digest = MessageDigest.getInstance("SHA-256")
        var conn = URL(url).openConnection() as HttpURLConnection
        conn.instanceFollowRedirects = true
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.setRequestProperty("User-Agent", "ZeroLeakage-Updater")
        try {
            if (conn.responseCode != 200) error("Download failed (HTTP ${conn.responseCode})")
            val total = if (conn.contentLengthLong > 0) conn.contentLengthLong else expectedSize
            var done = 0L
            var lastT = System.nanoTime(); var lastDone = 0L; var speed = 0L
            _install.value = Install.Downloading(0, total, 0)
            conn.inputStream.use { input ->
                target.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (!kotlin.coroutines.coroutineContext.isActive) throw kotlinx.coroutines.CancellationException()
                        out.write(buf, 0, n)
                        digest.update(buf, 0, n)
                        done += n
                        val now = System.nanoTime()
                        if (now - lastT > 200_000_000) {
                            speed = ((done - lastDone) * 1_000_000_000L) / (now - lastT)
                            lastT = now; lastDone = done
                            _install.value = Install.Downloading(done, total, speed)
                        }
                    }
                }
            }
            _install.value = Install.Downloading(done, total, speed)
            if (expectedSize > 0 && done != expectedSize) error("Download incomplete ($done of $expectedSize bytes)")
            return digest.digest().joinToString("") { "%02x".format(it) }
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun verify(context: Context, apk: File, release: Release, sha: String) {
        suspend fun step(i: Int) { _install.value = Install.Verifying(i); kotlinx.coroutines.delay(450) }   // paced for the animation
        val pm = context.packageManager

        step(0)   // 1. hash
        if (release.apkSha256 != null && !release.apkSha256.equals(sha, ignoreCase = true))
            error("The download doesn't match its published SHA-256. Nothing was installed.")

        step(1)   // 2. same app
        @Suppress("DEPRECATION")
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val archive = pm.getPackageArchiveInfo(apk.path, flags) ?: error("The download isn't a valid Android app.")
        if (archive.packageName != context.packageName) error("The download is a different app (${archive.packageName}).")

        step(2)   // 3. newer
        val newCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) archive.longVersionCode else @Suppress("DEPRECATION") archive.versionCode.toLong()
        if (newCode <= versionCode(context)) error("The download isn't newer than the installed version.")

        step(3)   // 4. same signing key
        val installed = pm.getPackageInfo(context.packageName, flags)
        fun certs(info: android.content.pm.PackageInfo): Set<String> =
            info.signingInfo?.apkContentsSigners?.map { s -> MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) } }?.toSet()
                ?: emptySet()
        val a = certs(archive); val b = certs(installed)
        if (a.isEmpty() || a != b) error("The download isn't signed by ZeroLeakage's key. Nothing was installed.")

        step(4)
    }

    private fun installWithPackageInstaller(context: Context, apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val callback = PendingIntent.getBroadcast(
                context, id, Intent(context, UpdateInstallReceiver::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,   // the installer adds the result extras
            )
            session.commit(callback.intentSender)
        }
    }

    internal fun onInstallResult(status: Int, message: String?) {
        _install.value = when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> Install.Installing
            PackageInstaller.STATUS_SUCCESS -> Install.Idle   // the app is replaced and restarted by Android
            PackageInstaller.STATUS_FAILURE_ABORTED -> Install.Failed("Install cancelled")
            else -> Install.Failed(message ?: "Android couldn't install the update")
        }
    }
}

/** Receives Android's installer result; shows the system "Update this app?" confirmation when asked. */
class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            val confirm: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT)
            confirm?.let { runCatching { context.startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } }
        }
        Updates.onInstallResult(status, intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE))
    }
}
