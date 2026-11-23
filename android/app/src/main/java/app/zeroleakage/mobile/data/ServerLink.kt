package app.zeroleakage.mobile.data

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.zeroleakage.mobile.filters.Filters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Link this phone to your own ZeroLeakage Server with a one-time pairing code. Once linked, the phone is an
 * exact clone of the server's protection:
 *  - it uses the server as its encrypted DNS (its own DoH address), so every server policy (blocked services,
 *    categories, SafeSearch, schedules, Guard) applies here too, even on mobile data;
 *  - filter lists, custom lists and your allow / block lists mirror the server, both ways.
 * Optional and never required. The device token is encrypted with a key in the Android Keystore.
 */
object ServerLink {

    data class Link(
        val server: String, val deviceId: String, val deviceName: String, val dohUrl: String?,
        val serverName: String, val linkedAt: Long, val username: String? = null,
    )

    sealed interface Sync {
        data object Idle : Sync
        data object Running : Sync
        data class Ok(val at: Long, val policyVersion: String?, val lists: Int, val allow: Int, val block: Int, val services: Int) : Sync
        data class Failed(val at: Long, val message: String) : Sync
    }

    private lateinit var prefs: SharedPreferences
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private var pushJob: Job? = null
    private var periodic: Job? = null

    private val _link = MutableStateFlow<Link?>(null)
    val link: StateFlow<Link?> = _link.asStateFlow()
    private val _sync = MutableStateFlow<Sync>(Sync.Idle)
    val sync: StateFlow<Sync> = _sync.asStateFlow()

    fun init(context: Context, sharedPrefs: SharedPreferences) {
        prefs = sharedPrefs
        _link.value = runCatching { prefs.getString("link", null)?.let { decodeLink(JSONObject(it)) } }.getOrNull()
        Filters.onUserChange = { if (_link.value != null) schedulePush() }
        Filters.onListChange = { if (_link.value != null) { prefs.edit().putBoolean("link_lists_dirty", true).apply(); schedulePush() } }
        Filters.lockedLists = prefs.getStringSet("link_locked_lists", null)?.toSet() ?: emptySet()
        Filters.lockedBlock = prefs.getStringSet("link_locked_block", null)?.toSet() ?: emptySet()
        if (_link.value != null) {
            scope.launch { syncNow() }
            startPeriodic()
        }
    }

    // ───────────────────────── link / unlink ─────────────────────────

    /** Pairs with [rawServer] using a one-time [code] from the server dashboard. Returns an error, or null. */
    suspend fun pair(rawServer: String, code: String, deviceName: String): String? = withContext(Dispatchers.IO) {
        val server = normalizeServer(rawServer) ?: return@withContext "Enter your server's https:// address"
        val cleanCode = code.trim().uppercase().replace(" ", "")
        if (cleanCode.length < 8) return@withContext "Enter the pairing code from your server's dashboard"
        val body = JSONObject().put("code", cleanCode).put("deviceName", deviceName).put("platform", "android")
        finishLink(server, "$server/api/v1/devices/pair", body, deviceName, null)
    }

    /** Signs in with your server account (username + password); only the resulting device token is kept. */
    suspend fun signIn(rawServer: String, username: String, password: String, deviceName: String): String? = withContext(Dispatchers.IO) {
        val server = normalizeServer(rawServer) ?: return@withContext "Enter your server's https:// address"
        if (username.isBlank() || password.isBlank()) return@withContext "Enter your username and password"
        val body = JSONObject().put("username", username.trim()).put("password", password)
            .put("deviceName", deviceName).put("platform", "android")
        finishLink(server, "$server/api/v1/devices/link", body, deviceName, username.trim())
    }

    private suspend fun finishLink(server: String, url: String, body: JSONObject, deviceName: String, username: String?): String? {
        val res = runCatching { http("POST", url, body.toString(), null) }
            .getOrElse { return "Couldn't reach the server: ${it.message}" }
        if (res.first !in 200..299) return errorOf(res.second) ?: "The server refused it (HTTP ${res.first})"
        val json = JSONObject(res.second)
        val token = json.getString("token")
        val dev = json.getJSONObject("device")
        val srv = json.optJSONObject("server")
        val link = Link(
            server = server, deviceId = dev.getString("id"), deviceName = dev.optString("name", deviceName),
            dohUrl = dev.optString("dohUrl").ifBlank { null } ?: "$server/dns-query/${dev.getString("id")}",
            serverName = srv?.optString("name")?.ifBlank { null } ?: java.net.URL(server).host,
            linkedAt = System.currentTimeMillis(),
            username = username ?: json.optString("username").ifBlank { null },
        )
        prefs.edit()
            .putString("link", encodeLink(link).toString())
            .putString("link_token", Crypto.encrypt(token))
            .putString("link_prev_resolver", ZeroLeakage.resolverId.value)
            .putString("link_prev_custom", ZeroLeakage.customResolverUrl.value)
            .apply()
        _link.value = link
        // Use the server as this phone's encrypted DNS, so its policies apply here too.
        link.dohUrl?.takeIf { it.startsWith("https://") }?.let { ZeroLeakage.setCustomResolver(it) }
        syncNow()
        startPeriodic()
        return null
    }

    fun unlink() {
        val prevId = prefs.getString("link_prev_resolver", null)
        val prevCustom = prefs.getString("link_prev_custom", "") ?: ""
        if (prevId == ZeroLeakage.CUSTOM_RESOLVER && prevCustom.startsWith("https://")) ZeroLeakage.setCustomResolver(prevCustom)
        else ZeroLeakage.setResolver(prevId ?: ZeroLeakage.RESOLVERS.first().id)
        prefs.edit().remove("link").remove("link_token").remove("link_snapshot_allow").remove("link_snapshot_block")
            .remove("link_policy_version").remove("link_locked_lists").remove("link_locked_block").remove("link_lists_dirty").apply()
        Filters.lockedLists = emptySet()
        Filters.lockedBlock = emptySet()
        periodic?.cancel()
        _link.value = null
        _sync.value = Sync.Idle
    }

    // ───────────────────────── sync ─────────────────────────

    private fun startPeriodic() {
        periodic?.cancel()
        periodic = scope.launch {
            while (true) {
                delay(6 * 3_600_000L)                     // a few times a day is plenty; changes also push instantly
                syncNow()
            }
        }
    }

    private fun schedulePush() {
        pushJob?.cancel()
        pushJob = scope.launch { delay(3_000); syncNow() }   // debounce bursts of edits
    }

    /** Push your local rule edits, then pull the server's policy and apply it as an exact clone. */
    suspend fun syncNow(): Unit = mutex.withLock {
        val link = _link.value ?: return
        val token = prefs.getString("link_token", null)?.let { Crypto.decrypt(it) } ?: run {
            _sync.value = Sync.Failed(System.currentTimeMillis(), "Link key missing: unlink and pair again"); return
        }
        _sync.value = Sync.Running
        runCatching {
            withContext(Dispatchers.IO) {
                // 1. push local edits since the last sync (diff against the last server snapshot)
                val lastAllow = prefs.getStringSet("link_snapshot_allow", null) ?: emptySet()
                val lastBlock = prefs.getStringSet("link_snapshot_block", null) ?: emptySet()
                val nowAllow = Filters.userAllow.value
                val nowBlock = Filters.userBlock.value
                val now = System.currentTimeMillis()
                val changes = JSONArray()
                fun change(kind: String, d: String, deleted: Boolean) =
                    changes.put(JSONObject().put("kind", kind).put("domain", d).put("updatedAt", now).put("deleted", deleted))
                (nowAllow - lastAllow).forEach { change("allow", it, false) }
                (lastAllow - nowAllow).forEach { change("allow", it, true) }
                (nowBlock - lastBlock).forEach { change("block", it, false) }
                (lastBlock - nowBlock).forEach { change("block", it, true) }
                val listsDirty = prefs.getBoolean("link_lists_dirty", false)
                if (changes.length() > 0 || listsDirty) {
                    val put = JSONObject().put("rules", changes)
                    if (listsDirty) {
                        // your own extra lists (admin-set ones are always on and aren't yours to send)
                        val mine = Filters.enabled.value - Filters.lockedLists
                        val custom = JSONArray()
                        Filters.lists.value.filter { it.custom && it.id in mine }.forEach {
                            custom.put(JSONObject().put("name", it.name).put("url", it.url))
                        }
                        put.put("userPolicy", JSONObject()
                            .put("lists", JSONArray(mine.filterNot { id -> Filters.lists.value.any { it.id == id && it.custom } }))
                            .put("customLists", custom))
                    }
                    val r = http("PUT", "${link.server}/api/v1/sync", put.toString(), token)
                    if (r.first == 401) error("This phone was unlinked on the server")
                    if (r.first !in 200..299) error(errorOf(r.second) ?: "Push failed (HTTP ${r.first})")
                }
                // 2. pull and apply the effective policy
                val r = http("GET", "${link.server}/api/v1/sync", null, token)
                if (r.first == 401) error("This phone was unlinked on the server")
                if (r.first !in 200..299) error(errorOf(r.second) ?: "Sync failed (HTTP ${r.first})")
                val doc = JSONObject(r.second)
                val policy = doc.optJSONObject("policy") ?: JSONObject()
                // What your admin enforces: shown as "Set by admin" and can't be weakened here.
                doc.optJSONObject("locked")?.let { locked ->
                    Filters.lockedLists = locked.optJSONArray("lists")?.strings() ?: emptySet()
                    Filters.lockedBlock = locked.optJSONArray("blockDomains")?.strings() ?: emptySet()
                    prefs.edit().putStringSet("link_locked_lists", Filters.lockedLists)
                        .putStringSet("link_locked_block", Filters.lockedBlock).apply()
                }
                val effective = doc.optJSONObject("effective")

                val allow = effective?.optJSONArray("allow")?.strings() ?: liveRules(doc, "allow")
                val block = effective?.optJSONArray("block")?.strings() ?: liveRules(doc, "block")
                Filters.replaceUser(allow, block)

                val customIds = policy.optJSONArray("customLists")?.let { arr ->
                    Filters.syncCustomLists((0 until arr.length()).map { i ->
                        val o = arr.getJSONObject(i); o.optString("name") to o.optString("url")
                    })
                } ?: emptySet()
                val lists = policy.optJSONArray("lists")?.strings() ?: doc.optJSONArray("lists")?.strings()
                if (lists != null) Filters.setEnabledExact(lists + customIds)

                policy.optJSONObject("guard")?.let { g -> if (g.has("enabled")) Guard.setEnabled(g.optBoolean("enabled", true)) }

                // keep using this device's DoH address if the server's hostname changed
                doc.optString("dohUrl").takeIf { it.startsWith("https://") }?.let { url ->
                    if (url != link.dohUrl) {
                        val updated = link.copy(dohUrl = url)
                        prefs.edit().putString("link", encodeLink(updated).toString()).apply()
                        _link.value = updated
                    }
                    if (ZeroLeakage.resolver().url != url) ZeroLeakage.setCustomResolver(url)
                }

                prefs.edit()
                    .putBoolean("link_lists_dirty", false)
                    .putStringSet("link_snapshot_allow", Filters.userAllow.value)
                    .putStringSet("link_snapshot_block", Filters.userBlock.value)
                    .putString("link_policy_version", doc.optString("policyVersion"))
                    .apply()
                Sync.Ok(System.currentTimeMillis(), doc.optString("policyVersion").ifBlank { null },
                    lists?.size ?: Filters.enabled.value.size, allow.size, block.size,
                    policy.optJSONArray("services")?.length() ?: 0)
            }
        }.onSuccess { _sync.value = it }
            .onFailure { _sync.value = Sync.Failed(System.currentTimeMillis(), it.message ?: "Sync failed") }
    }

    private fun liveRules(doc: JSONObject, kind: String): Set<String> {
        val arr = doc.optJSONArray("rules") ?: return emptySet()
        return (0 until arr.length()).map { arr.getJSONObject(it) }
            .filter { it.optString("kind") == kind && !it.optBoolean("deleted") }
            .map { it.optString("domain") }.toSet()
    }

    private fun JSONArray.strings(): Set<String> = (0 until length()).map { optString(it) }.filter { it.isNotBlank() }.toSet()

    // ───────────────────────── helpers ─────────────────────────

    /** https only: your rules and DNS must never travel in plain text. */
    fun normalizeServer(raw: String): String? {
        var s = raw.trim().trimEnd('/')
        if (s.isEmpty()) return null
        if (!s.startsWith("http://") && !s.startsWith("https://")) s = "https://$s"
        if (!s.startsWith("https://")) return null
        return runCatching { URL(s); s }.getOrNull()
    }

    private fun http(method: String, url: String, body: String?, token: String?): Pair<Int, String> {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000; readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "ZeroLeakage-Android/${Build.VERSION.SDK_INT}")
            token?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) { doOutput = true; setRequestProperty("Content-Type", "application/json") }
        }
        try {
            body?.let { b -> conn.outputStream.use { it.write(b.toByteArray()) } }
            val code = conn.responseCode
            val text = (if (code < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
            return code to text
        } finally {
            conn.disconnect()
        }
    }

    private fun errorOf(body: String): String? = runCatching { JSONObject(body).optString("error").ifBlank { null } }.getOrNull()

    private fun encodeLink(l: Link) = JSONObject().put("server", l.server).put("id", l.deviceId).put("name", l.deviceName)
        .put("doh", l.dohUrl).put("srv", l.serverName).put("at", l.linkedAt).put("user", l.username)

    private fun decodeLink(o: JSONObject) = Link(o.getString("server"), o.getString("id"), o.optString("name"),
        o.optString("doh").ifBlank { null }, o.optString("srv"), o.optLong("at"), o.optString("user").ifBlank { null })

    /** AES-GCM with a non-exportable key in the Android Keystore, for the device token. */
    private object Crypto {
        private const val ALIAS = "zeroleakage_link"

        private fun key(): SecretKey {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build())
            }.generateKey()
        }

        fun encrypt(plain: String): String {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            val out = c.iv + c.doFinal(plain.toByteArray())
            return Base64.encodeToString(out, Base64.NO_WRAP)
        }

        fun decrypt(enc: String): String? = runCatching {
            val all = Base64.decode(enc, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, all, 0, 12)) }
            String(c.doFinal(all, 12, all.size - 12))
        }.getOrNull()
    }
}
