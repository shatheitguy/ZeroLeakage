package app.zeroleakage.mobile.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.view.inputmethod.InputMethodManager
import java.util.concurrent.ConcurrentHashMap

/**
 * "Should I let this app online?": a plain-language recommendation shown wherever ZeroLeakage asks you to
 * allow an app. It's advice, not a rule: it comes from what kind of app it is (known apps, Android's app
 * category, name hints) and errs on the side of the mission: if an app works offline, going online usually
 * means ads, analytics or tracking.
 */
object AppAdvice {

    enum class Level(val label: String, val action: String) {
        NEEDED("Needed", "Allow"),
        RECOMMENDED("Recommended", "Allow"),
        OPTIONAL("Your call", "Block unless you use its online features"),
        NOT_NEEDED("Not needed", "Block"),
        NO_INTERNET("Doesn't use internet", "Nothing to do"),
    }

    data class Advice(val level: Level, val reason: String)

    private val cache = ConcurrentHashMap<String, Advice>()

    private val KNOWN: Map<String, Pair<Level, String>> = buildMap {
        fun put(level: Level, reason: String, vararg pkgs: String) = pkgs.forEach { put(it, level to reason) }
        put(Level.NEEDED, "Browser: needs internet to load pages.",
            "com.android.chrome", "org.mozilla.firefox", "com.brave.browser", "com.microsoft.emmx", "com.sec.android.app.sbrowser",
            "com.opera.browser", "com.duckduckgo.mobile.android", "org.torproject.torbrowser")
        put(Level.NEEDED, "Messenger: can't send or receive without internet.",
            "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "org.thoughtcrime.securesms", "com.google.android.apps.messaging",
            "com.samsung.android.messaging", "com.discord", "com.microsoft.teams", "us.zoom.videomeetings", "com.facebook.orca", "com.viber.voip")
        put(Level.NEEDED, "Email: needs internet to sync mail.",
            "com.google.android.gm", "com.microsoft.office.outlook", "ch.protonmail.android", "com.samsung.android.email.provider")
        put(Level.NEEDED, "Search and Google services: needs internet.",
            "com.google.android.googlequicksearchbox", "com.android.vending", "com.google.android.apps.maps",
            "com.google.android.apps.translate", "com.google.android.apps.authenticator2")
        put(Level.NEEDED, "Streaming: plays from the internet.",
            "com.google.android.youtube", "com.google.android.apps.youtube.music", "com.spotify.music", "com.netflix.mediaclient",
            "com.amazon.avod.thirdpartyclient", "com.disney.disneyplus")
        put(Level.RECOMMENDED, "Syncs your data online; works partly offline.",
            "com.google.android.apps.photos", "com.google.android.calendar", "com.google.android.apps.docs", "com.google.android.keep",
            "com.google.android.contacts", "com.google.android.dialer", "com.samsung.android.dialer", "com.google.android.apps.nbu.files")
        put(Level.OPTIONAL, "Social media: needs internet, but collects a lot of data. Allow only if you use it.",
            "com.facebook.katana", "com.instagram.android", "com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.snapchat.android",
            "com.twitter.android", "com.reddit.frontpage", "com.pinterest", "com.linkedin.android")
    }

    private val OFFLINE_HINTS = listOf(
        "calculator", "calc", "clock", "alarm", "flashlight", "torch", "compass", "camera", "gallery", "filemanager", "files",
        "notes", "notepad", "recorder", "voicerecorder", "launcher", "wallpaper", "qrscanner", "qrcode", "scanner", "ruler",
        "level", "timer", "stopwatch", "unitconverter", "converter", "magnifier", "screenrecorder", "fmradio", "radio",
    )
    private val MONEY_HINTS = listOf("bank", "wallet", "pay", "finance", "money", "broker")

    fun forPackage(context: Context, pkg: String): Advice = cache.getOrPut(pkg) { compute(context, pkg) }

    private fun compute(context: Context, pkg: String): Advice {
        KNOWN[pkg]?.let { return Advice(it.first, it.second) }
        val pm = context.packageManager
        val info: ApplicationInfo? = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull()

        // Apps that never asked for internet can't use it anyway.
        val usesInternet = runCatching {
            pm.checkPermission(android.Manifest.permission.INTERNET, pkg) == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(true)
        if (!usesInternet) return Advice(Level.NO_INTERNET, "This app doesn't use the internet at all.")

        // Keyboards see everything you type: they don't need internet to work.
        val isKeyboard = runCatching {
            context.getSystemService(InputMethodManager::class.java)?.inputMethodList?.any { it.packageName == pkg }
        }.getOrNull() == true
        if (isKeyboard) return Advice(Level.NOT_NEEDED,
            "Keyboard: it sees everything you type and works fine offline. Online is only for sync, GIFs and suggestions.")

        val p = pkg.lowercase()
        val label = info?.let { runCatching { pm.getApplicationLabel(it).toString().lowercase() }.getOrNull() } ?: ""
        if (MONEY_HINTS.any { it in p || it in label }) return Advice(Level.NEEDED, "Banking / payments: needs internet to work.")
        if (OFFLINE_HINTS.any { it in p.replace(".", "") || it in label.replace(" ", "") })
            return Advice(Level.NOT_NEEDED, "Works without internet. Going online here usually means ads or tracking.")

        return when (info?.category) {
            ApplicationInfo.CATEGORY_SOCIAL -> Advice(Level.OPTIONAL, "Social app: needs internet but collects a lot of data. Allow only if you use it.")
            ApplicationInfo.CATEGORY_NEWS -> Advice(Level.NEEDED, "News: loads articles from the internet.")
            ApplicationInfo.CATEGORY_MAPS -> Advice(Level.NEEDED, "Maps: needs internet for maps and directions.")
            ApplicationInfo.CATEGORY_VIDEO, ApplicationInfo.CATEGORY_AUDIO -> Advice(Level.RECOMMENDED, "Media: needed for streaming; local files play offline.")
            ApplicationInfo.CATEGORY_PRODUCTIVITY -> Advice(Level.RECOMMENDED, "Productivity: usually syncs online; often works offline too.")
            ApplicationInfo.CATEGORY_IMAGE -> Advice(Level.OPTIONAL, "Photos: work offline. Online is for backup and sharing.")
            ApplicationInfo.CATEGORY_GAME -> Advice(Level.OPTIONAL, "Game: most run offline. Online is mostly ads and analytics unless you play multiplayer.")
            ApplicationInfo.CATEGORY_ACCESSIBILITY -> Advice(Level.NOT_NEEDED, "Accessibility tool: works offline and can read your screen. Keep it off the internet.")
            else -> Advice(Level.OPTIONAL, "Allow it if you use its online features; otherwise blocking keeps your data on the phone.")
        }
    }
}
