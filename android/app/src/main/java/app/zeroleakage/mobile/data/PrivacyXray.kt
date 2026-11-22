package app.zeroleakage.mobile.data

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager

/**
 * Privacy X-ray: which installed apps CAN read, hear or see the user's private data.
 *
 * Everything here comes from what Android exposes to a normal app: granted runtime permissions,
 * special-access app-ops, and the secure settings for accessibility services, notification
 * listeners and keyboards. Android does NOT let a normal app see another app's live microphone /
 * camera use or its AppOps history, so this is a capability map, not an activity log.
 *
 * [PrivacyXray.scan] does PackageManager I/O — call it off the main thread.
 */
enum class Risk { CRITICAL, HIGH, MEDIUM, LOW }

enum class Capability(val title: String, val explain: String, val risk: Risk) {
    READ_SCREEN(
        "Reads your screen",
        "Accessibility service: can read everything shown on screen, including chats, messages and passwords as you view them, and can tap for you.",
        Risk.CRITICAL,
    ),
    READ_NOTIFICATIONS(
        "Reads notifications",
        "Notification access: sees the text of every notification, including message previews from chat and SMS apps, and OTP codes.",
        Risk.CRITICAL,
    ),
    KEYBOARD(
        "Keyboard",
        "Enabled keyboard: sees everything you type into apps that use it — messages, searches, and anything not in a password field.",
        Risk.CRITICAL,
    ),
    DEVICE_ADMIN(
        "Device admin",
        "Active device administrator: can lock or wipe the device, enforce policies, and is harder to uninstall.",
        Risk.CRITICAL,
    ),
    MICROPHONE("Microphone", "Can record audio while the permission allows it (status-bar indicator shows when in use).", Risk.HIGH),
    CAMERA("Camera", "Can take photos and video while the permission allows it (status-bar indicator shows when in use).", Risk.HIGH),
    SMS("SMS", "Can read, receive or send text messages.", Risk.HIGH),
    CALLS("Calls & phone", "Can read the call log, phone state, or place and answer calls.", Risk.HIGH),
    LOCATION_BACKGROUND("Background location", "Can get your location even when you're not using the app.", Risk.HIGH),
    LOCATION("Location", "Can get your precise or approximate location while in use.", Risk.MEDIUM),
    CONTACTS("Contacts", "Can read your contacts list.", Risk.MEDIUM),
    DRAW_OVER("Draws over apps", "Can display over other apps — used for chat heads, but also for overlays that mimic other screens.", Risk.MEDIUM),
    USAGE_ACCESS("Usage access", "Can see which apps you use, when and for how long.", Risk.MEDIUM),
    FILES_MEDIA("Files & media", "Can read your photos, videos, audio or (with all-files access) every file in shared storage.", Risk.MEDIUM),
    NEARBY("Nearby devices", "Can scan for and connect to Bluetooth / Wi-Fi devices near you.", Risk.LOW),
    BODY("Body & activity", "Can read body sensors or physical activity (steps, walking, driving).", Risk.LOW),
}

data class AppExposure(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val capabilities: Set<Capability>,
    val score: Int,
    val isDefaultKeyboard: Boolean,
) {
    /** Per-app risk of a capability: a system (pre-installed) keyboard is HIGH rather than CRITICAL. */
    fun riskOf(cap: Capability): Risk =
        if (cap == Capability.KEYBOARD && isSystem) Risk.HIGH else cap.risk

    /** Highest risk among this app's capabilities. */
    val topRisk: Risk
        get() = capabilities.map { riskOf(it) }.minByOrNull { it.ordinal } ?: Risk.LOW

    val hasCritical: Boolean get() = topRisk == Risk.CRITICAL
}

data class XrayReport(
    /** Apps with at least one capability, sorted by score (desc), then label. */
    val apps: List<AppExposure>,
    /** Number of apps holding each capability (every capability is present as a key). */
    val counts: Map<Capability, Int>,
    /** Label of the default keyboard, or null if it could not be determined. */
    val defaultKeyboardLabel: String?,
    val defaultKeyboardPackage: String?,
    val scannedAt: Long,
) {
    fun count(cap: Capability): Int = counts[cap] ?: 0
}

object PrivacyXray {

    private const val GRANTED = PackageInfo.REQUESTED_PERMISSION_GRANTED

    private val PERMS_MIC = setOf("android.permission.RECORD_AUDIO")
    private val PERMS_CAMERA = setOf("android.permission.CAMERA")
    private val PERMS_BG_LOCATION = setOf("android.permission.ACCESS_BACKGROUND_LOCATION")
    private val PERMS_LOCATION = setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION")
    private val PERMS_SMS = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS")
    private val PERMS_CALLS = setOf(
        "android.permission.READ_CALL_LOG", "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE", "android.permission.ANSWER_PHONE_CALLS",
    )
    private val PERMS_CONTACTS = setOf("android.permission.READ_CONTACTS")
    private val PERMS_FILES = setOf(
        "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO", "android.permission.READ_EXTERNAL_STORAGE",
    )
    private val PERMS_NEARBY = setOf(
        "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
        "android.permission.NEARBY_WIFI_DEVICES",
    )
    private val PERMS_BODY = setOf("android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION")

    private fun weight(r: Risk) = when (r) {
        Risk.CRITICAL -> 40
        Risk.HIGH -> 15
        Risk.MEDIUM -> 6
        Risk.LOW -> 2
    }

    fun scan(context: Context): XrayReport {
        val pm = context.packageManager
        val cr = context.contentResolver
        val self = context.packageName

        // Newer Android versions refuse direct reads of several Secure settings to apps targeting a recent SDK
        // (e.g. ENABLED_INPUT_METHODS on Android 14+). Use the public APIs, and treat every settings read as
        // optional so one refusal never breaks the whole scan.
        fun secure(key: String): String? = runCatching { Settings.Secure.getString(cr, key) }.getOrNull()

        // Accessibility: the public AccessibilityManager list of *enabled* services.
        val accessibility: Set<String> = runCatching {
            context.getSystemService(AccessibilityManager::class.java)
                ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                ?.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }?.toSet()
        }.getOrNull() ?: parseComponentPackages(secure(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))

        // Notification access has no public "who is enabled" API; read the setting where Android still allows it.
        val listeners = parseComponentPackages(secure("enabled_notification_listeners"))

        // Keyboards: InputMethodManager is the public API for enabled keyboards and the current one.
        val imm = runCatching { context.getSystemService(InputMethodManager::class.java) }.getOrNull()
        val defaultImePkg: String? = (
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) runCatching { imm?.currentInputMethodInfo?.packageName }.getOrNull()
            else null
        ) ?: secure(Settings.Secure.DEFAULT_INPUT_METHOD)?.substringBefore('/')?.trim()?.takeIf { it.isNotEmpty() }
        val keyboards = buildSet {
            runCatching { imm?.enabledInputMethodList?.forEach { add(it.packageName) } }
            if (isEmpty()) addAll(parseComponentPackages(secure(Settings.Secure.ENABLED_INPUT_METHODS)))
            defaultImePkg?.let { add(it) }
        }

        val admins: Set<String> = runCatching {
            context.getSystemService(DevicePolicyManager::class.java)
                ?.activeAdmins?.map { it.packageName }?.toSet()
        }.getOrNull() ?: emptySet()

        val appOps = context.getSystemService(AppOpsManager::class.java)

        val packages: List<PackageInfo> = runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }
        }.getOrNull() ?: emptyList()

        val apps = ArrayList<AppExposure>()
        for (info in packages) {
            val pkg = info.packageName ?: continue
            if (pkg == self) continue
            val ai = info.applicationInfo ?: continue
            val isSystem = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0

            val granted = HashSet<String>()
            val req = info.requestedPermissions
            val flags = info.requestedPermissionsFlags
            if (req != null && flags != null) {
                for (i in req.indices) {
                    if (i < flags.size && (flags[i] and GRANTED) != 0) req[i]?.let { granted.add(it) }
                }
            }
            fun any(set: Set<String>) = set.any { it in granted }
            fun opAllowed(op: String): Boolean = appOps != null && runCatching {
                appOps.unsafeCheckOpNoThrow(op, ai.uid, pkg) == AppOpsManager.MODE_ALLOWED
            }.getOrDefault(false)

            val caps = HashSet<Capability>()
            if (pkg in accessibility) caps += Capability.READ_SCREEN
            if (pkg in listeners) caps += Capability.READ_NOTIFICATIONS
            if (pkg in keyboards) caps += Capability.KEYBOARD
            if (pkg in admins) caps += Capability.DEVICE_ADMIN
            if (any(PERMS_MIC)) caps += Capability.MICROPHONE
            if (any(PERMS_CAMERA)) caps += Capability.CAMERA
            if (any(PERMS_SMS)) caps += Capability.SMS
            if (any(PERMS_CALLS)) caps += Capability.CALLS
            if (any(PERMS_BG_LOCATION)) caps += Capability.LOCATION_BACKGROUND
            if (any(PERMS_LOCATION)) caps += Capability.LOCATION
            if (any(PERMS_CONTACTS)) caps += Capability.CONTACTS
            if (any(PERMS_NEARBY)) caps += Capability.NEARBY
            if (any(PERMS_BODY)) caps += Capability.BODY
            if (any(PERMS_FILES)) caps += Capability.FILES_MEDIA
            // App-ops are only meaningful for apps that requested the matching permission.
            if ("android.permission.SYSTEM_ALERT_WINDOW" in (req ?: emptyArray()) && opAllowed("android:system_alert_window")) {
                caps += Capability.DRAW_OVER
            }
            if ("android.permission.PACKAGE_USAGE_STATS" in (req ?: emptyArray()) && opAllowed("android:get_usage_stats")) {
                caps += Capability.USAGE_ACCESS
            }
            if (Capability.FILES_MEDIA !in caps &&
                "android.permission.MANAGE_EXTERNAL_STORAGE" in (req ?: emptyArray()) &&
                opAllowed("android:manage_external_storage")
            ) {
                caps += Capability.FILES_MEDIA
            }

            if (caps.isEmpty()) continue

            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrNull()
                ?.takeIf { it.isNotBlank() } ?: pkg
            val score = caps.sumOf { cap ->
                weight(if (cap == Capability.KEYBOARD && isSystem) Risk.HIGH else cap.risk)
            }
            apps += AppExposure(
                packageName = pkg,
                label = label,
                isSystem = isSystem,
                capabilities = caps,
                score = score,
                isDefaultKeyboard = pkg == defaultImePkg,
            )
        }

        apps.sortWith(compareByDescending<AppExposure> { it.score }.thenBy { it.label.lowercase() })

        val counts = Capability.entries.associateWith { cap -> apps.count { cap in it.capabilities } }
        val keyboardLabel = defaultImePkg?.let { p ->
            apps.firstOrNull { it.packageName == p }?.label
                ?: runCatching { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() }.getOrNull()
                ?: p
        }

        return XrayReport(
            apps = apps,
            counts = counts,
            defaultKeyboardLabel = keyboardLabel,
            defaultKeyboardPackage = defaultImePkg,
            scannedAt = System.currentTimeMillis(),
        )
    }

    /** "pkg/cls:pkg2/cls2;subtype" → {pkg, pkg2}. */
    private fun parseComponentPackages(raw: String?): Set<String> {
        if (raw.isNullOrBlank()) return emptySet()
        return raw.split(':')
            .map { it.substringBefore(';').substringBefore('/').trim() }
            .filter { it.isNotEmpty() }
            .toSet()
    }
}
