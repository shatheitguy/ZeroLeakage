package app.zeroleakage.mobile.filters

/** A filter list the user can subscribe to, AdGuard-Home style. */
data class FilterList(
    val id: String,
    val name: String,
    val description: String,
    val group: String,
    /** Label shown in the live feed / stats when this list blocks a lookup. */
    val category: String,
    val url: String? = null,
    /** Bundled list shipped inside the APK (works offline, no download). */
    val asset: String? = null,
    val homepage: String? = null,
    val defaultOn: Boolean = false,
    /** Rough rule count, shown before the list is downloaded. */
    val approxRules: String = "",
    val custom: Boolean = false,
) {
    val isBundled: Boolean get() = asset != null
}

object FilterCatalog {

    const val G_BUILTIN = "Built-in (offline)"
    const val G_ADS = "Ads & trackers"
    const val G_ALLINONE = "All-in-one"
    const val G_PRIVACY = "Privacy & telemetry"
    const val G_SECURITY = "Security"
    const val G_PARENTAL = "Parental & focus"
    const val G_CUSTOM = "Custom lists"

    val GROUP_ORDER = listOf(G_BUILTIN, G_ADS, G_ALLINONE, G_PRIVACY, G_SECURITY, G_PARENTAL, G_CUSTOM)

    private const val HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock"
    private const val SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master"

    val LISTS: List<FilterList> = listOf(
        // ── bundled (ids kept stable from v1.0) ──
        FilterList("telemetry", "OS & OEM Telemetry", "Google, Samsung, Xiaomi, Huawei & Meta phone-home endpoints.",
            G_BUILTIN, "Telemetry", asset = "blocklist_telemetry.txt", defaultOn = true),
        FilterList("trackers", "Ad & Tracker Mesh", "Ad networks, attribution SDKs, pixels and fingerprinting.",
            G_BUILTIN, "Ad Tracker", asset = "blocklist_trackers.txt", defaultOn = true),
        FilterList("analytics", "App Analytics SDKs", "Crash reporters and product analytics: Sentry, Mixpanel, Amplitude…",
            G_BUILTIN, "Analytics", asset = "blocklist_analytics.txt", defaultOn = true),
        FilterList("malware", "Malware & Phishing (core)", "Known stalkerware, cryptojacking and phishing hosts.",
            G_BUILTIN, "Malware", asset = "blocklist_malware.txt", defaultOn = true),

        // ── ads & trackers ──
        FilterList("adguard_dns", "AdGuard DNS filter", "AdGuard's DNS-optimised list: ads, trackers and analytics. Low false positives.",
            G_ADS, "Ad Tracker", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            homepage = "https://github.com/AdguardTeam/AdGuardSDNSFilter", defaultOn = true, approxRules = "~190K"),
        FilterList("adaway", "AdAway default", "Classic mobile ad-server hosts file from the AdAway project.",
            G_ADS, "Ad Tracker", "https://adaway.org/hosts.txt", homepage = "https://adaway.org", approxRules = "~6K"),
        FilterList("pgl", "Peter Lowe's list", "Long-running hand-curated ad and tracking server list.",
            G_ADS, "Ad Tracker", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            homepage = "https://pgl.yoyo.org/adservers/", approxRules = "~3K"),
        FilterList("easyprivacy", "EasyPrivacy", "Tracking-only list from the EasyList authors (domain rules only).",
            G_ADS, "Ad Tracker", "https://easylist.to/easylist/easyprivacy.txt", homepage = "https://easylist.to", approxRules = "~25K"),
        FilterList("hagezi_popup", "HaGeZi Pop-Up Ads", "Malicious pop-up, pop-under and redirect ad networks.",
            G_ADS, "Ad Tracker", "$HAGEZI/popupads.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~60K"),
        FilterList("someonewhocares", "Dan Pollock's hosts", "someonewhocares.org hosts: ads, banners, tracking and shock sites.",
            G_ADS, "Ad Tracker", "https://someonewhocares.org/hosts/zero/hosts", homepage = "https://someonewhocares.org/hosts/", approxRules = "~12K"),

        // ── all-in-one ──
        FilterList("oisd_small", "OISD Small", "Blocks ads, trackers and malware with almost zero breakage.",
            G_ALLINONE, "Ad Tracker", "https://small.oisd.nl/", homepage = "https://oisd.nl", approxRules = "~55K"),
        FilterList("oisd_big", "OISD Big", "OISD's full list. Bigger coverage, still tuned for no false positives.",
            G_ALLINONE, "Ad Tracker", "https://big.oisd.nl/", homepage = "https://oisd.nl", approxRules = "~200K"),
        FilterList("hagezi_light", "HaGeZi Light", "Basic protection: ads, tracking, metrics. Good for low-RAM phones.",
            G_ALLINONE, "Ad Tracker", "$HAGEZI/light.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~90K"),
        FilterList("hagezi_multi", "HaGeZi Multi Normal", "All-round protection: ads, affiliate, tracking, metrics, telemetry, phishing, malware.",
            G_ALLINONE, "Ad Tracker", "$HAGEZI/multi.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~200K"),
        FilterList("hagezi_pro", "HaGeZi Multi PRO", "Extended protection. Recommended by HaGeZi for most users.",
            G_ALLINONE, "Ad Tracker", "$HAGEZI/pro.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~250K"),
        FilterList("stevenblack", "StevenBlack Unified hosts", "Consolidated hosts from AdAway, Dan Pollock, URLhaus and more.",
            G_ALLINONE, "Ad Tracker", "$SB/hosts", homepage = "https://github.com/StevenBlack/hosts", approxRules = "~80K"),

        // ── privacy & native telemetry ──
        FilterList("hagezi_xiaomi", "Native tracker: Xiaomi", "Blocks MIUI / HyperOS analytics and phone-home.",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.xiaomi.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~400"),
        FilterList("hagezi_samsung", "Native tracker: Samsung", "Blocks One UI / Samsung device analytics.",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.samsung.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~200"),
        FilterList("hagezi_huawei", "Native tracker: Huawei", "Blocks EMUI / HarmonyOS analytics.",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.huawei.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~200"),
        FilterList("hagezi_tiktok", "Native tracker: TikTok", "Blocks TikTok's analytics and fingerprinting (TikTok keeps working).",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.tiktok.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~600"),
        FilterList("hagezi_amazon", "Native tracker: Amazon", "Blocks Amazon device and app metrics.",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.amazon.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~400"),
        FilterList("hagezi_apple", "Native tracker: Apple", "Blocks Apple analytics endpoints.",
            G_PRIVACY, "Telemetry", "$HAGEZI/native.apple.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~100"),

        // ── security ──
        FilterList("hagezi_tif_mini", "HaGeZi Threat Intelligence (mini)", "Malware, phishing, scam, crypto-jacking and C2 domains seen recently.",
            G_SECURITY, "Malware", "$HAGEZI/tif.mini.txt", homepage = "https://github.com/hagezi/dns-blocklists", approxRules = "~150K"),
        FilterList("urlhaus", "URLhaus malware filter", "Malware distribution hosts from abuse.ch URLhaus.",
            G_SECURITY, "Malware", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
            homepage = "https://gitlab.com/malware-filter/urlhaus-filter", approxRules = "~10K"),
        FilterList("phishing_army", "Phishing Army", "Phishing domains from PhishTank, OpenPhish and others.",
            G_SECURITY, "Malware", "https://phishing.army/download/phishing_army_blocklist.txt",
            homepage = "https://phishing.army", approxRules = "~140K"),
        FilterList("nocoin", "NoCoin", "Browser crypto-mining scripts.",
            G_SECURITY, "Malware", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
            homepage = "https://github.com/hoshsadiq/adblock-nocoin-list", approxRules = "~400"),

        // ── parental & focus ──
        FilterList("sb_gambling", "Gambling", "Betting and casino sites (StevenBlack alternate).",
            G_PARENTAL, "Gambling", "$SB/alternates/gambling-only/hosts", homepage = "https://github.com/StevenBlack/hosts", approxRules = "~5K"),
        FilterList("sb_adult", "Adult content", "Pornography sites (StevenBlack alternate).",
            G_PARENTAL, "Adult", "$SB/alternates/porn-only/hosts", homepage = "https://github.com/StevenBlack/hosts", approxRules = "~70K"),
        FilterList("sb_social", "Social media", "Facebook, Instagram, TikTok, X, Reddit… for focus mode.",
            G_PARENTAL, "Social", "$SB/alternates/social-only/hosts", homepage = "https://github.com/StevenBlack/hosts", approxRules = "~3K"),
    )

    val DEFAULT_ON: Set<String> = LISTS.filter { it.defaultOn }.map { it.id }.toSet()
}
