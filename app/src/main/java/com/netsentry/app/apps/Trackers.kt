package com.netsentry.app.apps

/**
 * Known tracking, advertising and analytics SDKs, identified by the Java package names
 * their code uses (the same approach Exodus Privacy uses), plus the server domains they
 * report to. Not exhaustive — it covers the SDKs found in most mainstream apps.
 */
data class TrackerSdk(val name: String, val category: String, val prefixes: List<String>)

object Trackers {

    const val ADS = "Advertising"
    const val ANALYTICS = "Analytics"
    const val ATTRIBUTION = "Install attribution"
    const val CRASH = "Crash reporting"
    const val LOCATION = "Location data"
    const val MARKETING = "Marketing & push"
    const val RECORDING = "Session recording"

    val sdks: List<TrackerSdk> = listOf(
        TrackerSdk("Google AdMob", ADS, listOf("com.google.android.gms.ads.", "com.google.ads.")),
        TrackerSdk("Google Firebase Analytics", ANALYTICS, listOf("com.google.firebase.analytics.")),
        TrackerSdk("Google Analytics", ANALYTICS, listOf("com.google.android.gms.analytics.")),
        TrackerSdk("Google Tag Manager", ANALYTICS, listOf("com.google.android.gms.tagmanager.")),
        TrackerSdk("Google Crashlytics", CRASH, listOf("com.google.firebase.crashlytics.", "com.crashlytics.")),
        TrackerSdk("Facebook Analytics", ANALYTICS, listOf("com.facebook.appevents.")),
        TrackerSdk("Facebook Audience Network", ADS, listOf("com.facebook.ads.")),
        TrackerSdk("Facebook Login", ANALYTICS, listOf("com.facebook.login.")),
        TrackerSdk("AppsFlyer", ATTRIBUTION, listOf("com.appsflyer.")),
        TrackerSdk("Adjust", ATTRIBUTION, listOf("com.adjust.sdk.")),
        TrackerSdk("Branch", ATTRIBUTION, listOf("io.branch.")),
        TrackerSdk("Kochava", ATTRIBUTION, listOf("com.kochava.")),
        TrackerSdk("Singular", ATTRIBUTION, listOf("com.singular.sdk.")),
        TrackerSdk("Amplitude", ANALYTICS, listOf("com.amplitude.")),
        TrackerSdk("Mixpanel", ANALYTICS, listOf("com.mixpanel.")),
        TrackerSdk("Segment", ANALYTICS, listOf("com.segment.analytics.")),
        TrackerSdk("Flurry", ANALYTICS, listOf("com.flurry.")),
        TrackerSdk("Heap", ANALYTICS, listOf("com.heapanalytics.")),
        TrackerSdk("Yandex AppMetrica", ANALYTICS, listOf("com.yandex.metrica.", "io.appmetrica.")),
        TrackerSdk("Huawei Analytics", ANALYTICS, listOf("com.huawei.hms.analytics.")),
        TrackerSdk("Umeng", ANALYTICS, listOf("com.umeng.")),
        TrackerSdk("comScore", ANALYTICS, listOf("com.comscore.")),
        TrackerSdk("Nielsen", ANALYTICS, listOf("com.nielsen.")),
        TrackerSdk("Localytics", ANALYTICS, listOf("com.localytics.")),
        TrackerSdk("Microsoft App Center", ANALYTICS, listOf("com.microsoft.appcenter.")),
        TrackerSdk("AppLovin", ADS, listOf("com.applovin.")),
        TrackerSdk("Unity Ads", ADS, listOf("com.unity3d.ads.", "com.unity3d.services.")),
        TrackerSdk("ironSource", ADS, listOf("com.ironsource.")),
        TrackerSdk("Vungle / Liftoff", ADS, listOf("com.vungle.")),
        TrackerSdk("Chartboost", ADS, listOf("com.chartboost.")),
        TrackerSdk("InMobi", ADS, listOf("com.inmobi.")),
        TrackerSdk("Mintegral", ADS, listOf("com.mbridge.msdk.", "com.mintegral.")),
        TrackerSdk("Pangle (ByteDance)", ADS, listOf("com.bytedance.sdk.openadsdk.")),
        TrackerSdk("Tapjoy", ADS, listOf("com.tapjoy.")),
        TrackerSdk("AdColony", ADS, listOf("com.adcolony.")),
        TrackerSdk("Smaato", ADS, listOf("com.smaato.")),
        TrackerSdk("Criteo", ADS, listOf("com.criteo.")),
        TrackerSdk("Amazon Ads", ADS, listOf("com.amazon.device.ads.")),
        TrackerSdk("MoPub", ADS, listOf("com.mopub.")),
        TrackerSdk("Start.io", ADS, listOf("com.startapp.")),
        TrackerSdk("Moat", ADS, listOf("com.moat.")),
        TrackerSdk("Integral Ad Science", ADS, listOf("com.integralads.")),
        TrackerSdk("Braze", MARKETING, listOf("com.braze.", "com.appboy.")),
        TrackerSdk("OneSignal", MARKETING, listOf("com.onesignal.")),
        TrackerSdk("Airship", MARKETING, listOf("com.urbanairship.")),
        TrackerSdk("CleverTap", MARKETING, listOf("com.clevertap.")),
        TrackerSdk("Sentry", CRASH, listOf("io.sentry.")),
        TrackerSdk("Bugsnag", CRASH, listOf("com.bugsnag.")),
        TrackerSdk("New Relic", CRASH, listOf("com.newrelic.agent.")),
        TrackerSdk("Instabug", CRASH, listOf("com.instabug.")),
        TrackerSdk("AppDynamics", CRASH, listOf("com.appdynamics.")),
        TrackerSdk("Dynatrace", CRASH, listOf("com.dynatrace.")),
        TrackerSdk("Tencent Bugly", CRASH, listOf("com.tencent.bugly.")),
        TrackerSdk("FullStory", RECORDING, listOf("com.fullstory.")),
        TrackerSdk("UXCam", RECORDING, listOf("com.uxcam.")),
        TrackerSdk("Smartlook", RECORDING, listOf("com.smartlook.")),
        TrackerSdk("Foursquare Pilgrim", LOCATION, listOf("com.foursquare.pilgrim.")),
        TrackerSdk("Radar", LOCATION, listOf("io.radar.")),
        TrackerSdk("Cuebiq", LOCATION, listOf("com.cuebiq.")),
    )

    /** Domain suffix → who runs it. Used for both embedded servers and live lookups. */
    private val domains: Map<String, String> = mapOf(
        "doubleclick.net" to "Google Ads",
        "googleadservices.com" to "Google Ads",
        "googlesyndication.com" to "Google Ads",
        "google-analytics.com" to "Google Analytics",
        "app-measurement.com" to "Google Firebase Analytics",
        "crashlytics.com" to "Google Crashlytics",
        "graph.facebook.com" to "Facebook",
        "an.facebook.com" to "Facebook Audience Network",
        "appsflyer.com" to "AppsFlyer",
        "appsflyersdk.com" to "AppsFlyer",
        "adjust.com" to "Adjust",
        "adj.st" to "Adjust",
        "branch.io" to "Branch",
        "app.link" to "Branch",
        "kochava.com" to "Kochava",
        "singular.net" to "Singular",
        "amplitude.com" to "Amplitude",
        "mixpanel.com" to "Mixpanel",
        "segment.io" to "Segment",
        "segment.com" to "Segment",
        "flurry.com" to "Flurry",
        "heapanalytics.com" to "Heap",
        "appmetrica.yandex.net" to "Yandex AppMetrica",
        "mc.yandex.ru" to "Yandex Metrica",
        "umeng.com" to "Umeng",
        "scorecardresearch.com" to "comScore",
        "imrworldwide.com" to "Nielsen",
        "localytics.com" to "Localytics",
        "appcenter.ms" to "Microsoft App Center",
        "applovin.com" to "AppLovin",
        "applvn.com" to "AppLovin",
        "unityads.unity3d.com" to "Unity Ads",
        "supersonicads.com" to "ironSource",
        "ironsrc.com" to "ironSource",
        "ironsrc.mobi" to "ironSource",
        "vungle.com" to "Vungle / Liftoff",
        "chartboost.com" to "Chartboost",
        "inmobi.com" to "InMobi",
        "rayjump.com" to "Mintegral",
        "pangle.io" to "Pangle (ByteDance)",
        "pangolin-sdk-toutiao.com" to "Pangle (ByteDance)",
        "tapjoy.com" to "Tapjoy",
        "adcolony.com" to "AdColony",
        "smaato.net" to "Smaato",
        "criteo.com" to "Criteo",
        "criteo.net" to "Criteo",
        "amazon-adsystem.com" to "Amazon Ads",
        "mopub.com" to "MoPub",
        "startappservice.com" to "Start.io",
        "moatads.com" to "Moat",
        "adsafeprotected.com" to "Integral Ad Science",
        "braze.com" to "Braze",
        "appboy.com" to "Braze",
        "onesignal.com" to "OneSignal",
        "urbanairship.com" to "Airship",
        "clevertap-prod.com" to "CleverTap",
        "wzrkt.com" to "CleverTap",
        "sentry.io" to "Sentry",
        "bugsnag.com" to "Bugsnag",
        "nr-data.net" to "New Relic",
        "instabug.com" to "Instabug",
        "fullstory.com" to "FullStory",
        "uxcam.com" to "UXCam",
        "smartlook.com" to "Smartlook",
        "radar.io" to "Radar",
        "cuebiq.com" to "Cuebiq",
        "analytics.tiktok.com" to "TikTok Analytics",
        "ads-twitter.com" to "X (Twitter) Ads",
        "analytics.twitter.com" to "X (Twitter) Analytics",
    )

    /** Returns the tracker company for a host name, or null if it isn't a known tracker. */
    fun ownerOf(host: String): String? {
        val h = host.lowercase().trimEnd('.')
        var candidate = h
        while (true) {
            domains[candidate]?.let { return it }
            val dot = candidate.indexOf('.')
            if (dot < 0) return null
            candidate = candidate.substring(dot + 1)
        }
    }
}
