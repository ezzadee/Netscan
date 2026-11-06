package com.netsentry.app.apps

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import com.netsentry.app.scan.Severity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

data class HostInfo(val host: String, val trackerOwner: String?)

data class AppReport(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val uid: Int,
    val installer: String?,
    val fromStore: Boolean,
    val isSystem: Boolean,
    val hasInternet: Boolean,
    val sensitiveGranted: List<String>,
    val specialAccess: List<String>,
    val trackers: List<TrackerSdk>,
    val hosts: List<HostInfo>,
    val risk: Severity,
    val riskReasons: List<String>,
)

/** Builds a security and privacy profile for every user-installed app. */
class AppInventory(private val context: Context) {

    private val pm = context.packageManager
    private val cacheFile = File(context.filesDir, "app_scan_cache.json")

    private val sensitive = linkedMapOf(
        Manifest.permission.ACCESS_FINE_LOCATION to "Precise location",
        Manifest.permission.ACCESS_BACKGROUND_LOCATION to "Location all the time",
        Manifest.permission.CAMERA to "Camera",
        Manifest.permission.RECORD_AUDIO to "Microphone",
        Manifest.permission.READ_CONTACTS to "Contacts",
        Manifest.permission.READ_SMS to "Read SMS",
        Manifest.permission.RECEIVE_SMS to "Receive SMS",
        Manifest.permission.SEND_SMS to "Send SMS",
        Manifest.permission.READ_CALL_LOG to "Call log",
        Manifest.permission.READ_CALENDAR to "Calendar",
        Manifest.permission.BODY_SENSORS to "Body sensors",
        Manifest.permission.READ_EXTERNAL_STORAGE to "Files and media",
        "android.permission.READ_MEDIA_IMAGES" to "Photos",
        "android.permission.READ_MEDIA_VIDEO" to "Videos",
        "android.permission.MANAGE_EXTERNAL_STORAGE" to "All files",
    )

    private val trustedInstallers = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia",
        "com.google.android.feedback", "com.huawei.appmarket", "com.xiaomi.mipicks",
        "com.oppo.market", "com.heytap.market",
    )

    /**
     * Scans every app. [onProgress] is called with (done, total, currentLabel).
     * Code scanning is cached per app version, so later scans only re-read updated apps.
     */
    fun scan(onProgress: (Int, Int, String) -> Unit): List<AppReport> {
        @Suppress("DEPRECATION")
        val apps = pm.getInstalledApplications(0).filter { ai ->
            val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val updatedSystem = ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            (!system || updatedSystem) && ai.packageName != context.packageName
        }

        val accessibility = enabledAccessibilityPackages()
        val listeners = runCatching { NotificationManagerCompat.getEnabledListenerPackages(context) }
            .getOrDefault(emptySet())
        val admins = runCatching {
            context.getSystemService(DevicePolicyManager::class.java)?.activeAdmins?.map { it.packageName }
        }.getOrNull().orEmpty().toSet()

        val cache = loadCache()
        val newCache = JSONObject()
        val out = mutableListOf<AppReport>()

        apps.forEachIndexed { i, ai ->
            val label = pm.getApplicationLabel(ai).toString()
            onProgress(i, apps.size, label)
            val info = packageInfo(ai.packageName) ?: return@forEachIndexed
            val versionKey = "${longVersion(info)}:${info.lastUpdateTime}"

            // Code scan (cached)
            val cached = cache.optJSONObject(ai.packageName)?.takeIf { it.optString("v") == versionKey }
            val dex = if (cached != null) {
                val names = cached.optJSONArray("t").toStrings().toSet()
                DexScanner.Result(
                    trackers = Trackers.sdks.filter { it.name in names }.toSet(),
                    hosts = cached.optJSONArray("h").toStrings().toSet(),
                )
            } else {
                val paths = listOfNotNull(ai.sourceDir) + (ai.splitSourceDirs?.toList() ?: emptyList())
                DexScanner.scan(paths)
            }
            newCache.put(ai.packageName, JSONObject()
                .put("v", versionKey)
                .put("t", JSONArray(dex.trackers.map { it.name }))
                .put("h", JSONArray(dex.hosts.toList())))

            // Permissions
            val requested = info.requestedPermissions ?: emptyArray()
            val flags = info.requestedPermissionsFlags ?: IntArray(0)
            val granted = requested.indices
                .filter { it < flags.size && flags[it] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
                .map { requested[it] }
                .toSet()
            val sensitiveGranted = sensitive.filterKeys { it in granted }.values.toList()
            val hasInternet = Manifest.permission.INTERNET in requested

            val special = buildList {
                if (ai.packageName in accessibility) add("Accessibility service (can read the screen and act for you)")
                if (ai.packageName in listeners) add("Notification access (reads all notifications, including codes)")
                if (ai.packageName in admins) add("Device administrator")
                if ("android.permission.REQUEST_INSTALL_PACKAGES" in requested) add("Can ask to install other apps")
                if ("android.permission.SYSTEM_ALERT_WINDOW" in requested) add("Can ask to draw over other apps")
            }

            val installer = installerOf(ai.packageName)
            val fromStore = installer != null && installer in trustedInstallers
            val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0

            val hosts = dex.hosts.map { HostInfo(it, Trackers.ownerOf(it)) }
                .sortedWith(compareBy<HostInfo> { it.trackerOwner == null }.thenBy { it.host })

            val (risk, reasons) = rate(fromStore || isSystem, special, sensitiveGranted, dex.trackers)
            out += AppReport(
                packageName = ai.packageName,
                label = label,
                versionName = info.versionName,
                uid = ai.uid,
                installer = installer,
                fromStore = fromStore,
                isSystem = isSystem,
                hasInternet = hasInternet,
                sensitiveGranted = sensitiveGranted,
                specialAccess = special,
                trackers = dex.trackers.sortedBy { it.name },
                hosts = hosts,
                risk = risk,
                riskReasons = reasons,
            )
        }
        onProgress(apps.size, apps.size, "")
        runCatching { cacheFile.writeText(newCache.toString()) }
        return out.sortedWith(compareBy<AppReport> { it.risk.ordinal }.thenBy { it.label.lowercase() })
    }

    private fun rate(
        trustedSource: Boolean,
        special: List<String>,
        sensitive: List<String>,
        trackers: Set<TrackerSdk>,
    ): Pair<Severity, List<String>> {
        val reasons = mutableListOf<String>()
        val powerful = special.filter { !it.startsWith("Can ask") }
        if (!trustedSource) reasons += "Installed from outside an app store"
        if (powerful.isNotEmpty()) reasons += "Has powerful access: ${powerful.joinToString { it.substringBefore(" (") }}"
        if (trackers.isNotEmpty()) reasons += "${trackers.size} tracking/ads SDK(s) in its code"
        if (sensitive.isNotEmpty()) reasons += "Granted: ${sensitive.joinToString()}"
        val risk = when {
            !trustedSource && powerful.isNotEmpty() -> Severity.HIGH
            !trustedSource && sensitive.any { "SMS" in it || it == "Microphone" || it == "Call log" } -> Severity.HIGH
            powerful.isNotEmpty() || !trustedSource || trackers.size >= 6 -> Severity.MEDIUM
            trackers.isNotEmpty() || sensitive.isNotEmpty() -> Severity.LOW
            else -> Severity.PASS
        }
        return risk to reasons
    }

    private fun enabledAccessibilityPackages(): Set<String> = runCatching {
        val am = context.getSystemService(AccessibilityManager::class.java)
        am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            ?.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
            ?.toSet()
    }.getOrNull() ?: emptySet()

    @Suppress("DEPRECATION")
    private fun packageInfo(pkg: String): PackageInfo? = try {
        pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun installerOf(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private fun longVersion(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode
        else @Suppress("DEPRECATION") info.versionCode.toLong()

    private fun loadCache(): JSONObject = runCatching {
        if (cacheFile.exists()) JSONObject(cacheFile.readText()) else JSONObject()
    }.getOrDefault(JSONObject())

    private fun JSONArray?.toStrings(): List<String> =
        if (this == null) emptyList() else (0 until length()).map { getString(it) }
}
