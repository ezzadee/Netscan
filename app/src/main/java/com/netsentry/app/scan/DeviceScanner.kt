package com.netsentry.app.scan

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit

/** Checks the phone's own configuration. */
class DeviceScanner(private val context: Context) {

    fun scan(): List<Finding> = buildList {
        addAll(patchLevel())
        add(screenLock())
        addAll(debugSettings())
        rootCheck()?.let { add(it) }
        add(encryption())
        addAll(sideloadedApps())
        addAll(dnsAndVpn())
    }

    private fun patchLevel(): List<Finding> {
        val patch = Build.VERSION.SECURITY_PATCH
        val date = runCatching { LocalDate.parse(patch) }.getOrNull()
            ?: return listOf(
                Finding(Category.DEVICE, Severity.INFO, "Security patch level unknown",
                    "The phone reported \"$patch\" as its patch level.")
            )
        val days = ChronoUnit.DAYS.between(date, LocalDate.now())
        val version = "Android ${Build.VERSION.RELEASE}, security patch $patch ($days days old)."
        val fix = "Settings > System > Software update (or Settings > Security > Security update). " +
            "If no update is offered for months, the phone may be out of support."
        return listOf(
            when {
                days > 180 -> Finding(Category.DEVICE, Severity.HIGH, "Security updates are badly out of date", version, fix)
                days > 90 -> Finding(Category.DEVICE, Severity.MEDIUM, "Security updates are behind", version, fix)
                days > 45 -> Finding(Category.DEVICE, Severity.LOW, "A security update is probably available", version, fix)
                else -> Finding(Category.DEVICE, Severity.PASS, "Security patches are current", version)
            }
        )
    }

    private fun screenLock(): Finding {
        val km = context.getSystemService(KeyguardManager::class.java)
        return if (km?.isDeviceSecure == true) {
            Finding(Category.DEVICE, Severity.PASS, "Screen lock is set", "A PIN, pattern, password or biometric protects the phone.")
        } else {
            Finding(Category.DEVICE, Severity.HIGH, "No screen lock",
                "Anyone holding the phone can open it, and the storage isn't protected by your PIN.",
                "Settings > Security > Screen lock — set a PIN of 6+ digits or a password.")
        }
    }

    private fun debugSettings(): List<Finding> {
        val cr = context.contentResolver
        val devOn = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adbOn = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        return buildList {
            if (adbOn) {
                add(Finding(Category.DEVICE, Severity.MEDIUM, "USB debugging is on",
                    "A computer the phone is plugged into can install apps and read data if you approve it.",
                    "Settings > System > Developer options > turn off USB debugging (and Wireless debugging)."))
            } else if (devOn) {
                add(Finding(Category.DEVICE, Severity.LOW, "Developer options are enabled",
                    "Not dangerous by itself, but it exposes settings that lower security.",
                    "Settings > System > Developer options > toggle off at the top."))
            } else {
                add(Finding(Category.DEVICE, Severity.PASS, "Developer options and USB debugging are off", "Debug access is closed."))
            }
        }
    }

    private fun rootCheck(): Finding? {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk",
        )
        val hits = mutableListOf<String>()
        suPaths.filter { File(it).exists() }.forEach { hits += it }
        if (Build.TAGS?.contains("test-keys") == true) hits += "build signed with test keys"
        listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser").forEach { pkg ->
            if (isInstalled(pkg)) hits += "root manager app $pkg"
        }
        return if (hits.isEmpty()) {
            Finding(Category.DEVICE, Severity.PASS, "No signs of rooting", "No su binary or root manager app found.")
        } else {
            Finding(Category.DEVICE, Severity.HIGH, "Phone appears to be rooted",
                "Found: ${hits.joinToString()}. Root access lets any app that gets it bypass Android's security.",
                "If you didn't root this phone yourself, back up your data and factory reset it.")
        }
    }

    private fun encryption(): Finding {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val status = dpm?.storageEncryptionStatus ?: DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED
        return when (status) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ->
                Finding(Category.DEVICE, Severity.PASS, "Storage is encrypted", "Your data is unreadable without unlocking the phone.")
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY ->
                Finding(Category.DEVICE, Severity.MEDIUM, "Storage encrypted with a default key",
                    "Encryption isn't tied to your screen lock, so it offers little protection.",
                    "Set a screen lock PIN or password.")
            else ->
                Finding(Category.DEVICE, Severity.HIGH, "Storage is not encrypted",
                    "Data could be read directly off the phone's storage.",
                    "Settings > Security > Encryption, or set a screen lock on newer phones.")
        }
    }

    private fun sideloadedApps(): List<Finding> {
        val pm = context.packageManager
        val trusted = setOf(
            "com.android.vending",               // Google Play
            "com.sec.android.app.samsungapps",   // Galaxy Store
            "com.amazon.venezia",                // Amazon Appstore
            "com.google.android.feedback",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.oppo.market", "com.heytap.market",
        )
        @Suppress("DEPRECATION")
        val apps = pm.getInstalledApplications(0)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
            .filter { it.packageName != context.packageName }
        val outside = apps.filter { app ->
            val installer = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    pm.getInstallSourceInfo(app.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION") pm.getInstallerPackageName(app.packageName)
                }
            }.getOrNull()
            installer == null || installer !in trusted
        }
        if (outside.isEmpty()) {
            return listOf(Finding(Category.DEVICE, Severity.PASS, "All apps came from an app store",
                "${apps.size} user-installed apps checked."))
        }
        val names = outside.take(12).joinToString { pm.getApplicationLabel(it).toString() }
        val more = if (outside.size > 12) " and ${outside.size - 12} more" else ""
        return listOf(Finding(Category.DEVICE, Severity.LOW,
            "${outside.size} app(s) installed outside an app store",
            "$names$more. Sideloaded apps skip store malware screening. Apps restored from a backup or " +
                "installed by your carrier can also show up here.",
            "Uninstall any you don't recognize: Settings > Apps."))
    }

    private fun dnsAndVpn(): List<Finding> {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val net = cm.activeNetwork ?: return emptyList()
        val caps = cm.getNetworkCapabilities(net)
        val link = cm.getLinkProperties(net)
        return buildList {
            if (link?.isPrivateDnsActive == true) {
                add(Finding(Category.DEVICE, Severity.PASS, "Private DNS is on",
                    "Website lookups are encrypted${link.privateDnsServerName?.let { " via $it" } ?: ""}."))
            } else {
                add(Finding(Category.DEVICE, Severity.LOW, "Private DNS is off",
                    "The network you're on can see (and on hostile networks, alter) which sites you look up.",
                    "Settings > Network & internet > Private DNS > Private DNS provider hostname, e.g. dns.google or one.one.one.one."))
            }
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                add(Finding(Category.DEVICE, Severity.INFO, "A VPN is active",
                    "Traffic is tunneled through your VPN provider, which protects it on untrusted Wi-Fi."))
            }
        }
    }

    private fun isInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0); true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }
}
