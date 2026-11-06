package com.netsentry.app.scan

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

class WifiScanner(private val context: Context, private val baseline: Baseline) {

    data class Result(
        val findings: List<Finding>,
        val networks: List<WifiNetwork>,
        val connectedSsid: String?,
    )

    private val wifi = context.applicationContext.getSystemService(WifiManager::class.java)

    suspend fun scan(): Result {
        val findings = mutableListOf<Finding>()

        val lm = context.getSystemService(LocationManager::class.java)
        if (lm?.isLocationEnabled == false) {
            findings += Finding(Category.WIFI_NEARBY, Severity.INFO, "Location is off — nearby scan limited",
                "Android only shares Wi-Fi and cell tower lists with apps while Location is on.",
                "Turn on Location from the quick settings panel, then scan again.")
        }
        if (wifi == null) {
            return Result(findings, emptyList(), null)
        }
        @Suppress("DEPRECATION")
        val scanAlways = wifi.isScanAlwaysAvailable
        if (!wifi.isWifiEnabled && !scanAlways) {
            findings += Finding(Category.WIFI_NEARBY, Severity.INFO, "Wi-Fi is off",
                "Nearby Wi-Fi networks weren't scanned.", "Turn Wi-Fi on and scan again.")
            return Result(findings, emptyList(), null)
        }

        val raw = freshScanResults()
        val networks = raw.map { it.toNetwork() }

        val connected = connectedInfo()
        val connectedSsid = connected?.first

        val (nearby, flaggedSsids) = nearbyFindings(networks, connectedSsid)
        findings += nearby
        val marked = networks.map { n ->
            n.copy(flagged = n.ssid in flaggedSsids && n.security.isWeak)
        }

        findings += connectionFindings(marked, connected)
        baseline.recordWifi(marked)

        return Result(findings, marked.sortedByDescending { it.levelDbm }, connectedSsid)
    }

    // ---------------------------------------------------------------- scanning

    /**
     * Asks for a new scan and waits up to 10 s for it. Android limits apps to 4 scans per
     * 2 minutes; when throttled it returns the most recent cached results instead.
     */
    @Suppress("DEPRECATION")
    private suspend fun freshScanResults(): List<ScanResult> {
        val wm = wifi ?: return emptyList()
        withTimeoutOrNull(10_000) {
            suspendCancellableCoroutine<Unit> { cont ->
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(c: Context, i: Intent) {
                        runCatching { context.unregisterReceiver(this) }
                        if (cont.isActive) cont.resume(Unit)
                    }
                }
                ContextCompat.registerReceiver(
                    context, receiver,
                    IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                    ContextCompat.RECEIVER_NOT_EXPORTED,
                )
                cont.invokeOnCancellation { runCatching { context.unregisterReceiver(receiver) } }
                val started = runCatching { wm.startScan() }.getOrDefault(false)
                if (!started) {
                    runCatching { context.unregisterReceiver(receiver) }
                    if (cont.isActive) cont.resume(Unit)
                }
            }
        }
        return try {
            wm.scanResults ?: emptyList()
        } catch (_: SecurityException) {
            emptyList()
        }
    }

    @Suppress("DEPRECATION")
    private fun ScanResult.toNetwork(): WifiNetwork {
        val caps = capabilities ?: ""
        val security = parseSecurity(caps)
        val name = SSID?.removeSurrounding("\"")?.takeUnless { it == "<unknown ssid>" } ?: ""
        return WifiNetwork(
            ssid = name,
            bssid = BSSID ?: "",
            security = security,
            wps = caps.contains("[WPS"),
            tkipOnly = caps.contains("TKIP") && !caps.contains("CCMP"),
            levelDbm = level,
            frequencyMhz = frequency,
        )
    }

    // ---------------------------------------------------------------- nearby networks

    /** Returns the findings plus the set of SSIDs that look like evil twins. */
    private fun nearbyFindings(
        networks: List<WifiNetwork>,
        connectedSsid: String?,
    ): Pair<List<Finding>, Set<String>> {
        val out = mutableListOf<Finding>()
        val suspicious = mutableSetOf<String>()
        if (networks.isEmpty()) {
            out += Finding(Category.WIFI_NEARBY, Severity.INFO, "No nearby networks returned",
                "Android returned an empty scan. This happens if Location is off, permission was denied, " +
                    "or scans are being throttled. Wait a minute and try again.")
            return out to suspicious
        }

        // Evil twin: one network name broadcast both with and without encryption.
        val bySsid = networks.filter { it.ssid.isNotEmpty() }.groupBy { it.ssid }
        var twins = 0
        for ((ssid, aps) in bySsid) {
            val types = aps.map { it.security }.toSet()
            val weak = aps.filter { it.security.isWeak }
            val strong = aps.filter { !it.security.isWeak }
            val history = baseline.wifiSecurityHistory(ssid)
            val yours = ssid == connectedSsid
            if (weak.isNotEmpty() && strong.isNotEmpty()) {
                twins++
                suspicious += ssid
                val w = weak.maxBy { it.levelDbm }
                out += Finding(Category.WIFI_NEARBY, if (yours) Severity.HIGH else Severity.MEDIUM,
                    "Possible evil twin: \"$ssid\"",
                    "\"$ssid\" is being broadcast as ${types.joinToString { it.label }}. An open copy of a " +
                        "secured network is a classic trick to get phones to join an attacker's hotspot. " +
                        "Open copy: ${w.bssid}, ${w.levelDbm} dBm.",
                    "Don't join the open copy. In Wi-Fi settings, tap the network and check it asks for a password.")
            } else if (weak.isNotEmpty() && history.any { !it.isWeak }) {
                twins++
                suspicious += ssid
                out += Finding(Category.WIFI_NEARBY, if (yours) Severity.HIGH else Severity.MEDIUM,
                    "\"$ssid\" was secured before, now open",
                    "Earlier scans saw \"$ssid\" with ${history.filter { !it.isWeak }.joinToString { it.label }}. " +
                        "Now it's ${weak.first().security.label}. This can be a fake hotspot using the same name.",
                    "Avoid this network until you've confirmed with its owner.")
            }
        }
        if (twins == 0) {
            out += Finding(Category.WIFI_NEARBY, Severity.PASS, "No look-alike networks found",
                "${bySsid.size} network names checked for open copies of secured networks.")
        }

        val open = networks.filter { it.security == WifiSecurity.OPEN }
        if (open.isNotEmpty()) {
            out += Finding(Category.WIFI_NEARBY, Severity.INFO, "${open.size} open network(s) nearby",
                "Anyone on an open network can see unencrypted traffic. Not a threat unless you connect.",
                "If you use public Wi-Fi, use a VPN and turn off auto-connect for open networks.")
        }
        val wep = networks.filter { it.security == WifiSecurity.WEP }
        if (wep.isNotEmpty()) {
            out += Finding(Category.WIFI_NEARBY, Severity.INFO, "${wep.size} network(s) using broken WEP",
                "WEP can be cracked in minutes. Treat these as open.")
        }
        return out to suspicious
    }

    // ---------------------------------------------------------------- current connection

    /** Returns (ssid, bssid, wifiInfo) of the current Wi-Fi connection, or null. */
    @Suppress("DEPRECATION")
    private fun connectedInfo(): Triple<String, String, WifiInfo>? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
        val info = wifi?.connectionInfo ?: return null
        val ssid = info.ssid?.removeSurrounding("\"") ?: return null
        if (ssid == "<unknown ssid>" || ssid.isEmpty()) return null
        return Triple(ssid, info.bssid ?: "", info)
    }

    private fun connectionFindings(
        networks: List<WifiNetwork>,
        connected: Triple<String, String, WifiInfo>?,
    ): List<Finding> {
        val out = mutableListOf<Finding>()
        if (connected == null) {
            out += Finding(Category.WIFI_CONNECTION, Severity.INFO, "Not connected to Wi-Fi",
                "Only nearby networks and cellular were checked.")
            return out
        }
        val (ssid, bssid, info) = connected
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm?.let { it.getNetworkCapabilities(it.activeNetwork) }
        val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

        val match = networks.firstOrNull { it.bssid.equals(bssid, ignoreCase = true) }
        val security = match?.security ?: securityFromInfo(info)

        when (security) {
            WifiSecurity.OPEN, WifiSecurity.WEP -> out += Finding(Category.WIFI_CONNECTION,
                if (vpn) Severity.LOW else Severity.HIGH,
                "Connected to an unprotected network (\"$ssid\", ${security.label})",
                if (vpn) "Your VPN is encrypting traffic, which covers most of the risk."
                else "Other people on this network, or whoever runs it, can watch or tamper with unencrypted traffic.",
                "Disconnect, or turn on a VPN before using it.")
            WifiSecurity.WPA -> out += Finding(Category.WIFI_CONNECTION, Severity.MEDIUM,
                "\"$ssid\" uses outdated WPA security",
                "Original WPA/TKIP has known weaknesses.",
                "If this is your router, switch it to WPA2-AES or WPA3 in its admin page.")
            WifiSecurity.OWE -> out += Finding(Category.WIFI_CONNECTION, Severity.LOW,
                "\"$ssid\" is Enhanced Open",
                "Traffic is encrypted, but anyone can join and there's no proof the hotspot is genuine.")
            null -> out += Finding(Category.WIFI_CONNECTION, Severity.INFO,
                "Couldn't read the security type of \"$ssid\"", "The network didn't appear in the latest scan.")
            else -> out += Finding(Category.WIFI_CONNECTION, Severity.PASS,
                "\"$ssid\" uses ${security.label}", "The connection to the router is encrypted.")
        }
        if (match?.wps == true) {
            out += Finding(Category.WIFI_CONNECTION, Severity.LOW, "WPS is enabled on \"$ssid\"",
                "The WPS PIN feature on many routers can be brute-forced to reveal the Wi-Fi password.",
                "If it's your router, turn off WPS in its admin page.")
        }
        if (match?.tkipOnly == true && security != WifiSecurity.WPA) {
            out += Finding(Category.WIFI_CONNECTION, Severity.LOW, "\"$ssid\" uses the weak TKIP cipher",
                "TKIP is deprecated.", "Set the router to AES/CCMP only.")
        }
        if (caps != null) {
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) {
                out += Finding(Category.WIFI_CONNECTION, Severity.INFO, "Sign-in page network",
                    "This is a captive-portal hotspot (hotel, café, airport). Expect it to be shared and unmonitored.")
            } else if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                out += Finding(Category.WIFI_CONNECTION, Severity.LOW, "Internet access not verified",
                    "Android's connectivity check failed on this network. It may be down — or intercepting traffic.")
            }
        }

        // New access point for a network you've used before (mesh nodes also trigger this).
        val known = baseline.knownBssids(ssid)
        val realBssid = bssid.isNotEmpty() && bssid != "02:00:00:00:00:00"
        if (realBssid && known.isNotEmpty() && known.none { it.equals(bssid, true) }) {
            out += Finding(Category.WIFI_CONNECTION, Severity.INFO, "New access point for \"$ssid\"",
                "You're connected through $bssid, which hasn't been seen for this network before. " +
                    "Normal if you have mesh Wi-Fi or a new router; suspicious otherwise.")
        }
        if (realBssid) baseline.recordConnectedBssid(ssid, bssid)
        return out
    }

    private fun securityFromInfo(info: WifiInfo): WifiSecurity? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return when (info.currentSecurityType) {
            WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurity.OPEN
            WifiInfo.SECURITY_TYPE_WEP -> WifiSecurity.WEP
            WifiInfo.SECURITY_TYPE_PSK -> WifiSecurity.WPA2
            WifiInfo.SECURITY_TYPE_SAE -> WifiSecurity.WPA3
            WifiInfo.SECURITY_TYPE_OWE -> WifiSecurity.OWE
            WifiInfo.SECURITY_TYPE_EAP,
            WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE,
            WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> WifiSecurity.ENTERPRISE
            else -> null
        }
    }

    companion object {
        fun parseSecurity(caps: String): WifiSecurity {
            val c = caps.uppercase()
            return when {
                c.contains("WEP") -> WifiSecurity.WEP
                c.contains("EAP") -> WifiSecurity.ENTERPRISE
                c.contains("SAE") && c.contains("PSK") -> WifiSecurity.WPA2_WPA3
                c.contains("SAE") -> WifiSecurity.WPA3
                c.contains("OWE") -> WifiSecurity.OWE
                c.contains("RSN") || c.contains("WPA2") -> WifiSecurity.WPA2
                c.contains("WPA") -> WifiSecurity.WPA
                else -> WifiSecurity.OPEN
            }
        }
    }
}
