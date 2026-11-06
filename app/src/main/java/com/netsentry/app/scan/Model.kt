package com.netsentry.app.scan

enum class Severity(val weight: Int, val label: String) {
    HIGH(25, "High"),
    MEDIUM(10, "Medium"),
    LOW(4, "Low"),
    INFO(0, "Info"),
    PASS(0, "OK"),
}

enum class Category(val title: String) {
    DEVICE("This phone"),
    WIFI_CONNECTION("Current Wi-Fi connection"),
    WIFI_NEARBY("Nearby Wi-Fi"),
    CELLULAR("Cellular network"),
}

data class Finding(
    val category: Category,
    val severity: Severity,
    val title: String,
    val detail: String,
    val fix: String? = null,
)

enum class WifiSecurity(val label: String, val rank: Int) {
    OPEN("Open", 0),
    WEP("WEP", 1),
    WPA("WPA (old)", 2),
    OWE("Enhanced Open", 3),
    WPA2("WPA2", 4),
    WPA2_WPA3("WPA2/WPA3", 5),
    WPA3("WPA3", 6),
    ENTERPRISE("Enterprise", 6),
    ;

    /** True for networks that send traffic without real protection. */
    val isWeak: Boolean get() = this == OPEN || this == WEP
}

data class WifiNetwork(
    val ssid: String,          // "" for hidden networks
    val bssid: String,
    val security: WifiSecurity,
    val wps: Boolean,
    val tkipOnly: Boolean,
    val levelDbm: Int,
    val frequencyMhz: Int,
    val flagged: Boolean = false,
) {
    val band: String
        get() = when {
            frequencyMhz >= 5925 -> "6 GHz"
            frequencyMhz >= 4900 -> "5 GHz"
            else -> "2.4 GHz"
        }
}

data class CellTower(
    val radio: String,         // GSM, WCDMA, LTE, NR, CDMA, TD-SCDMA
    val generation: String,    // 2G, 3G, 4G, 5G
    val mcc: String?,
    val mnc: String?,
    val areaCode: Long?,       // LAC or TAC
    val cellId: Long?,         // CID / CI / NCI
    val pci: Int?,
    val dbm: Int?,
    val serving: Boolean,
    val firstSeenNow: Boolean = false,
) {
    /** Stable key that identifies one physical cell, without the area code. */
    val key: String? get() = if (cellId == null) null else "$radio:$mcc-$mnc:$cellId"
}

data class ScanReport(
    val timestamp: Long,
    val findings: List<Finding>,
    val wifiNetworks: List<WifiNetwork>,
    val cells: List<CellTower>,
    val connectedSsid: String?,
) {
    val score: Int get() = (100 - findings.sumOf { it.severity.weight }).coerceIn(0, 100)
}
