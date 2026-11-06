package com.netsentry.app.scan

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Remembers what "normal" looks like in the places you use the phone, so later scans
 * can spot changes: a Wi-Fi name that used to be secured showing up open, or a cell
 * tower whose area code suddenly changed. Stored only on the phone.
 */
class Baseline(context: Context) {

    private val prefs = context.getSharedPreferences("baseline", Context.MODE_PRIVATE)

    // ---------- Wi-Fi: SSID -> security types seen ----------

    fun wifiSecurityHistory(ssid: String): Set<WifiSecurity> {
        val obj = JSONObject(prefs.getString(KEY_WIFI, "{}") ?: "{}")
        val arr = obj.optJSONArray(ssid) ?: return emptySet()
        return (0 until arr.length()).mapNotNull { i ->
            runCatching { WifiSecurity.valueOf(arr.getString(i)) }.getOrNull()
        }.toSet()
    }

    fun recordWifi(networks: List<WifiNetwork>) {
        val obj = JSONObject(prefs.getString(KEY_WIFI, "{}") ?: "{}")
        networks.filter { it.ssid.isNotEmpty() && !it.flagged }.forEach { net ->
            val existing = obj.optJSONArray(net.ssid) ?: JSONArray()
            val values = (0 until existing.length()).map { existing.getString(it) }.toMutableSet()
            values += net.security.name
            obj.put(net.ssid, JSONArray(values.toList()))
        }
        // Keep the file small: drop the oldest entries past 1,500 SSIDs.
        while (obj.length() > 1500) obj.remove(obj.keys().next())
        prefs.edit().putString(KEY_WIFI, obj.toString()).apply()
    }

    // ---------- Wi-Fi: access points seen for the network you connect to ----------

    fun knownBssids(ssid: String): Set<String> {
        val obj = JSONObject(prefs.getString(KEY_HOME_APS, "{}") ?: "{}")
        val arr = obj.optJSONArray(ssid) ?: return emptySet()
        return (0 until arr.length()).map { arr.getString(it) }.toSet()
    }

    fun recordConnectedBssid(ssid: String, bssid: String) {
        val obj = JSONObject(prefs.getString(KEY_HOME_APS, "{}") ?: "{}")
        val arr = obj.optJSONArray(ssid) ?: JSONArray()
        val set = (0 until arr.length()).map { arr.getString(it) }.toMutableSet()
        set += bssid
        obj.put(ssid, JSONArray(set.toList()))
        prefs.edit().putString(KEY_HOME_APS, obj.toString()).apply()
    }

    // ---------- Cellular: cell key -> area code, first seen, times seen ----------

    data class CellRecord(val areaCode: Long?, val firstSeen: Long, val timesSeen: Int)

    fun cell(key: String): CellRecord? {
        val obj = JSONObject(prefs.getString(KEY_CELLS, "{}") ?: "{}")
        val rec = obj.optJSONObject(key) ?: return null
        return CellRecord(
            areaCode = if (rec.has("area")) rec.getLong("area") else null,
            firstSeen = rec.optLong("first"),
            timesSeen = rec.optInt("seen"),
        )
    }

    fun cellCount(): Int = JSONObject(prefs.getString(KEY_CELLS, "{}") ?: "{}").length()

    fun recordCells(cells: List<CellTower>, now: Long) {
        val obj = JSONObject(prefs.getString(KEY_CELLS, "{}") ?: "{}")
        cells.forEach { c ->
            val key = c.key ?: return@forEach
            val rec = obj.optJSONObject(key) ?: JSONObject().put("first", now).put("seen", 0)
            rec.put("seen", rec.optInt("seen") + 1)
            if (c.areaCode != null) rec.put("area", c.areaCode)
            obj.put(key, rec)
        }
        while (obj.length() > 3000) obj.remove(obj.keys().next())
        prefs.edit().putString(KEY_CELLS, obj.toString()).apply()
    }

    fun clear() = prefs.edit().clear().apply()

    private companion object {
        const val KEY_WIFI = "wifi_security"
        const val KEY_HOME_APS = "connected_aps"
        const val KEY_CELLS = "cells"
    }
}
