package com.netsentry.app.monitor

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/** Things that would stop the monitor from seeing lookups, shown before and while it runs. */
object MonitorChecks {

    fun warnings(context: Context, monitorRunning: Boolean): List<String> {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val out = mutableListOf<String>()

        val u = DnsMonitorService.underlying(cm)
        val strictHost = u?.second?.privateDnsServerName
        if (strictHost != null) {
            out += "Private DNS is set to \"$strictHost\", so Android encrypts lookups and sends them " +
                "straight to that server, past the monitor. While monitoring, set Settings > Network & " +
                "internet > Private DNS to Automatic, then switch it back after."
        }

        if (!monitorRunning) {
            val active = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            if (active?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                out += "Another VPN is on. Android allows one VPN at a time, so starting the monitor will " +
                    "turn it off until you stop monitoring."
            }
        }
        return out
    }
}
