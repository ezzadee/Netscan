package com.netsentry.app.scan

import android.content.Context
import android.os.Build
import android.telephony.CellIdentityNr
import android.telephony.CellInfo
import android.telephony.CellInfoCdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.CellSignalStrengthNr
import android.telephony.TelephonyManager
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * Looks for warning signs of a fake cell tower (an "IMSI catcher" / cell-site simulator).
 * A phone can't prove a tower is fake, so these are indicators, not verdicts.
 */
class CellScanner(private val context: Context, private val baseline: Baseline) {

    data class Result(val findings: List<Finding>, val cells: List<CellTower>)

    private val tm = context.getSystemService(TelephonyManager::class.java)

    suspend fun scan(): Result {
        val findings = mutableListOf<Finding>()
        if (tm == null || tm.simState != TelephonyManager.SIM_STATE_READY) {
            findings += Finding(Category.CELLULAR, Severity.INFO, "No active SIM",
                "Cellular checks need a working SIM or eSIM.")
            return Result(findings, emptyList())
        }

        val infos = freshCellInfo()
        val now = System.currentTimeMillis()
        val learning = baseline.cellCount() < 25
        val cells = infos.mapNotNull { it.toTower() }.map { c ->
            c.copy(firstSeenNow = c.key != null && baseline.cell(c.key!!) == null)
        }
        val serving = cells.filter { it.serving }
        val neighbors = cells.filter { !it.serving }

        // ---- Network generation (the key downgrade-attack signal)
        val gen = currentGeneration()
        val servingGen = serving.firstOrNull()?.generation ?: gen
        val modernNearby = neighbors.any { it.generation == "4G" || it.generation == "5G" }
        when (servingGen) {
            "2G" -> findings += Finding(Category.CELLULAR,
                if (modernNearby) Severity.HIGH else Severity.MEDIUM,
                if (modernNearby) "Dropped to 2G while 4G/5G towers are in range" else "Phone is connected over 2G",
                "2G has no way to check that a tower is genuine and uses weak or no encryption. Fake towers " +
                    "often force phones down to 2G. Most US carriers have shut 2G down, so a 2G connection here is unusual.",
                "Turn off 2G: Settings > Network & internet > SIMs > Allow 2G (Android 12+ on most phones; " +
                    "on Samsung: Connections > Mobile networks > Network mode, choose LTE/5G only).")
            "3G" -> findings += Finding(Category.CELLULAR, Severity.LOW, "Phone is connected over 3G",
                "Major US carriers have retired 3G, so being on it is unexpected. It may be a roaming partner " +
                    "or a misreport by the modem.",
                "If this keeps happening where you normally get 4G/5G, scan again and note the location.")
            "4G", "5G" -> findings += Finding(Category.CELLULAR, Severity.PASS, "Connected over $servingGen",
                "4G and 5G authenticate the network to your phone, which blocks the simplest fake-tower attacks.")
            else -> findings += Finding(Category.CELLULAR, Severity.INFO, "Network type unknown",
                "Grant the Phone permission so the app can read the network type.")
        }

        // ---- Country code doesn't match the SIM while not roaming
        val simMcc = tm.simOperator?.take(3)
        val servingMcc = serving.firstOrNull()?.mcc
        if (!simMcc.isNullOrEmpty() && !servingMcc.isNullOrEmpty() && servingMcc != simMcc && !tm.isNetworkRoaming) {
            findings += Finding(Category.CELLULAR, Severity.MEDIUM, "Tower country code doesn't match your SIM",
                "Serving tower reports country code $servingMcc; your SIM is $simMcc and the phone says it isn't roaming.")
        }

        // ---- Changes against the towers this phone has seen before
        var lacChanges = 0
        for (c in cells) {
            val key = c.key ?: continue
            val prev = baseline.cell(key) ?: continue
            if (prev.areaCode != null && c.areaCode != null && prev.areaCode != c.areaCode) {
                lacChanges++
                findings += Finding(Category.CELLULAR, if (c.serving) Severity.MEDIUM else Severity.LOW,
                    "Tower ${c.cellId} changed its area code",
                    "This ${c.radio} cell was seen with area code ${prev.areaCode}, now ${c.areaCode}. Real towers rarely " +
                        "change this; fake towers that copy a real cell ID often use a different one. Carrier " +
                        "maintenance can also cause it.")
            }
        }

        serving.firstOrNull()?.let { s ->
            if (s.cellId == null) {
                findings += Finding(Category.CELLULAR, Severity.LOW, "Serving tower didn't report an ID",
                    "The phone is registered on a ${s.radio} cell with no valid cell ID. Some modems do this; so do some simulators.")
            }
            val veryStrong = s.dbm != null && s.dbm > strongThreshold(s.radio)
            if (s.firstSeenNow && !learning && veryStrong) {
                findings += Finding(Category.CELLULAR, Severity.LOW, "New, unusually strong tower",
                    "You're on a ${s.radio} cell (ID ${s.cellId}) never seen before, at ${s.dbm} dBm. Fake towers " +
                        "tend to be close by and very loud. A new small cell or being next to a real tower also does this.")
            }
            if ((s.generation == "4G" || s.generation == "5G") && neighbors.isEmpty()) {
                findings += Finding(Category.CELLULAR, Severity.INFO, "Serving tower lists no neighbors",
                    "Real networks usually advertise nearby cells. Some phones just don't report them, so treat this as a weak signal.")
            }
        }

        if (learning) {
            findings += Finding(Category.CELLULAR, Severity.INFO, "Learning the towers around you",
                "${baseline.cellCount()} cells recorded so far. Scan at home, work and on your commute over a few days " +
                    "so changes stand out.")
        } else if (lacChanges == 0) {
            findings += Finding(Category.CELLULAR, Severity.PASS, "Towers match what's been seen before",
                "${cells.count { !it.firstSeenNow }} of ${cells.size} visible cells are known, with no area-code changes.")
        }

        if (Build.VERSION.SDK_INT >= 35) {
            findings += Finding(Category.CELLULAR, Severity.INFO, "Turn on your phone's own fake-tower alerts",
                "Android 15+ on some phones (Pixel, newer Samsung) can warn you about unencrypted connections and " +
                    "requests for your phone's identity.",
                "Settings > Security & privacy > More security settings > Mobile network security (if your phone has it).")
        }

        baseline.recordCells(cells, now)
        return Result(findings, cells.sortedWith(compareByDescending<CellTower> { it.serving }.thenByDescending { it.dbm ?: -200 }))
    }

    private fun strongThreshold(radio: String) = when (radio) {
        "LTE", "NR" -> -65     // RSRP
        else -> -55
    }

    // ------------------------------------------------------------ reading cell info

    private suspend fun freshCellInfo(): List<CellInfo> {
        val manager = tm ?: return emptyList()
        val fresh = try {
            withTimeoutOrNull(6_000) {
                suspendCancellableCoroutine<List<CellInfo>> { cont ->
                    manager.requestCellInfoUpdate(context.mainExecutor,
                        object : TelephonyManager.CellInfoCallback() {
                            override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                                if (cont.isActive) cont.resume(cellInfo)
                            }

                            override fun onError(errorCode: Int, detail: Throwable?) {
                                if (cont.isActive) cont.resume(emptyList())
                            }
                        })
                }
            }
        } catch (_: SecurityException) {
            null
        }
        if (!fresh.isNullOrEmpty()) return fresh
        return try {
            manager.allCellInfo ?: emptyList()
        } catch (_: SecurityException) {
            emptyList()
        }
    }

    private fun currentGeneration(): String? {
        val type = try {
            tm?.dataNetworkType ?: return null
        } catch (_: SecurityException) {
            return null
        }
        return when (type) {
            TelephonyManager.NETWORK_TYPE_GPRS, TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_CDMA, TelephonyManager.NETWORK_TYPE_1xRTT,
            TelephonyManager.NETWORK_TYPE_IDEN, TelephonyManager.NETWORK_TYPE_GSM -> "2G"
            TelephonyManager.NETWORK_TYPE_UMTS, TelephonyManager.NETWORK_TYPE_EVDO_0,
            TelephonyManager.NETWORK_TYPE_EVDO_A, TelephonyManager.NETWORK_TYPE_EVDO_B,
            TelephonyManager.NETWORK_TYPE_HSDPA, TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_HSPA, TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_EHRPD, TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "3G"
            TelephonyManager.NETWORK_TYPE_LTE, TelephonyManager.NETWORK_TYPE_IWLAN -> "4G"
            TelephonyManager.NETWORK_TYPE_NR -> "5G"
            else -> null
        }
    }

    private fun valid(v: Int): Long? = if (v == CellInfo.UNAVAILABLE || v < 0) null else v.toLong()
    private fun dbm(v: Int): Int? = if (v == CellInfo.UNAVAILABLE || v >= 0) null else v

    private fun CellInfo.toTower(): CellTower? = when (this) {
        is CellInfoLte -> CellTower("LTE", "4G", cellIdentity.mccString, cellIdentity.mncString,
            valid(cellIdentity.tac), valid(cellIdentity.ci), valid(cellIdentity.pci)?.toInt(),
            dbm(cellSignalStrength.dbm), isRegistered)
        is CellInfoNr -> {
            val id = cellIdentity as CellIdentityNr
            val sig = cellSignalStrength as CellSignalStrengthNr
            CellTower("NR", "5G", id.mccString, id.mncString, valid(id.tac),
                id.nci.takeIf { it != CellInfo.UNAVAILABLE_LONG && it >= 0 },
                valid(id.pci)?.toInt(), dbm(sig.dbm), isRegistered)
        }
        is CellInfoGsm -> CellTower("GSM", "2G", cellIdentity.mccString, cellIdentity.mncString,
            valid(cellIdentity.lac), valid(cellIdentity.cid), null, dbm(cellSignalStrength.dbm), isRegistered)
        is CellInfoWcdma -> CellTower("WCDMA", "3G", cellIdentity.mccString, cellIdentity.mncString,
            valid(cellIdentity.lac), valid(cellIdentity.cid), valid(cellIdentity.psc)?.toInt(),
            dbm(cellSignalStrength.dbm), isRegistered)
        is CellInfoTdscdma -> CellTower("TD-SCDMA", "3G", cellIdentity.mccString, cellIdentity.mncString,
            valid(cellIdentity.lac), valid(cellIdentity.cid), null, dbm(cellSignalStrength.dbm), isRegistered)
        is CellInfoCdma -> CellTower("CDMA", "2G", null, valid(cellIdentity.systemId)?.toString(),
            valid(cellIdentity.networkId), valid(cellIdentity.basestationId), null,
            dbm(cellSignalStrength.dbm), isRegistered)
        else -> null
    }
}
