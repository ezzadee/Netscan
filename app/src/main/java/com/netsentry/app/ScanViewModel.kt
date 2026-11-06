package com.netsentry.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.netsentry.app.scan.Baseline
import com.netsentry.app.scan.CellScanner
import com.netsentry.app.scan.DeviceScanner
import com.netsentry.app.scan.Finding
import com.netsentry.app.scan.ScanReport
import com.netsentry.app.scan.Severity
import com.netsentry.app.scan.WifiScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class UiState(
    val scanning: Boolean = false,
    val step: String = "",
    val report: ScanReport? = null,
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val baseline = Baseline(app)
    private val device = DeviceScanner(app)
    private val wifi = WifiScanner(app, baseline)
    private val cell = CellScanner(app, baseline)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun scan(missingPermissions: List<String>) {
        if (_state.value.scanning) return
        viewModelScope.launch {
            _state.value = _state.value.copy(scanning = true, step = "Scanning Wi-Fi and cell towers…")
            val wifiJob = async { runCatching { wifi.scan() }.getOrNull() }
            val cellJob = async { runCatching { cell.scan() }.getOrNull() }
            val deviceFindings = withContext(Dispatchers.Default) {
                runCatching { device.scan() }.getOrDefault(emptyList())
            }
            val w = wifiJob.await()
            val c = cellJob.await()

            val findings = buildList {
                if (missingPermissions.isNotEmpty()) {
                    add(Finding(com.netsentry.app.scan.Category.DEVICE, Severity.INFO,
                        "Some permissions were denied",
                        "Missing: ${missingPermissions.joinToString { it.substringAfterLast('.') }}. " +
                            "Results for Wi-Fi and cellular will be incomplete.",
                        "Settings > Apps > NetSentry > Permissions."))
                }
                addAll(deviceFindings)
                w?.let { addAll(it.findings) }
                c?.let { addAll(it.findings) }
            }
            _state.value = UiState(
                scanning = false,
                report = ScanReport(
                    timestamp = System.currentTimeMillis(),
                    findings = findings,
                    wifiNetworks = w?.networks.orEmpty(),
                    cells = c?.cells.orEmpty(),
                    connectedSsid = w?.connectedSsid,
                ),
            )
        }
    }

    fun resetBaseline() {
        baseline.clear()
    }
}
