package com.netsentry.app.apps

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class AppsState(
    val scanning: Boolean = false,
    val done: Int = 0,
    val total: Int = 0,
    val current: String = "",
    val apps: List<AppReport>? = null,
)

class AppsViewModel(app: Application) : AndroidViewModel(app) {

    private val inventory = AppInventory(app)
    private val _state = MutableStateFlow(AppsState())
    val state: StateFlow<AppsState> = _state.asStateFlow()

    fun scan() {
        if (_state.value.scanning) return
        _state.update { it.copy(scanning = true, done = 0, total = 0, current = "") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                inventory.scan { done, total, label ->
                    _state.update { it.copy(done = done, total = total, current = label) }
                }
            }.getOrNull()
            _state.update { it.copy(scanning = false, apps = result ?: it.apps) }
        }
    }
}
