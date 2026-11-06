package com.netsentry.app.monitor

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

/** One server lookup an app made while the monitor was running. */
data class DnsEvent(
    val time: Long,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val domain: String,
    val type: String,
    val ips: List<String>,
    val ok: Boolean,
)

/**
 * Shared between the VPN service and the UI (same process). Keeps the newest events in
 * memory and appends every event to a file so the log survives restarts.
 */
object MonitorRepository {

    private const val MEMORY_CAP = 8000
    private const val FILE_CAP = 30000

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _events = MutableStateFlow<List<DnsEvent>>(emptyList())
    /** Newest first. */
    val events: StateFlow<List<DnsEvent>> = _events.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val io = Executors.newSingleThreadExecutor()
    @Volatile private var loaded = false
    private var file: File? = null

    fun init(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            val f = File(context.applicationContext.filesDir, "dns_log.jsonl")
            file = f
            loaded = true
            io.execute {
                val lines = runCatching { if (f.exists()) f.readLines() else emptyList() }.getOrDefault(emptyList())
                val parsed = lines.takeLast(MEMORY_CAP).mapNotNull { fromJson(it) }.reversed()
                _events.update { current -> (current + parsed).take(MEMORY_CAP) }
                if (lines.size > FILE_CAP) {
                    runCatching { f.writeText(lines.takeLast(FILE_CAP / 2).joinToString("\n", postfix = "\n")) }
                }
            }
        }
    }

    fun setRunning(value: Boolean) {
        _running.value = value
        if (value) _error.value = null
    }

    fun setError(message: String?) {
        _error.value = message
    }

    fun add(e: DnsEvent) {
        _events.update { listOf(e) + it.take(MEMORY_CAP - 1) }
        val f = file ?: return
        io.execute { runCatching { f.appendText(toJson(e) + "\n") } }
    }

    fun clear() {
        _events.value = emptyList()
        val f = file ?: return
        io.execute { runCatching { f.delete() } }
    }

    private fun toJson(e: DnsEvent): String = JSONObject()
        .put("t", e.time).put("u", e.uid).put("p", e.packageName).put("l", e.appLabel)
        .put("d", e.domain).put("y", e.type).put("i", JSONArray(e.ips)).put("ok", e.ok)
        .toString()

    private fun fromJson(s: String): DnsEvent? = runCatching {
        val o = JSONObject(s)
        val ips = o.optJSONArray("i")
        DnsEvent(
            time = o.getLong("t"),
            uid = o.optInt("u", -1),
            packageName = o.optString("p"),
            appLabel = o.optString("l"),
            domain = o.getString("d"),
            type = o.optString("y"),
            ips = if (ips == null) emptyList() else (0 until ips.length()).map { ips.getString(it) },
            ok = o.optBoolean("ok", true),
        )
    }.getOrNull()
}
