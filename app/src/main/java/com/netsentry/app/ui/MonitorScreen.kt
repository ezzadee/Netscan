package com.netsentry.app.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netsentry.app.apps.Trackers
import com.netsentry.app.monitor.DnsEvent
import com.netsentry.app.monitor.DnsMonitorService
import com.netsentry.app.monitor.MonitorChecks
import com.netsentry.app.monitor.MonitorRepository
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private data class DomainStat(val domain: String, val count: Int, val last: Long, val owner: String?, val ip: String?)

private data class AppTraffic(
    val key: String,
    val label: String,
    val packageName: String,
    val lookups: Int,
    val domains: List<DomainStat>,
) {
    val trackerDomains: Int get() = domains.count { it.owner != null }
}

private val timeFmt = SimpleDateFormat("MMM d, h:mm:ss a", Locale.US)

@Composable
fun MonitorScreen() {
    val context = LocalContext.current
    val running by MonitorRepository.running.collectAsState()
    val events by MonitorRepository.events.collectAsState()
    val error by MonitorRepository.error.collectAsState()
    var view by rememberSaveable { mutableIntStateOf(0) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == Activity.RESULT_OK) DnsMonitorService.start(context)
        else MonitorRepository.setError("The monitor needs Android's VPN permission to see lookups.")
    }
    val start = {
        val prepare = VpnService.prepare(context)
        if (prepare == null) DnsMonitorService.start(context) else vpnLauncher.launch(prepare)
    }

    val warnings = remember(running) { MonitorChecks.warnings(context, running) }
    val byApp = remember(events) { groupByApp(events) }
    val trackers = remember(events) { trackerSummary(events) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Panel {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Dot(if (running) Palette.Accent else Palette.Line, 10)
                        Spacer(Modifier.width(8.dp))
                        Text(if (running) "Monitoring connections" else "Monitor is off",
                            color = Palette.Text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (running) "${events.size} lookups logged from ${byApp.size} apps. Use your phone normally; " +
                            "this keeps running in the background (you'll see a key icon in the status bar)."
                        else "Logs every server each app looks up before it connects. It runs as a local VPN that " +
                            "only handles lookups — your traffic isn't routed anywhere new and nothing leaves the phone.",
                        color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp,
                    )
                    Spacer(Modifier.height(14.dp))
                    if (running) {
                        PrimaryButton("Stop monitoring", color = Palette.Medium) { DnsMonitorService.stop(context) }
                    } else {
                        PrimaryButton("Start monitoring", onClick = start)
                    }
                    error?.let {
                        Spacer(Modifier.height(8.dp))
                        Text(it, color = Palette.High, fontSize = 12.sp)
                    }
                }
            }
        }

        warnings.forEach { w ->
            item {
                Panel {
                    Row {
                        Dot(Palette.Medium)
                        Spacer(Modifier.width(8.dp))
                        Text(w, color = Palette.Text, fontSize = 13.sp, lineHeight = 18.sp)
                    }
                }
            }
        }

        if (events.isNotEmpty()) {
            item {
                SegmentedTabs(listOf("By app", "Trackers", "Recent"), view) { view = it }
            }
            when (view) {
                0 -> items(byApp, key = { "a-" + it.key }) { AppTrafficCard(it) }
                1 -> {
                    if (trackers.isEmpty()) item { EmptyNote("No lookups to known tracker or ad servers yet.") }
                    items(trackers, key = { "t-" + it.first }) { (owner, apps, count) ->
                        Panel {
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(owner, color = Palette.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold,
                                        modifier = Modifier.weight(1f))
                                    Badge("$count lookups", Palette.Low)
                                }
                                Spacer(Modifier.height(4.dp))
                                Text("Contacted by: ${apps.joinToString()}", color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp)
                            }
                        }
                    }
                }
                else -> items(events.take(300)) { RecentRow(it) }
            }
            item {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = { shareCsv(context, events) }) {
                        Text("Share log (CSV)", color = Palette.Info, fontSize = 13.sp)
                    }
                    TextButton(onClick = { MonitorRepository.clear() }) {
                        Text("Clear log", color = Palette.Muted, fontSize = 13.sp)
                    }
                }
            }
        } else {
            item {
                EmptyNote(
                    "What it can't see: apps that use their own encrypted DNS (Chrome's \"Use secure DNS\", " +
                        "Firefox) or connect to a hard-coded IP address without a lookup. Most apps use normal " +
                        "lookups, so this catches the large majority of connections."
                )
            }
        }
    }
}

@Composable
private fun AppTrafficCard(a: AppTraffic) {
    var open by rememberSaveable(a.key) { mutableStateOf(false) }
    Panel(onClick = { open = !open }) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(a.label, color = Palette.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (a.packageName.isNotEmpty()) {
                        Text(a.packageName, color = Palette.Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
                Spacer(Modifier.width(8.dp))
                Column(horizontalAlignment = Alignment.End) {
                    Text("${a.domains.size} servers", color = Palette.Text, fontSize = 13.sp)
                    if (a.trackerDomains > 0) Badge("${a.trackerDomains} trackers", Palette.Low)
                }
            }
            if (open) {
                Spacer(Modifier.height(8.dp))
                Text("${a.lookups} lookups. Yellow tags mark known tracking or ad companies.",
                    color = Palette.Muted, fontSize = 12.sp)
                Spacer(Modifier.height(4.dp))
                a.domains.forEach { d ->
                    Column(Modifier.padding(vertical = 3.dp)) {
                        HostLine(d.domain, d.owner, "${d.count}×")
                        Text(
                            listOfNotNull(d.ip, "last ${timeFmt.format(Date(d.last))}").joinToString(" · "),
                            color = Palette.Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun RecentRow(e: DnsEvent) {
    Panel {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(e.appLabel, color = Palette.Text, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Text(timeFmt.format(Date(e.time)), color = Palette.Muted, fontSize = 11.sp)
            }
            Spacer(Modifier.height(2.dp))
            HostLine(e.domain, Trackers.ownerOf(e.domain), if (e.ok) e.type else "failed")
        }
    }
}

private fun groupByApp(events: List<DnsEvent>): List<AppTraffic> =
    events.groupBy { if (it.packageName.isEmpty()) "uid:${it.uid}" else it.packageName }
        .map { (key, evs) ->
            val domains = evs.groupBy { it.domain }.map { (d, list) ->
                DomainStat(
                    domain = d,
                    count = list.size,
                    last = list.maxOf { it.time },
                    owner = Trackers.ownerOf(d),
                    ip = list.firstOrNull { it.ips.isNotEmpty() }?.ips?.first(),
                )
            }.sortedByDescending { it.count }
            AppTraffic(key, evs.first().appLabel, evs.first().packageName, evs.size, domains)
        }
        .sortedByDescending { it.domains.size }

/** (tracker company, apps that contacted it, lookup count) */
private fun trackerSummary(events: List<DnsEvent>): List<Triple<String, List<String>, Int>> =
    events.mapNotNull { e -> Trackers.ownerOf(e.domain)?.let { it to e } }
        .groupBy({ it.first }, { it.second })
        .map { (owner, evs) -> Triple(owner, evs.map { it.appLabel }.distinct(), evs.size) }
        .sortedByDescending { it.third }

private fun shareCsv(context: android.content.Context, events: List<DnsEvent>) {
    val sb = StringBuilder("time,app,package,domain,type,ips,tracker\n")
    events.take(3000).forEach { e ->
        fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""
        sb.append(q(timeFmt.format(Date(e.time)))).append(',')
            .append(q(e.appLabel)).append(',')
            .append(q(e.packageName)).append(',')
            .append(q(e.domain)).append(',')
            .append(e.type).append(',')
            .append(q(e.ips.joinToString(" "))).append(',')
            .append(q(Trackers.ownerOf(e.domain) ?: ""))
            .append('\n')
    }
    val send = Intent(Intent.ACTION_SEND)
        .setType("text/csv")
        .putExtra(Intent.EXTRA_SUBJECT, "NetSentry connection log")
        .putExtra(Intent.EXTRA_TEXT, sb.toString())
    context.startActivity(Intent.createChooser(send, "Share connection log").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}
