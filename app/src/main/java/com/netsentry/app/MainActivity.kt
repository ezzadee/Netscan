package com.netsentry.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.netsentry.app.apps.AppsViewModel
import com.netsentry.app.monitor.MonitorRepository
import com.netsentry.app.ui.AppsScreen
import com.netsentry.app.ui.MonitorScreen
import com.netsentry.app.ui.NetSentryTheme
import com.netsentry.app.ui.Palette
import com.netsentry.app.ui.ScanScreen
import com.netsentry.app.ui.SegmentedTabs

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        MonitorRepository.init(this)
        setContent { NetSentryTheme { App() } }
    }
}

@Composable
private fun App() {
    val scanVm: ScanViewModel = viewModel()
    val appsVm: AppsViewModel = viewModel()
    var screen by rememberSaveable { mutableIntStateOf(0) }

    Column(
        Modifier
            .fillMaxSize()
            .background(Palette.Bg)
            .windowInsetsPadding(WindowInsets.safeDrawing)
    ) {
        Column(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 12.dp)) {
            Text("NetSentry", color = Palette.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold)
            Text("Network, app and device security check", color = Palette.Muted, fontSize = 14.sp,
                modifier = Modifier.padding(bottom = 12.dp))
            SegmentedTabs(listOf("Scan", "Apps", "Monitor"), screen) { screen = it }
        }
        Box(Modifier.weight(1f)) {
            when (screen) {
                0 -> ScanScreen(scanVm)
                1 -> AppsScreen(appsVm)
                else -> MonitorScreen()
            }
        }
    }
}
