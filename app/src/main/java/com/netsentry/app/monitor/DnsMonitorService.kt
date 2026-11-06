package com.netsentry.app.monitor

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * A local, on-phone VPN that only carries DNS. Android hands every app's server lookups
 * to it; it records which app asked for which server, forwards the lookup to your normal
 * DNS server, and passes the answer back. All other traffic never enters the tunnel.
 */
class DnsMonitorService : VpnService() {

    companion object {
        const val ACTION_STOP = "com.netsentry.app.STOP_MONITOR"
        private const val TUN_ADDR = "10.111.222.1"
        private const val DNS_ADDR = "10.111.222.2"

        fun start(context: Context) {
            context.startService(Intent(context, DnsMonitorService::class.java))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, DnsMonitorService::class.java).setAction(ACTION_STOP))
        }

        /** Non-VPN network that carries internet, with its link properties. */
        fun underlying(cm: ConnectivityManager): Pair<Network, LinkProperties?>? {
            @Suppress("DEPRECATION")
            val nets = cm.allNetworks
            val candidates = nets.filter { n ->
                val c = cm.getNetworkCapabilities(n) ?: return@filter false
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
            val best = candidates.firstOrNull { n ->
                cm.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            } ?: candidates.firstOrNull() ?: return null
            return best to cm.getLinkProperties(best)
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var out: FileOutputStream? = null
    private val outLock = Any()
    private var pool: ExecutorService? = null
    @Volatile private var running = false

    private val labels = ConcurrentHashMap<Int, Pair<String, String>>()
    @Volatile private var upstream: Pair<Network?, List<InetAddress>> = null to emptyList()
    @Volatile private var upstreamCheckedAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        MonitorRepository.init(this)
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running) startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        refreshUpstream(force = true)
        val builder = Builder()
            .setSession("NetSentry connection monitor")
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32)
            .setBlocking(true)
            .setMetered(false)
        runCatching { builder.addDisallowedApplication(packageName) }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }
        if (pfd == null) {
            MonitorRepository.setError("Android didn't allow the monitor to start. Open NetSentry and tap Start again.")
            stopSelf()
            return
        }
        tun = pfd
        out = FileOutputStream(pfd.fileDescriptor)
        pool = Executors.newFixedThreadPool(6)
        running = true
        MonitorRepository.setRunning(true)

        thread(name = "netsentry-tun", isDaemon = true) { readLoop(pfd) }
    }

    private fun readLoop(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val n = try {
                input.read(buf)
            } catch (_: Exception) {
                break
            }
            if (n <= 0) continue
            val q = DnsPacket.parseQuery(buf, n) ?: continue   // e.g. DNS-over-TLS probes: dropped
            pool?.execute { handle(q) }
        }
    }

    private fun handle(q: DnsPacket.Query) {
        val uid = ownerUid(q)
        val (pkg, label) = appFor(uid)
        val response = forward(q.dns)
        if (response != null) {
            val packet = DnsPacket.buildResponse(q, response)
            synchronized(outLock) { runCatching { out?.write(packet) } }
        }
        val (rcode, ips) = if (response != null) DnsPacket.parseAnswers(response) else (-1 to emptyList())
        MonitorRepository.add(
            DnsEvent(
                time = System.currentTimeMillis(),
                uid = uid,
                packageName = pkg,
                appLabel = label,
                domain = q.name,
                type = DnsPacket.typeName(q.qtype),
                ips = ips,
                ok = response != null && rcode == 0,
            )
        )
    }

    private fun ownerUid(q: DnsPacket.Query): Int = try {
        val cm = getSystemService(ConnectivityManager::class.java) ?: throw IllegalStateException()
        cm.getConnectionOwnerUid(
            OsConstants.IPPROTO_UDP,
            InetSocketAddress(InetAddress.getByAddress(q.srcIp), q.srcPort),
            InetSocketAddress(InetAddress.getByAddress(q.dstIp), q.dstPort),
        )
    } catch (_: Exception) {
        Process.INVALID_UID
    }

    private fun appFor(uid: Int): Pair<String, String> {
        labels[uid]?.let { return it }
        val result = when {
            uid < 0 -> "" to "Unknown app"
            uid < Process.FIRST_APPLICATION_UID -> "android" to "Android system"
            else -> {
                val pkgs = packageManager.getPackagesForUid(uid) ?: emptyArray()
                val pkg = pkgs.firstOrNull()
                if (pkg == null) "" to "App (uid $uid)" else {
                    val label = runCatching {
                        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
                    }.getOrDefault(pkg)
                    val suffix = if (pkgs.size > 1) " + ${pkgs.size - 1} shared" else ""
                    pkg to label + suffix
                }
            }
        }
        labels[uid] = result
        return result
    }

    // ------------------------------------------------------------ forwarding

    private fun refreshUpstream(force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force && now - upstreamCheckedAt < 30_000) return
        upstreamCheckedAt = now
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val u = underlying(cm)
        val servers = u?.second?.dnsServers.orEmpty()
        upstream = u?.first to servers.ifEmpty {
            listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("9.9.9.9"))
        }
    }

    private fun forward(query: ByteArray): ByteArray? {
        refreshUpstream()
        val (network, servers) = upstream
        for (server in servers.take(3)) {
            try {
                DatagramSocket().use { s ->
                    protect(s)
                    if (network != null) runCatching { network.bindSocket(s) }
                    s.soTimeout = 4000
                    s.send(DatagramPacket(query, query.size, server, 53))
                    val buf = ByteArray(4096)
                    val resp = DatagramPacket(buf, buf.size)
                    s.receive(resp)
                    return buf.copyOf(resp.length)
                }
            } catch (_: Exception) {
                // try the next server
            }
        }
        refreshUpstream(force = true)
        return null
    }

    // ------------------------------------------------------------ lifecycle

    override fun onRevoke() {
        // Another VPN started, or the user disconnected us in Settings.
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        running = false
        runCatching { tun?.close() }
        tun = null
        out = null
        pool?.shutdownNow()
        pool = null
        MonitorRepository.setRunning(false)
    }
}
