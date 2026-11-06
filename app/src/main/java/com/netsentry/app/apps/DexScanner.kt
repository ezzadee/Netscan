package com.netsentry.app.apps

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Reads the string table of every classes*.dex file inside an APK — without running or
 * decompiling anything — to find:
 *  - class names that belong to known tracker SDKs
 *  - web addresses (http/https) hard-coded into the app, i.e. servers it is built to contact
 */
object DexScanner {

    data class Result(val trackers: Set<TrackerSdk>, val hosts: Set<String>)

    private const val MAX_DEX_BYTES = 80 * 1024 * 1024
    private const val MAX_HOSTS = 300

    private val dexName = Regex("""classes\d*\.dex""")
    private val urlRegex =Regex("""https?://([A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9])""")

    /** Hosts that appear in nearly every app as XML namespaces, licenses or docs — not connections. */
    private val noiseSuffixes = listOf(
        "schemas.android.com", "w3.org", "ns.adobe.com", "xmlpull.org", "apache.org",
        "json-schema.org", "schemas.microsoft.com", "purl.org", "xml.org", "example.com",
        "example.org", "example.net", "localhost", "schema.org", "opensource.org",
        "creativecommons.org", "gnu.org", "mozilla.org", "jquery.com", "github.com",
        "stackoverflow.com", "developer.android.com", "android.com", "unicode.org",
        "openxmlformats.org", "xmlsoap.org", "ietf.org", "oasis-open.org", "kotlinlang.org",
        "javax.xml", "java.sun.com", "oracle.com", "jetbrains.com", "goo.gl", "bit.ly",
    )

    // Tracker prefixes as dex type descriptors: "com.appsflyer." -> "Lcom/appsflyer/"
    private val descriptorPrefixes: List<Pair<ByteArray, TrackerSdk>> = Trackers.sdks.flatMap { sdk ->
        sdk.prefixes.map { p -> ("L" + p.replace('.', '/')).toByteArray(Charsets.US_ASCII) to sdk }
    }

    private val HTTP = "http".toByteArray(Charsets.US_ASCII)

    fun scan(apkPaths: List<String>): Result {
        val trackers = mutableSetOf<TrackerSdk>()
        val hosts = linkedSetOf<String>()
        for (path in apkPaths) {
            if (!File(path).canRead()) continue
            try {
                ZipFile(path).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val e = entries.nextElement()
                        if (!dexName.matches(e.name)) continue
                        if (e.size > MAX_DEX_BYTES) continue
                        val bytes = zip.getInputStream(e).use { it.readBytes() }
                        scanDex(bytes, trackers, hosts)
                    }
                }
            } catch (_: Exception) {
                // Unreadable or unusual APK: skip it.
            }
        }
        return Result(trackers, hosts)
    }

    private fun scanDex(b: ByteArray, trackers: MutableSet<TrackerSdk>, hosts: MutableSet<String>) {
        if (b.size < 0x70 || b[0] != 'd'.code.toByte() || b[1] != 'e'.code.toByte() || b[2] != 'x'.code.toByte()) return
        val buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
        val count = buf.getInt(0x38)
        val idsOff = buf.getInt(0x3C)
        if (count <= 0 || idsOff <= 0 || idsOff.toLong() + count.toLong() * 4 > b.size) return

        for (i in 0 until count) {
            var p = buf.getInt(idsOff + i * 4)
            if (p <= 0 || p >= b.size) continue
            // Skip the ULEB128 length prefix.
            while (p < b.size && (b[p].toInt() and 0x80) != 0) p++
            p++
            if (p >= b.size) continue
            val start = p
            while (p < b.size && b[p] != 0.toByte()) p++
            val end = p
            val len = end - start
            if (len < 4) continue

            if (b[start] == 'L'.code.toByte()) {
                for ((prefix, sdk) in descriptorPrefixes) {
                    if (sdk in trackers || prefix.size > len) continue
                    if (regionMatches(b, start, prefix)) trackers += sdk
                }
            } else if (hosts.size < MAX_HOSTS && contains(b, start, end, HTTP)) {
                val s = String(b, start, len, Charsets.ISO_8859_1)
                urlRegex.findAll(s).forEach { m ->
                    val host = m.groupValues[1].lowercase()
                    if (isUseful(host)) hosts += host
                }
            }
        }
    }

    private fun isUseful(host: String): Boolean {
        if (!host.contains('.')) return false
        val tld = host.substringAfterLast('.')
        val isIp = host.all { it.isDigit() || it == '.' }
        if (!isIp && (tld.length < 2 || !tld.all { it.isLetter() })) return false
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || host == "0.0.0.0") return false
        return noiseSuffixes.none { host == it || host.endsWith(".$it") }
    }

    private fun regionMatches(b: ByteArray, at: Int, prefix: ByteArray): Boolean {
        if (at + prefix.size > b.size) return false
        for (k in prefix.indices) if (b[at + k] != prefix[k]) return false
        return true
    }

    private fun contains(b: ByteArray, from: Int, to: Int, needle: ByteArray): Boolean {
        var i = from
        val last = to - needle.size
        while (i <= last) {
            if (b[i] == needle[0] && regionMatches(b, i, needle)) return true
            i++
        }
        return false
    }
}
