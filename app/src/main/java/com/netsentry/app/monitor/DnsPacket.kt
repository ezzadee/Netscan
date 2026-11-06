package com.netsentry.app.monitor

import java.net.InetAddress

/** Minimal IPv4 + UDP + DNS parsing and building, just enough to relay DNS lookups. */
object DnsPacket {

    class Query(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val dns: ByteArray,
        val name: String,
        val qtype: Int,
    )

    /** Parses an IPv4/UDP packet addressed to port 53. Returns null for anything else. */
    fun parseQuery(p: ByteArray, len: Int): Query? {
        if (len < 28) return null
        if ((p[0].toInt() shr 4) != 4) return null
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return null
        if (p[9].toInt() and 0xFF != 17) return null       // UDP only
        val srcIp = p.copyOfRange(12, 16)
        val dstIp = p.copyOfRange(16, 20)
        val srcPort = u16(p, ihl)
        val dstPort = u16(p, ihl + 2)
        if (dstPort != 53) return null
        val udpLen = u16(p, ihl + 4)
        val payloadLen = minOf(udpLen - 8, len - ihl - 8)
        if (payloadLen < 12) return null
        val dns = p.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
        if (u16(dns, 4) < 1) return null                   // no question
        val (name, end) = readName(dns, 12) ?: return null
        if (end + 4 > dns.size) return null
        val qtype = u16(dns, end)
        return Query(srcIp, dstIp, srcPort, dstPort, dns, name, qtype)
    }

    /** Wraps a DNS response in IPv4/UDP headers, sent from the DNS address back to the app. */
    fun buildResponse(q: Query, dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        val out = ByteArray(total)
        out[0] = 0x45
        put16(out, 2, total)
        put16(out, 6, 0x4000)                             // don't fragment
        out[8] = 64                                         // TTL
        out[9] = 17                                         // UDP
        System.arraycopy(q.dstIp, 0, out, 12, 4)
        System.arraycopy(q.srcIp, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20))
        put16(out, 20, q.dstPort)
        put16(out, 22, q.srcPort)
        put16(out, 24, 8 + dns.size)
        put16(out, 26, 0)                                   // UDP checksum optional on IPv4
        System.arraycopy(dns, 0, out, 28, dns.size)
        return out
    }

    /** Pulls the IP addresses (A / AAAA records) and the result code out of a DNS response. */
    fun parseAnswers(dns: ByteArray): Pair<Int, List<String>> {
        if (dns.size < 12) return -1 to emptyList()
        val rcode = dns[3].toInt() and 0x0F
        val qd = u16(dns, 4)
        val an = u16(dns, 6)
        var pos = 12
        repeat(qd) {
            pos = skipName(dns, pos) ?: return rcode to emptyList()
            pos += 4
        }
        val ips = mutableListOf<String>()
        repeat(an) {
            pos = skipName(dns, pos) ?: return rcode to ips
            if (pos + 10 > dns.size) return rcode to ips
            val type = u16(dns, pos)
            val rdLen = u16(dns, pos + 8)
            pos += 10
            if (pos + rdLen > dns.size) return rcode to ips
            if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                runCatching { InetAddress.getByAddress(dns.copyOfRange(pos, pos + rdLen)).hostAddress }
                    .getOrNull()?.let { if (ips.size < 6) ips += it }
            }
            pos += rdLen
        }
        return rcode to ips
    }

    fun typeName(t: Int): String = when (t) {
        1 -> "A"
        28 -> "AAAA"
        5 -> "CNAME"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        33 -> "SRV"
        64 -> "SVCB"
        65 -> "HTTPS"
        else -> "TYPE$t"
    }

    // ---------------------------------------------------------------- helpers

    private fun readName(b: ByteArray, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var pos = start
        var end = -1
        var jumps = 0
        while (true) {
            if (pos >= b.size) return null
            val l = b[pos].toInt() and 0xFF
            when {
                l == 0 -> { if (end < 0) end = pos + 1; break }
                l and 0xC0 == 0xC0 -> {
                    if (pos + 1 >= b.size || ++jumps > 10) return null
                    if (end < 0) end = pos + 2
                    pos = ((l and 0x3F) shl 8) or (b[pos + 1].toInt() and 0xFF)
                }
                else -> {
                    if (pos + 1 + l > b.size) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(b, pos + 1, l, Charsets.ISO_8859_1))
                    pos += 1 + l
                }
            }
        }
        return sb.toString().lowercase() to end
    }

    private fun skipName(b: ByteArray, start: Int): Int? {
        var pos = start
        while (pos < b.size) {
            val l = b[pos].toInt() and 0xFF
            if (l == 0) return pos + 1
            if (l and 0xC0 == 0xC0) return if (pos + 2 <= b.size) pos + 2 else null
            pos += 1 + l
        }
        return null
    }

    private fun u16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, at: Int, v: Int) {
        b[at] = (v shr 8).toByte()
        b[at + 1] = v.toByte()
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len) {
            sum += u16(b, i)
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}
