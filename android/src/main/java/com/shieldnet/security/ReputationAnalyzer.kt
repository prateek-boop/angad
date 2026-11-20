package com.shieldnet.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.URI
import javax.net.ssl.HttpsURLConnection

data class ReputationResult(
    val dnsResolves: Boolean,
    val ipAddresses: List<String>,
    val isPrivateIp: Boolean,
    val hasValidTls: Boolean,
    val tlsIssuer: String?
)

/**
 * Tier 1 Reputation Analyzer for Android.
 * Checks DNS resolution, comprehensive SSRF non-public IP protection, and TLS certificates.
 */
class ReputationAnalyzer {

    companion object {
        fun isPrivateOrRestricted(addr: InetAddress): Boolean {
            if (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress ||
                addr.isAnyLocalAddress || addr.isMulticastAddress) {
                return true
            }
            val bytes = addr.address
            if (bytes.size == 4) { // IPv4
                val b0 = bytes[0].toInt() and 0xFF
                val b1 = bytes[1].toInt() and 0xFF
                val b2 = bytes[2].toInt() and 0xFF
                // 0.0.0.0/8
                if (b0 == 0) return true
                // 100.64.0.0/10 (Carrier Grade NAT)
                if (b0 == 100 && (b1 and 0xC0) == 64) return true
                // 192.0.0.0/24 (IETF Protocol Assignments)
                if (b0 == 192 && b1 == 0 && b2 == 0) return true
                // 192.0.2.0/24 (TEST-NET-1)
                if (b0 == 192 && b1 == 0 && b2 == 2) return true
                // 198.51.100.0/24 (TEST-NET-2)
                if (b0 == 198 && b1 == 51 && b2 == 100) return true
                // 203.0.113.0/24 (TEST-NET-3)
                if (b0 == 203 && b1 == 0 && b2 == 113) return true
                // 255.255.255.255 (Broadcast)
                if (b0 == 255 && b1 == 255 && b2 == 255 && (bytes[3].toInt() and 0xFF) == 255) return true
            } else if (bytes.size == 16) { // IPv6
                val b0 = bytes[0].toInt() and 0xFF
                // fc00::/7 (Unique Local Address)
                if ((b0 and 0xFE) == 0xFC) return true
                // fe80::/10 (Link-Local)
                if (b0 == 0xFE && (bytes[1].toInt() and 0xC0) == 0x80) return true
            }
            return false
        }
    }

    suspend fun check(url: String): ReputationResult = withContext(Dispatchers.IO) {
        val host = try {
            val uri = URI(if (url.contains("://")) url else "http://$url")
            uri.host ?: ""
        } catch (e: Exception) {
            ""
        }

        if (host.isEmpty()) {
            return@withContext ReputationResult(false, emptyList(), false, false, null)
        }

        var dnsResolves = false
        val ips = mutableListOf<String>()
        var isPrivate = false

        try {
            val addresses = InetAddress.getAllByName(host)
            dnsResolves = addresses.isNotEmpty()
            for (addr in addresses) {
                ips.add(addr.hostAddress ?: "")
                if (isPrivateOrRestricted(addr)) {
                    isPrivate = true
                }
            }
        } catch (e: Exception) {
            dnsResolves = false
        }

        var hasTls = false
        var issuer: String? = null

        if (url.startsWith("https://", ignoreCase = true) && dnsResolves && !isPrivate) {
            var conn: HttpsURLConnection? = null
            try {
                conn = URI(url).toURL().openConnection() as? HttpsURLConnection
                if (conn != null) {
                    conn.connectTimeout = 3500
                    conn.readTimeout = 3500
                    conn.instanceFollowRedirects = false
                    conn.requestMethod = "HEAD"
                    conn.connect()
                    val certs = conn.serverCertificates
                    if (certs != null && certs.isNotEmpty()) {
                        hasTls = true
                        issuer = (certs[0] as? java.security.cert.X509Certificate)?.issuerX500Principal?.name
                    }
                }
            } catch (e: Exception) {
                hasTls = false
            } finally {
                try {
                    conn?.disconnect()
                } catch (e: Exception) {
                    // Ignore disconnect errors
                }
            }
        }

        ReputationResult(
            dnsResolves = dnsResolves,
            ipAddresses = ips,
            isPrivateIp = isPrivate,
            hasValidTls = hasTls,
            tlsIssuer = issuer
        )
    }
}
