package com.shieldnet.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI

data class RedirectResult(
    val chain: List<String>,
    val finalUrl: String,
    val domainChanged: Boolean,
    val redirectCount: Int,
    val blocked: Boolean,
    val blockReason: String?
)

/**
 * Tier 2 Redirect Follower for Android with full SSRF and protocol protections.
 */
class RedirectResolver {

    suspend fun resolve(initialUrl: String, maxHops: Int = 10): RedirectResult = withContext(Dispatchers.IO) {
        val chain = mutableListOf(initialUrl)
        val visitedUrls = mutableSetOf(initialUrl.lowercase())
        var currentUrl = initialUrl
        var hops = 0

        while (hops < maxHops) {
            val uri = try {
                URI(currentUrl)
            } catch (e: Exception) {
                return@withContext RedirectResult(chain, currentUrl, false, hops, true, "Invalid URI syntax: $currentUrl")
            }

            val scheme = uri.scheme?.lowercase()
            if (scheme != "http" && scheme != "https") {
                return@withContext RedirectResult(chain, currentUrl, false, hops, true, "Blocked non-HTTP protocol redirect: $scheme")
            }

            val host = uri.host ?: ""
            if (host.isEmpty()) {
                return@withContext RedirectResult(chain, currentUrl, false, hops, true, "Missing hostname in redirect URL")
            }

            try {
                val addresses = InetAddress.getAllByName(host)
                if (addresses.isEmpty() || addresses.any { ReputationAnalyzer.isPrivateOrRestricted(it) }) {
                    return@withContext RedirectResult(chain, currentUrl, false, hops, true, "SSRF Blocked: Private or non-routable address for host $host")
                }
            } catch (e: Exception) {
                return@withContext RedirectResult(chain, currentUrl, false, hops, true, "Could not resolve host: $host")
            }

            var conn: HttpURLConnection? = null
            var code = -1
            var location: String? = null

            try {
                conn = uri.toURL().openConnection() as? HttpURLConnection
                if (conn == null) {
                    break
                }
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.requestMethod = "HEAD"
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) ShieldNet/1.0")
                code = conn.responseCode
                if (code in 300..399) {
                    location = conn.getHeaderField("Location")
                }
            } catch (e: Exception) {
                break
            } finally {
                try {
                    conn?.disconnect()
                } catch (e: Exception) {
                    // Ignore disconnect failure
                }
            }

            if (code in 300..399 && !location.isNullOrEmpty()) {
                val nextUrl = try {
                    uri.resolve(location).toString()
                } catch (e: Exception) {
                    break
                }

                // Detect redirect loops
                if (visitedUrls.contains(nextUrl.lowercase())) {
                    return@withContext RedirectResult(chain, currentUrl, false, hops, true, "Redirect loop detected: $nextUrl")
                }

                visitedUrls.add(nextUrl.lowercase())
                chain.add(nextUrl)
                currentUrl = nextUrl
                hops++
            } else {
                break
            }
        }

        val initialDomain = try { URI(initialUrl).host ?: "" } catch (e: Exception) { "" }
        val finalDomain = try { URI(currentUrl).host ?: "" } catch (e: Exception) { "" }

        RedirectResult(
            chain = chain,
            finalUrl = currentUrl,
            domainChanged = initialDomain.isNotEmpty() && finalDomain.isNotEmpty() && initialDomain != finalDomain,
            redirectCount = hops,
            blocked = false,
            blockReason = null
        )
    }
}
