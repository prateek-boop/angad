package com.shieldnet.security

import java.net.URI
import kotlin.math.ln

/**
 * 41-feature engineered risk extractor for Android.
 * Matches the ShieldNet feature specification contract with robust URL parsing.
 */
class FeatureExtractor {

    companion object {
        const val NUM_FEATURES = 41

        val SUSPICIOUS_TLDS = setOf(
            "xyz", "top", "work", "loan", "click", "country", "link", "gq",
            "cf", "ga", "ml", "tk", "men", "club", "vip", "fit", "buzz"
        )
        val MISLEADING_TLDS = setOf("zip", "mov")
        val SUSPICIOUS_EXTENSIONS = setOf(
            "exe", "scr", "bat", "cmd", "vbs", "ps1", "apk", "jar", "msi", "sh"
        )
        val KNOWN_BRANDS = setOf(
            "paypal", "apple", "google", "microsoft", "amazon", "netflix",
            "facebook", "instagram", "chase", "wellsfargo", "bankofamerica"
        )
        val LOGIN_KEYWORDS = setOf("login", "signin", "log-in", "sign-in")
        val SECURE_KEYWORDS = setOf("secure", "security")
        val ACCOUNT_KEYWORDS = setOf("account", "bill", "billing")
        val UPDATE_KEYWORDS = setOf("update", "upgrade")
        val VERIFY_KEYWORDS = setOf("verify", "verification")
        val BANK_KEYWORDS = setOf("bank", "banking", "wallet")
        val URL_SHORTENERS = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd")
    }

    fun extract(url: String): FloatArray {
        val features = FloatArray(NUM_FEATURES)
        if (url.isBlank()) return features

        val urlLower = url.lowercase().trim()
        val normalizedUrl = if (url.contains("://")) url else "http://$url"

        var host = ""
        var path = ""
        var query = ""
        var fragment = ""
        var scheme = ""
        var port = -1

        try {
            val uri = URI(normalizedUrl)
            host = uri.host ?: ""
            path = uri.path ?: ""
            query = uri.query ?: ""
            fragment = uri.fragment ?: ""
            scheme = uri.scheme?.lowercase() ?: ""
            port = uri.port
        } catch (e: Exception) {
            // Robust fallback parsing for unescaped or non-standard characters
            try {
                val afterScheme = normalizedUrl.substringAfter("://")
                val authAndRest = afterScheme.split("/", limit = 2)
                val authority = authAndRest[0]
                val rest = if (authAndRest.size > 1) "/" + authAndRest[1] else ""

                val hostPort = authority.substringBefore("@").let { if (authority.contains("@")) authority.substringAfter("@") else authority }
                if (hostPort.contains(":")) {
                    host = hostPort.substringBefore(":")
                    port = hostPort.substringAfter(":").toIntOrNull() ?: -1
                } else {
                    host = hostPort
                }

                val pathPart = rest.substringBefore("?").substringBefore("#")
                path = pathPart
                if (rest.contains("?")) {
                    query = rest.substringAfter("?").substringBefore("#")
                }
                if (rest.contains("#")) {
                    fragment = rest.substringAfter("#")
                }
                scheme = normalizedUrl.substringBefore("://").lowercase()
            } catch (ex: Exception) {
                // If all fails, use minimal defaults
                host = ""
            }
        }

        val pathSegments = path.split("/").filter { it.isNotEmpty() }
        val subdomains = host.split(".").filter { it.isNotEmpty() }
        val tld = if (subdomains.size > 1) subdomains.last() else ""
        val registeredDomain = if (subdomains.size >= 2) subdomains[subdomains.size - 2] else host

        features[0] = url.length.toFloat()
        features[1] = url.count { it == '.' }.toFloat()
        features[2] = url.count { it == '-' }.toFloat()
        features[3] = url.count { it == '_' }.toFloat()
        features[4] = url.count { it.isDigit() }.toFloat()
        features[5] = url.count { !it.isLetterOrDigit() && ":/.-_?&=%#@~+".indexOf(it) == -1 }.toFloat()
        features[6] = if (url.contains("@")) 1f else 0f
        features[7] = pathSegments.size.toFloat()
        features[8] = if (query.isNotEmpty()) query.split("&").size.toFloat() else 0f
        features[9] = if (fragment.isNotEmpty()) 1f else 0f
        features[10] = shannonEntropy(url)
        features[11] = maxConsecutiveConsonants(url).toFloat()
        features[12] = host.length.toFloat()
        features[13] = (subdomains.size - 2).coerceAtLeast(0).toFloat()
        features[14] = if (isIpAddress(host)) 1f else 0f
        features[15] = if (URL_SHORTENERS.any { host == it || host.endsWith(".$it") }) 1f else 0f
        features[16] = if (SUSPICIOUS_TLDS.contains(tld)) 1f else 0f
        features[17] = if (host.contains("xn--")) 1f else 0f
        features[18] = digitRatio(registeredDomain)
        features[19] = tld.length.toFloat()
        features[20] = if (urlLower.startsWith("https://")) 1f else 0f
        features[21] = if (port != -1) 1f else 0f
        features[22] = if (port == -1 || port == 80 || port == 443) 1f else 0f
        features[23] = if (path.contains("//")) 1f else 0f
        features[24] = "%[0-9a-fA-F]{2}".toRegex().findAll(url).count().toFloat()
        val ext = path.substringAfterLast(".", "")
        features[25] = if (path.contains(".") && SUSPICIOUS_EXTENSIONS.contains(ext.lowercase())) 1f else 0f
        features[26] = if (LOGIN_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[27] = if (SECURE_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[28] = if (ACCOUNT_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[29] = if (UPDATE_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[30] = if (VERIFY_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[31] = if (BANK_KEYWORDS.any { urlLower.contains(it) }) 1f else 0f
        features[32] = brandImpersonationScore(urlLower, registeredDomain)
        features[33] = if ("(url|redirect|next|dest|continue)=https?".toRegex(RegexOption.IGNORE_CASE).containsMatchIn(query)) 1f else 0f
        features[34] = if (subdomains.size > 3) 1f else 0f
        features[35] = randomDomainScore(registeredDomain)
        features[36] = if (subdomains.any { it.length > 20 }) 1f else 0f
        features[37] = if (url.isNotEmpty()) (path.length.toFloat() / url.length.toFloat()) else 0f
        features[38] = if (KNOWN_BRANDS.any { host.contains(it) && !registeredDomain.contains(it) }) 1f else 0f
        features[39] = if (MISLEADING_TLDS.contains(tld)) 1f else 0f
        features[40] = if ("[Ѐ-ӿͰ-Ͽ]".toRegex().containsMatchIn(host)) 1f else 0f

        return features
    }

    private fun shannonEntropy(s: String): Float {
        if (s.isEmpty()) return 0f
        val counts = s.groupingBy { it }.eachCount()
        val len = s.length.toDouble()
        var entropy = 0.0
        for (count in counts.values) {
            val p = count / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy.toFloat()
    }

    private fun maxConsecutiveConsonants(s: String): Int {
        val consonants = "bcdfghjklmnpqrstvwxyz"
        var best = 0
        var run = 0
        for (c in s.lowercase()) {
            if (consonants.indexOf(c) != -1) {
                run++
                if (run > best) best = run
            } else {
                run = 0
            }
        }
        return best
    }

    private fun isIpAddress(host: String): Boolean {
        return "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$".toRegex().matches(host)
    }

    private fun digitRatio(s: String): Float {
        if (s.isEmpty()) return 0f
        return s.count { it.isDigit() }.toFloat() / s.length.toFloat()
    }

    private fun brandImpersonationScore(urlLower: String, domain: String): Float {
        var hits = 0
        for (brand in KNOWN_BRANDS) {
            if (urlLower.contains(brand) && !domain.contains(brand)) {
                hits++
            }
        }
        return (hits / 3f).coerceAtMost(1f)
    }

    private fun randomDomainScore(label: String): Float {
        if (label.length < 4) return 0f
        var score = 0f
        if (shannonEntropy(label) > 3.5f) score += 0.4f
        if (maxConsecutiveConsonants(label) >= 5) score += 0.3f
        if (digitRatio(label) > 0.3f) score += 0.3f
        return score.coerceAtMost(1f)
    }
}
