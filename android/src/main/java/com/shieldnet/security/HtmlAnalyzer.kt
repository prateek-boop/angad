package com.shieldnet.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jsoup.Jsoup
import java.net.URI

data class HtmlFeatures(
    val hasPasswordField: Boolean,
    val passwordFieldCount: Int,
    val formCount: Int,
    val formDomainMismatch: Boolean,
    val hiddenInputCount: Int,
    val scriptCount: Int,
    val title: String,
    val titleBrandMismatch: Boolean,
    val error: String? = null
)

/**
 * Tier 3 HTML Form & Credential Harvester Analyzer for Android.
 * Inspects DOM for password fields, cross-domain exfiltration forms, and brand spoofing.
 */
class HtmlAnalyzer {

    suspend fun analyze(url: String, timeoutMs: Int = 5000): HtmlFeatures = withContext(Dispatchers.IO) {
        val host = try {
            URI(if (url.contains("://")) url else "http://$url").host ?: ""
        } catch (e: Exception) {
            ""
        }

        try {
            val doc = Jsoup.connect(url)
                .timeout(timeoutMs)
                .userAgent("Mozilla/5.0 (Linux; Android 14) ShieldNet/1.0")
                .maxBodySize(2 * 1024 * 1024)
                .followRedirects(true)
                .get()

            val forms = doc.select("form")
            val passwordInputs = doc.select("input[type=password]")
            val hiddenInputs = doc.select("input[type=hidden]")
            val scripts = doc.select("script")
            val title = doc.title().trim()

            var formDomainMismatch = false
            for (form in forms) {
                // Use absUrl to automatically resolve relative and protocol-relative (//) URLs
                var targetAction = form.absUrl("action")
                if (targetAction.isEmpty()) {
                    targetAction = form.attr("action")
                }

                if (targetAction.isNotEmpty()) {
                    val actionHost = try {
                        val norm = if (targetAction.startsWith("//")) "https:$targetAction" else targetAction
                        URI(norm).host ?: ""
                    } catch (e: Exception) {
                        ""
                    }

                    if (actionHost.isNotEmpty() && host.isNotEmpty() &&
                        !actionHost.equals(host, ignoreCase = true) &&
                        !actionHost.endsWith(".$host", ignoreCase = true)) {
                        formDomainMismatch = true
                    }
                }
            }

            var titleMismatch = false
            val titleLower = title.lowercase()
            for (brand in FeatureExtractor.KNOWN_BRANDS) {
                if (titleLower.contains(brand) && !host.contains(brand, ignoreCase = true)) {
                    titleMismatch = true
                    break
                }
            }

            HtmlFeatures(
                hasPasswordField = passwordInputs.isNotEmpty(),
                passwordFieldCount = passwordInputs.size,
                formCount = forms.size,
                formDomainMismatch = formDomainMismatch,
                hiddenInputCount = hiddenInputs.size,
                scriptCount = scripts.size,
                title = title,
                titleBrandMismatch = titleMismatch
            )
        } catch (e: Exception) {
            HtmlFeatures(
                hasPasswordField = false,
                passwordFieldCount = 0,
                formCount = 0,
                formDomainMismatch = false,
                hiddenInputCount = 0,
                scriptCount = 0,
                title = "",
                titleBrandMismatch = false,
                error = e.message
            )
        }
    }
}
