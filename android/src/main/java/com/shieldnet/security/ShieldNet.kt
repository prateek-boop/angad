package com.shieldnet.security

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class AppMetadata(
    val packageName: String? = null,
    val appName: String? = null,
    val uid: Int = 0,
    val timestamp: Long = System.currentTimeMillis()
)

data class AndroidScanResult(
    val url: String,
    val finalUrl: String,
    val category: String,
    val riskScore: Float,
    val confidence: Float,
    val decision: String, // "allow", "review", "block"
    val reasons: List<String>,
    val probabilities: Map<String, Float>,
    val tiersRun: List<String>,
    val scanTimeMs: Long,
    val tier1Reputation: ReputationResult? = null,
    val tier2Redirect: RedirectResult? = null,
    val tier3Html: HtmlFeatures? = null,
    val tier4Visual: VisualAnalysisResult? = null,
    val appMetadata: AppMetadata? = null
)

/**
 * Complete Android ShieldNet Scanner Orchestrator.
 * Supports all 5 tiers (Tier 0 to Tier 4) natively on Android with fault tolerance.
 */
class ShieldNet(context: Context) {

    private val engine = ShieldNetEngine(context)
    private val reputation = ReputationAnalyzer()
    private val redirects = RedirectResolver()
    private val htmlAnalyzer = HtmlAnalyzer()
    private val visualAnalyzer = AndroidVisualAnalyzer(context)

    suspend fun scan(
        url: String,
        depth: String = "tier0",
        appMetadata: AppMetadata? = null
    ): AndroidScanResult = withContext(Dispatchers.Default) {
        val started = System.currentTimeMillis()
        val reasons = mutableListOf<String>()
        val tiersRun = mutableListOf("tier0")

        // 1. Tier 0: On-device ONNX Model + 41 heuristics (~15ms)
        var prediction = engine.predict(url)
        var category = prediction.category
        var riskScore = prediction.riskScore
        var confidence = prediction.confidence
        var probs = prediction.probabilities.toMutableMap()

        if (category == "safe") {
            reasons.add("No suspicious URL patterns detected by the neural network.")
        } else {
            reasons.add("Detected $category pattern in URL structure.")
        }

        var finalUrl = url
        var repResult: ReputationResult? = null
        var redirResult: RedirectResult? = null
        var htmlResult: HtmlFeatures? = null
        var visualResult: VisualAnalysisResult? = null

        // 2. Tier 1: Reputation & Infrastructure
        if (depth in listOf("tier1", "tier2", "tier3", "tier4")) {
            try {
                tiersRun.add("tier1")
                val rep = reputation.check(url)
                repResult = rep
                if (rep.isPrivateIp) {
                    reasons.add("Target resolves to a private or non-routable IP address.")
                    riskScore = 1.0f
                    category = "malware"
                } else if (rep.hasValidTls) {
                    reasons.add("Valid TLS certificate verified (${rep.tlsIssuer ?: "Trusted CA"}).")
                    riskScore = (riskScore - 0.2f).coerceAtLeast(0f)
                }
            } catch (e: Exception) {
                reasons.add("Tier 1 reputation check error: ${e.message}")
            }
        }

        // 3. Tier 2: Redirect Resolution
        if (depth in listOf("tier2", "tier3", "tier4")) {
            try {
                tiersRun.add("tier2")
                val redir = redirects.resolve(url)
                redirResult = redir
                if (redir.blocked) {
                    reasons.add("Redirect blocked by security policy: ${redir.blockReason}")
                    riskScore = 1.0f
                } else {
                    finalUrl = redir.finalUrl
                    if (redir.domainChanged) {
                        reasons.add("Redirect chain crosses over to another domain: $finalUrl")
                        // Rescore destination with Tier 0
                        val destPrediction = engine.predict(finalUrl)
                        if (destPrediction.riskScore > riskScore) {
                            prediction = destPrediction
                            riskScore = destPrediction.riskScore
                            category = destPrediction.category
                            confidence = destPrediction.confidence
                            probs = destPrediction.probabilities.toMutableMap()
                        }
                    }
                }
            } catch (e: Exception) {
                reasons.add("Tier 2 redirect resolution error: ${e.message}")
            }
        }

        // 4. Tier 3: HTML Credential Harvesting Analysis
        if (depth in listOf("tier3", "tier4")) {
            try {
                tiersRun.add("tier3")
                val html = htmlAnalyzer.analyze(finalUrl)
                htmlResult = html
                if (html.hasPasswordField && html.formDomainMismatch) {
                    reasons.add("HTML inspection detected a login form submitting credentials to an external domain!")
                    riskScore = 1.0f
                    category = "phishing"
                    probs["phishing"] = 0.99f
                    probs["safe"] = 0.01f
                } else if (html.titleBrandMismatch) {
                    reasons.add("Page <title> claims a known brand name that does not match the actual domain.")
                    riskScore = riskScore.coerceAtLeast(0.85f)
                    category = "phishing"
                }
            } catch (e: Exception) {
                reasons.add("Tier 3 HTML analysis error: ${e.message}")
            }
        }

        // 5. Tier 4: Visual Perception (Headless WebView Screenshot + 64-bit DCT pHash)
        if (depth == "tier4") {
            try {
                tiersRun.add("tier4")
                val visual = visualAnalyzer.analyze(finalUrl)
                visualResult = visual
                if (visual.captured && visual.matchedBrand != null) {
                    if (!visual.domainMatches) {
                        reasons.add("CRITICAL VISUAL MATCH: Rendered page is visually identical to ${visual.matchedBrand} (${String.format("%.1f", visual.similarityPercent)}% match), but domain does NOT match!")
                        category = "phishing"
                        riskScore = 1.0f
                        probs["phishing"] = 0.99f
                        probs["safe"] = 0.01f
                    } else {
                        reasons.add("Visual page matches genuine ${visual.matchedBrand} domain.")
                        riskScore = (riskScore - 0.3f).coerceAtLeast(0f)
                    }
                }
            } catch (e: Exception) {
                reasons.add("Tier 4 visual perception error: ${e.message}")
            }
        }

        // Final Decision Engine
        val decision = when {
            riskScore >= 0.65f -> "block"
            riskScore >= 0.35f -> "review"
            else -> "allow"
        }

        val elapsed = System.currentTimeMillis() - started

        AndroidScanResult(
            url = url,
            finalUrl = finalUrl,
            category = category,
            riskScore = riskScore,
            confidence = confidence,
            decision = decision,
            reasons = reasons,
            probabilities = probs,
            tiersRun = tiersRun,
            scanTimeMs = elapsed,
            tier1Reputation = repResult,
            tier2Redirect = redirResult,
            tier3Html = htmlResult,
            tier4Visual = visualResult,
            appMetadata = appMetadata
        )
    }

    fun close() {
        try {
            engine.close()
        } catch (e: Exception) {
            // Ignore
        }
    }
}
