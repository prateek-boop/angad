# ShieldNet Android SDK & NetGuard Mobile Firewall

Native Android security library combining on-device machine learning with a non-root transparent VPN firewall.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────────────────────┐
                      │                 Android Device                         │
                      │                                                        │
                      │  [Outbound Network Traffic from all Apps & Browser]    │
                      │                           │                            │
                      │                           ▼                            │
                      │           ShieldNetVpnService (tun0 interface)         │
                      │                           │                            │
                      │                           ▼                            │
                      │             Extract TLS ClientHello SNI                │
                      │                           │                            │
                      │                           ▼                            │
                      │         ┌───────────────────────────────────┐          │
                      │         │    ShieldNet Scanner Engine       │          │
                      │         │                                   │          │
                      │         │  Tier 0: ONNX Model (~18ms)       │          │
                      │         │  Tier 1: DNS & TLS Validity       │          │
                      │         │  Tier 2: Redirect Resolution      │          │
                      │         │  Tier 3: HTML Form Analysis       │          │
                      │         │  Tier 4: Headless WebView pHash   │          │
                      │         └─────────────────┬─────────────────┘          │
                      │                           │                            │
                      │                  Verdict Decision?                     │
                      │                           │                            │
                      │               ├──▶ ALLOW: Forward packet               │
                      │               └──▶ BLOCK: Drop packet immediately      │
                      └────────────────────────────────────────────────────────┘
```

---

## Features

* **Zero-Root Operation**: Uses standard `android.net.VpnService` to inspect traffic across all mobile applications without requiring root privileges or Shizuku/ADB.
* **On-Device Machine Learning (Tier 0)**: Powered by `onnxruntime-android` running the 28MB quantized BERT-Small model in **~15–25ms** on mobile ARM CPUs with zero network bandwidth.
* **Native Tier 4 Visual Perception**: Employs an off-screen, sandboxed Android `WebView` (Chromium) to render suspicious landing pages and computes a **64-bit DCT perceptual hash (`pHash`)** in **<2ms**, matching visually identical phishing traps against known brand portals.
* **Pre-Relay Dropping**: Malicious packets are dropped before forwarding a single byte to the destination server.

---

## Components

| Component | File | Purpose |
|---|---|---|
| **Core Orchestrator** | `ShieldNet.kt` | Coordinates Tiers 0 to 4 and produces final verdicts. |
| **ONNX Threat Engine** | `ShieldNetEngine.kt` | Executes the quantized subword model + 41 heuristics on-device. |
| **WordPiece Tokenizer** | `WordPieceTokenizer.kt` | Subword tokenizer matching HuggingFace BertTokenizer token-for-token. |
| **Visual Impersonation** | `AndroidVisualAnalyzer.kt` | Tier 4 headless WebView screenshot & 64-bit DCT pHash. |
| **Feature Extractor** | `FeatureExtractor.kt` | 41 engineered URL risk features in pure Kotlin. |
| **Reputation Inspector** | `ReputationAnalyzer.kt` | Tier 1 DNS resolution, private IP / SSRF blocking, and TLS cert check. |
| **Redirect Resolver** | `RedirectResolver.kt` | Tier 2 HTTP redirect unrolling with SSRF guard. |
| **HTML Harvester** | `HtmlAnalyzer.kt` | Tier 3 Jsoup form and password harvesting detection. |
| **VPN Firewall** | `ShieldNetVpnService.kt` | Packet-level interceptor reading TLS SNI on `tun0`. |

---

## Gradle Setup

Add the following to your Android application's `build.gradle.kts`:

```kotlin
dependencies {
    // ONNX Runtime Android
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.18.0")

    // HTML analysis & networking
    implementation("org.jsoup:jsoup:1.17.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
```

Copy the ONNX model files from `android/src/main/assets/` into your app's `src/main/assets/` directory:
* `model_quantized.onnx` (28.9 MB)
* `tokenizer.json` (711 KB)
* `config.json`

---

## How to Use in Your Android App

### 1. Direct URL Scan (Any App or Activity)

```kotlin
import com.shieldnet.security.ShieldNet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

val shieldNet = ShieldNet(context)

CoroutineScope(Dispatchers.Main).launch {
    // Fast instant check (~20ms)
    val tier0Result = shieldNet.scan("https://github.com/torvalds/linux", depth = "tier0")
    println("Decision: ${tier0Result.decision}, Risk: ${tier0Result.riskScore}")

    // Full 5-tier check including WebView visual screenshot
    val fullResult = shieldNet.scan("https://example.com", depth = "tier4")
    println("Full Scan Category: ${fullResult.category}")
    println("Similarity: ${fullResult.tier4Visual?.similarityPercent}%")
    println("Page Hash: ${fullResult.tier4Visual?.pageHash}")
    println("Matched Brand: ${fullResult.tier4Visual?.matchedBrand}")
    for (reason in fullResult.reasons) {
        println(" - $reason")
    }
}
```

### Result & Evidence Metadata

`AndroidScanResult` returns structured metadata across all tiers:

```kotlin
data class AndroidScanResult(
    val url: String,                           // Original target URL
    val finalUrl: String,                      // Unrolled destination URL after redirects
    val category: String,                      // "safe", "phishing", "malware", "scam"
    val riskScore: Float,                      // Fused threat score 0.0 - 1.0
    val confidence: Float,                     // Model prediction confidence
    val decision: String,                      // "allow", "review", or "block"
    val reasons: List<String>,                 // Human-readable evidence items
    val probabilities: Map<String, Float>,     // Class distribution
    val tiersRun: List<String>,                // ["tier0", "tier1", "tier2", "tier3", "tier4"]
    val scanTimeMs: Long,                      // Total wall-clock time in ms
    val tier1Reputation: ReputationResult?,    // DNS, resolved IPs, private IP / SSRF, TLS cert
    val tier2Redirect: RedirectResult?,        // Hop chain, domain change, SSRF guard
    val tier3Html: HtmlFeatures?,              // Forms, password inputs, hidden fields, scripts
    val tier4Visual: VisualAnalysisResult?,    // pHash hex, brand, distance, similarity %, render ms
    val appMetadata: AppMetadata?              // Calling app package name, UID, timestamp
)
```

### 2. Start the Global NetGuard VPN Firewall

In your Activity:

```kotlin
import android.net.VpnService
import android.content.Intent

val intent = VpnService.prepare(context)
if (intent != null) {
    // Request user permission for VPN
    startActivityForResult(intent, 0)
} else {
    // Permission already granted, start the firewall service
    val serviceIntent = Intent(context, ShieldNetVpnService::class.java)
    context.startService(serviceIntent)
}
```
