# ShieldNet & NetGuard Android APK Integration Specification

This specification details the architecture, code assets, dependencies, and configuration required to embed ShieldNet's multi-tier URL threat intelligence and NetGuard's mobile firewall into an Android Application (APK).

---

## 1. Architectural Overview & Integration Modes

ShieldNet supports three flexible integration architectures inside an Android app:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Android Application                             │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │               Integration Mode A: On-Device Native             │   │
│   │                                                                │   │
│   │   [Outbound App / Browser Traffic]                             │   │
│   │                  │                                             │   │
│   │                  ▼                                             │   │
│   │       ShieldNetVpnService (tun0)                               │   │
│   │                  │                                             │   │
│   │                  ▼                                             │   │
│   │         TLS SNI Parser (Port 443)                              │   │
│   │                  │                                             │   │
│   │                  ▼                                             │   │
│   │       ┌────────────────────────────────────────────────────┐   │   │
│   │       │               ShieldNet Engine                     │   │   │
│   │       │  Tier 0: ONNX Subword Transformer (~18ms)          │   │   │
│   │       │  Tier 1: DNS & TLS Certificate Validation          │   │   │
│   │       │  Tier 2: Redirect Resolution with SSRF Guard       │   │   │
│   │       │  Tier 3: Jsoup Form Credential Analysis            │   │   │
│   │       │  Tier 4: Headless WebView 64-bit DCT pHash         │   │   │
│   │       └─────────────────┬──────────────────────────────────┘   │   │
│   │                         │                                      │   │
│   │            ALLOW ───────┴─────── DROP (Malicious)              │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │         Integration Mode B: Hybrid Cloud Sync (Optional)       │   │
│   │                                                                │   │
│   │  Local ONNX Instant Scan ──(If uncertain)──▶ Cloud API Scan    │   │
│   │                                             FastAPI Backend    │   │
│   │                                             URLhaus/OpenPhish  │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

* **Mode A: Embedded On-Device Engine (Zero Backend Dependency)**
  The APK contains the quantized ONNX model, tokenizer vocabulary, perceptual visual brand store, and Kotlin scanning logic. Operates 100% offline with zero external server latency (~15–25ms per evaluation).
* **Mode B: NetGuard Transparent VPN Firewall (`VpnService`)**
  Runs as an unprivileged, zero-root background `android.net.VpnService`. Captures raw IP packets on virtual interface `tun0`, parses TLS ClientHello handshake frames to extract the Server Name Indication (SNI), and drops packets targeting malicious domains before a single byte reaches the destination.
* **Mode C: In-App UI / Link Protection SDK**
  Direct programmatic scanner called from your activities, fragments, view models, or QR code / browser components to evaluate URLs prior to rendering or opening external browser intents.

---

## 2. Master File & Asset Checklist

To integrate ShieldNet into your APK, the following directories and files must be present in your Android Studio project structure:

```
your-android-project/
├── app/
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── assets/
│   │   │   ├── model_quantized.onnx         <-- 28.9 MB: Quantized BERT-Small ONNX Model
│   │   │   ├── tokenizer.json               <-- 695 KB: WordPiece Tokenizer Vocabulary
│   │   │   ├── config.json                  <-- 756 B: Model metadata and labels
│   │   │   └── brand_reference_store.json   <-- 473 B: Tier 4 Visual pHash reference store
│   │   └── java/com/shieldnet/security/
│   │       ├── ShieldNet.kt                 <-- Main 5-Tier Scanner Orchestrator
│   │       ├── ShieldNetEngine.kt           <-- OnnxRuntime Android inference wrapper
│   │       ├── ShieldNetVpnService.kt       <-- Non-root packet inspector & firewall
│   │       ├── FeatureExtractor.kt          <-- 41 handcrafted heuristic risk features
│   │       ├── WordPieceTokenizer.kt        <-- Fast tokenizer matching BERT vocab
│   │       ├── AndroidVisualAnalyzer.kt     <-- Headless WebView screenshot & pHash
│   │       ├── ReputationAnalyzer.kt        <-- Tier 1 DNS & TLS validity verification
│   │       ├── RedirectResolver.kt          <-- Tier 2 HTTP redirect resolver & SSRF guard
│   │       └── HtmlAnalyzer.kt              <-- Tier 3 Jsoup credential form harvester
│   ├── build.gradle.kts (or build.gradle)
│   └── proguard-rules.pro
```

---

## 3. Asset Files Specification

Copy these assets directly from the repository's `android/src/main/assets/` into your APK project's `app/src/main/assets/`:

| File | Size | SHA256 Checksum | Purpose |
|---|---|---|---|
| `model_quantized.onnx` | 28.9 MB | `b82f10fd29dee2c9fe9cae51997529234bb889151965e0580c4f008e8124455e` | INT8 dynamically quantized transformer model for on-device inference. |
| `tokenizer.json` | 695 KB | Matches HuggingFace Tokenizer | Subword vocabulary (printable ASCII and token pieces). |
| `config.json` | 756 B | Production config | Defines class mappings (`safe`, `phishing`, `malware`, `data_leak`, `scam`). |
| `brand_reference_store.json` | 473 B | Canonical JSON | Known-good brand domains and 64-bit DCT perceptual hash hex strings. |

> [!IMPORTANT]
> To prevent Android build tools from compressing the ONNX model (which allows the ONNX C++ engine to direct-memory-map `mmap` the file with zero RAM duplication), configure `noCompress` in your Gradle build file.

---

## 4. Gradle Build Configuration

### `app/build.gradle.kts` (Kotlin DSL)

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.yourcompany.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.yourcompany.app"
        minSdk = 26      // Android 8.0 Oreo (covers 95%+ of active devices)
        targetSdk = 34

        // Optimize native library ABIs (ARM64 covers all modern smartphones)
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // CRITICAL: Prevent compression on model assets for fast zero-copy memory mapping
    androidResources {
        noCompress += listOf("onnx", "tflite", "json")
    }
}

dependencies {
    // 1. ONNX Runtime Android Engine (C++ inference engine)
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.18.0")

    // 2. Network analysis & redirect unrolling (Tiers 1 & 2)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // 3. HTML parsing & credential form analysis (Tier 3)
    implementation("org.jsoup:jsoup:1.17.2")

    // 4. Asynchronous non-blocking concurrency
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // 5. AndroidX Support
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.annotation:annotation:1.8.0")
}
```

---

## 5. Android Manifest Configuration

Add the required permissions and declare the firewall service in `app/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <!-- Network state and active network checks for Tiers 1-3 -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <!-- Foreground service permissions (Required for Android 14+ / API 34) -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:theme="@style/Theme.Material3.DayNight.NoActionBar">

        <!-- ShieldNet NetGuard Zero-Root Transparent VPN Firewall Service -->
        <service
            android:name="com.shieldnet.security.ShieldNetVpnService"
            android:permission="android.permission.BIND_VPN_SERVICE"
            android:foregroundServiceType="systemExempted"
            android:exported="false">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>

    </application>
</manifest>
```

---

## 6. ProGuard / R8 Obfuscation Rules

Add the following to `app/proguard-rules.pro` to prevent R8 from stripping native JNI methods or serializable models:

```proguard
# Preserve ONNX Runtime JNI methods and C++ native bridge
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**

# Preserve ShieldNet security models, tokenizer, and result data classes
-keep class com.shieldnet.security.** { *; }
-keepattributes *Annotation*

# Jsoup HTML parsing reflection preservation
-keep class org.jsoup.** { *; }
-dontwarn org.jsoup.**

# OkHttp & Okio networking
-dontwarn okhttp3.**
-dontwarn okio.**
```

---

## 7. Practical Integration Code Examples

### Example 1: Direct In-App URL Scanning (Activity / ViewModel)

```kotlin
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.shieldnet.security.ShieldNet
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var shieldNet: ShieldNet

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize engine (loads ONNX model once into memory)
        shieldNet = ShieldNet(applicationContext)

        lifecycleScope.launch {
            val urlToCheck = "https://secure-login.apple-verification.xyz"

            // 1. Instant check (~18ms) using local neural network + heuristics
            val instantResult = shieldNet.scan(urlToCheck, depth = "tier0")
            Log.d("ShieldNet", "Instant Decision: ${instantResult.decision}, Risk: ${instantResult.riskScore}")

            // 2. Full 5-tier multi-evidence inspection
            val deepResult = shieldNet.scan(urlToCheck, depth = "tier4")
            if (deepResult.decision == "block") {
                Log.e("ShieldNet", "Threat Detected: ${deepResult.category} (${deepResult.confidence * 100}%)")
                for (reason in deepResult.reasons) {
                    Log.e("ShieldNet", " - Evidence: $reason")
                }
            } else {
                Log.i("ShieldNet", "URL is safe to navigate")
            }
        }
    }
}
```

---

### Example 2: Starting the NetGuard Device-Wide VPN Firewall

```kotlin
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class FirewallActivity : AppCompatActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startFirewallService()
        } else {
            // User denied VPN permission
        }
    }

    fun toggleFirewall() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // Request user consent for local VPN tunnel
            vpnPermissionLauncher.launch(intent)
        } else {
            // Permission already granted
            startFirewallService()
        }
    }

    private fun startFirewallService() {
        val serviceIntent = Intent(this, com.shieldnet.security.ShieldNetVpnService::class.java)
        startService(serviceIntent)
    }
}
```

---

### Example 3: Optional Hybrid Cloud Fallback Client

If your APK wants to query your deployed ShieldNet Docker FastAPI backend when connected to Wi-Fi while using local ONNX as an offline fallback:

```kotlin
package com.shieldnet.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ShieldNetCloudClient(
    private val baseUrl: String = "https://your-shieldnet-api.com",
    private val apiKey: String = "shieldnet-dev-key"
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    suspend fun scanCloud(url: String, depth: String = "tier0"): JSONObject? = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("url", url)
                put("depth", depth)
            }
            val request = Request.Builder()
                .url("$baseUrl/api/v1/scan")
                .header("X-API-Key", apiKey)
                .header("Content-Type", "application/json")
                .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    JSONObject(response.body?.string() ?: "{}")
                } else null
            }
        } catch (e: Exception) {
            null // Network error -> Gracefully fallback to local on-device scan
        }
    }
}
```

---

## 8. Performance & Size Impact on Final APK

| Metric | Measured Impact | Notes |
|---|---|---|
| **Download Size Impact** | **~14 MB** (with App Bundle / ABI split) | Google Play Store splits native `.so` per ABI. `model_quantized.onnx` compresses down during distribution. |
| **Installed Disk Size** | **~38 MB** | 28.9 MB model + 4 MB native ONNX `.so` + tokenizer and bytecode. |
| **RAM Consumption** | **~35–45 MB** | ONNX Runtime allocates one thread pool and memory-maps weights. |
| **Tier 0 Scan Latency** | **~15–25 ms** | Evaluated on standard Snapdragon / Google Tensor ARM64 CPUs. |
| **Battery Consumption** | **< 1% per day** | SNI inspection only triggers during TCP connection setup (SYN/ClientHello); payload streams are forwarded in userspace with zero compute overhead. |
