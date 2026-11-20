plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.shieldnet.security"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        targetSdk = 34

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
}

dependencies {
    // ONNX Runtime Android (C++ native inference engine for on-device ML)
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.18.0")

    // Networking & Redirect Resolution (Tiers 1 & 2)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // HTML Parsing & Credential Harvesting Analysis (Tier 3)
    implementation("org.jsoup:jsoup:1.17.2")

    // Coroutines for non-blocking asynchronous scans
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // AndroidX
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.annotation:annotation:1.8.0")
}
