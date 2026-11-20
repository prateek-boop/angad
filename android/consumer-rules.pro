# Preserve ONNX Runtime JNI methods and classes
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**

# Preserve ShieldNet security models and classes
-keep class com.shieldnet.security.** { *; }

# Jsoup reflection preservation
-keep class org.jsoup.** { *; }
-dontwarn org.jsoup.**

# OkHttp & Coroutines
-dontwarn okhttp3.**
-dontwarn okio.**
