# ShieldNet Proguard rules
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**
-keep class com.shieldnet.security.** { *; }
-keepattributes *Annotation*
