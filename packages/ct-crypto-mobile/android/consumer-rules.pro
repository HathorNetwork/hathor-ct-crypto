# Consumer R8/ProGuard rules for @hathor/ct-crypto-mobile.
#
# JNA maps the UniffiLib interface methods to native symbols by Java method
# NAME, and maps Structure fields (RustBuffer capacity/len/data) reflectively.
# Renaming or stripping any of them breaks the FFI at runtime on the first
# crypto call.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keep class uniffi.hathor_ct_crypto.** { *; }
-keep class network.hathor.ctcrypto.** { *; }
# JNA references AWT classes that do not exist on Android.
-dontwarn java.awt.*
