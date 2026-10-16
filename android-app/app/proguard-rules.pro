# Device Connect release shrinking rules.
#
# The protocol module holds wire-format classes that are (de)serialized with
# Gson by field name. Gson uses reflection, so keep the fields it reflects on.
# Any class annotated with @SerializedName keeps its annotated name, but Gson
# also needs the no-arg constructor and field names to survive shrinking.

-keepattributes Signature
-keepattributes *Annotation*
-keepattributes InnerClasses,EnclosingMethod

# Keep Gson model classes in the protocol module and the app.
-keep class dev.deviceconnect.protocol.json.** { *; }

# Gson internals.
-dontwarn sun.misc.**
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# The vendored Noise implementation is pure Java crypto and must not be
# rewritten or stripped; it is reached reflectively in places and its
# security properties depend on the exact bytecode semantics.
-keep class com.southernstorm.noise.** { *; }
-dontwarn com.southernstorm.noise.**
