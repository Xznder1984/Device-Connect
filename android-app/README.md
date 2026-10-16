# android-app

The Android side of Device Connect: the phone app that a person installs on
their own device to pair with their own Windows PC.

This directory currently contains the **shared protocol module** (`:protocol`),
which is pure Kotlin/JVM so it builds and tests without the Android SDK. The
Compose app module is added in Phase 2 and depends on this module.

## Layout

```
android-app/
  settings.gradle.kts      Gradle build, includes :protocol
  build.gradle.kts         Root build; declares the Kotlin JVM plugin
  gradle.properties        Build cache + no JVM auto-download
  protocol/
    build.gradle.kts       Kotlin/JVM library, tests wired to the golden vectors
    src/main/java/         Vendored MIT Noise library (com.southernstorm.noise)
    src/main/kotlin/       Protocol code (framing, QR, confirmation, Noise)
    src/test/kotlin/       Conformance tests against protocol/test-vectors
```

The `:protocol` module is deliberately **not** an Android module. Keeping the
wire format in plain Kotlin/JVM means its conformance tests run on any machine
with a JDK, and the same sources are reused by the Android app module.

## What it contains

- `Framing.kt` — the 4-byte length-prefixed frame codec and an incremental
  `FrameDecoder` for byte streams, plus the binary `FileData` and
  `VideoAccessUnit` payloads.
- `Qr.kt` — the `dc1:` pairing payload (base64url JSON) encode/decode.
- `Confirm.kt` — the six-digit pairing confirmation code.
- `Noise.kt` — `Noise_XX_25519_ChaChaPoly_SHA256` handshake and transport
  helpers, built on the vendored MIT `rweather/noise-java` library. No custom
  cryptography.
- `ErrorCode.kt` — the closed set of protocol error codes.

## Build and test

The golden vectors and JSON Schemas live at the repository root
(`protocol/test-vectors`, `protocol/schema`) and are shared with the Rust and
TypeScript implementations. The build passes their location to the tests via
system properties, so run the tests through Gradle — not from an IDE that does
not apply `build.gradle.kts`.

```powershell
# from android-app/
gradle :protocol:test
```

Requirements: a JDK (17 or 21) and Gradle 9.x. Point `GRADLE_USER_HOME` at a
drive with space if the C: drive is tight, for example:

```powershell
$env:GRADLE_USER_HOME = "D:\Albarr\cache\gradle"
```

The Android application module (Phase 2) additionally needs the Android SDK
(`ANDROID_HOME`) and the Android Gradle Plugin.

## Crypto note

`com.southernstorm.noise` is vendored, MIT-licensed source (see
`THIRD-PARTY-NOTICES.md` and
`protocol/src/main/resources/META-INF/noise-java-LICENSE.txt`). It is included
rather than pulled from a repository because it is not published to Maven
Central. Fixed ephemeral keys are exposed only through a test-only entry point
(`Noise.handshake(..., fixedEphemeralPrivate = ...)`) so the handshake can be
checked against known-answer vectors; production code always uses random
ephemerals.
