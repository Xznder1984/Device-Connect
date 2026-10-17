# Third-party notices

Device Connect is MIT licensed (see `LICENSE`). It depends on third-party work,
and one library is vendored as source (see below). Every dependency here is
under a permissive license (MIT, Apache-2.0, BSD-3-Clause, Unlicense, or
EPL-2.0 for test-only tooling). There is no GPL/AGPL/SSPL code in this
repository, so the project's own MIT terms are not restricted.

When you add a dependency, verify its license first and record it here. Prefer
MIT, Apache-2.0, BSD, or OFL. Do not copy code in unless its license is
compatible and its copyright notice is preserved.

## Vendored source (copied into this repository)

| Component | Version | License | Location | Notes |
| --- | --- | --- | --- | --- |
| `rweather/noise-java` (`com.southernstorm.noise`) | commit `49377b6` | MIT | `android-app/protocol/src/main/java/com/southernstorm/noise/` | Plain-Java Noise Protocol implementation used for the `Noise_XX_25519_ChaChaPoly_SHA256` handshake. Vendored because it is not published to Maven Central and we want deterministic, offline Android builds. Original license text kept at `android-app/protocol/src/main/resources/META-INF/noise-java-LICENSE.txt`. Upstream: https://github.com/rweather/noise-java |

## Rust — `protocol/rust` (crate `dc-protocol`)

Direct dependencies; the transitive set (RustCrypto, dalek, serde tooling, etc.)
is likewise MIT / Apache-2.0 / BSD-3-Clause.

| Crate | Version | License |
| --- | --- | --- |
| `serde`, `serde_json` | 1.x | MIT OR Apache-2.0 |
| `base64` | 0.22 | MIT OR Apache-2.0 |
| `sha2` | 0.10 | MIT OR Apache-2.0 |
| `thiserror` | 2.x | MIT OR Apache-2.0 |
| `snow` | 0.9 | Apache-2.0 OR MIT |
| `hex` (dev only) | 0.4 | MIT OR Apache-2.0 |

Notable transitive crates: `curve25519-dalek`, `subtle` (BSD-3-Clause);
`chacha20poly1305`, `aes-gcm`, `zeroize` (Apache-2.0 OR MIT); `memchr`
(Unlicense OR MIT).

## TypeScript — `protocol/conformance/ts`

| Package | Version | License |
| --- | --- | --- |
| `ajv` (dev only) | 8.x | MIT |

The conformance suite runs on the Node.js built-in test runner and Node's
built-in TypeScript type stripping; Node.js is distributed under the MIT
license.

## Kotlin / Android — `android-app`

| Component | Version | License |
| --- | --- | --- |
| Kotlin standard library and Gradle plugin | 2.4.x | Apache-2.0 |
| Android Gradle plugin | 9.4.1 | Apache-2.0 |
| `com.google.code.gson:gson` | 2.14.0 | Apache-2.0 |
| `androidx.compose:compose-bom` (ui, foundation, material3, animation, runtime) | 2026.09.00 | Apache-2.0 |
| `androidx.activity:activity-compose` | 1.13.0 | Apache-2.0 |
| `androidx.core:core-ktx` | 1.19.1 | Apache-2.0 |
| `androidx.lifecycle:lifecycle-runtime-ktx`, `lifecycle-service`, `lifecycle-runtime-compose`, `lifecycle-viewmodel-compose` | 2.11.0 | Apache-2.0 |
| `androidx.camera:camera-core`, `camera-camera2`, `camera-lifecycle`, `camera-view` | 1.6.2 | Apache-2.0 |
| `com.google.zxing:core` | 3.5.3 | Apache-2.0 |
| `org.junit:junit-bom` / JUnit Jupiter (test only) | 6.x | EPL-2.0 |
| `com.southernstorm.noise` (vendored, see above) | MIT | MIT |

All of the `androidx.*` and `androidx.compose.*` libraries are released under the
Apache License 2.0 by The Android Open Source Project.

CameraX is used only to stream camera frames to an in-process QR decoder for
pairing, and ZXing performs that decode on-device. Google's ML Kit barcode
scanner was evaluated and rejected: it reports usage metrics to Google by
default, which conflicts with this project's no-telemetry rule.

## Windows app — `windows-app` (added in a later phase)

| Component | Version | License |
| --- | --- | --- |
| Tauri | 2.x | Apache-2.0 OR MIT |
| React / React DOM | 19.x | MIT |
| Vite, TypeScript | current | MIT / Apache-2.0 |

## Website — `website` (added in a later phase)

Fonts and icons must be OFL or permissive; each will be listed here with its
license file when it is added. No third-party fonts are bundled before that.

## Adding a dependency

1. Find the license (package metadata, `LICENSE`, or the repository).
2. Reject anything copyleft that would relicense our code (GPL, AGPL, SSPL) and
   anything unlicensed.
3. Add a row to the matching table above.
4. If you vendor source, keep the upstream license text and record the exact
   upstream revision.
