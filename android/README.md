# Mute for Android

Android port of Mute. `mute.py` runs **unchanged** inside the app via [Chaquopy](https://chaquo.com/chaquopy/),
so the protocol, crypto and Tor handling are the same code as on the desktop and both sides stay compatible.
Only the UI and a thin bridge are new.

```
android/
  python/android_bridge.py     headless wrapper around mute.Node (JSON events, blocking fingerprint prompt)
  app/src/main/java/.../
    MuteController.kt          owns the Python bridge, turns events into UiState
    MuteService.kt             foreground service that keeps the process (and tor) alive
    MainActivity.kt            Jetpack Compose UI: setup, tabbed chat (Chat, Connect, Files, Settings), fingerprint check
```

`mute.py` and `android/python/` are copied into `app/build/mute-python` at build time (`syncMutePython` task).

## Build

Needs Android Studio (or JDK 17 + Android SDK) and internet access for Gradle, Chaquopy's pip packages and the Tor binaries.

```bash
cd android
gradle wrapper          # once, if gradle/wrapper is missing (or just open the folder in Android Studio)
./gradlew assembleDebug # app/build/outputs/apk/debug/app-debug.apk
```

Tor comes from Briar's JARs (`org.briarproject:tor-android`, `obfs4proxy-android`, `snowflake-android`); the build unpacks the executables from them into `app/build/tor-jni` (jniLibs).
They are executables packaged as `lib*.so`; the app starts them as child processes exactly like the desktop version
does. Versions are set in `gradle.properties` (`+` = newest; pin them after the first good build).

## Download and install (no build needed)

Every `android-vX.Y.Z` release on the repository's Releases page carries `Mute-android.apk` (built by GitHub Actions,
with build provenance and `SHA256SUMS-android.txt`). On the phone: download the APK, open it, allow "install from this source"
once, tap Install. Needs Android 7.0+ on a 64-bit phone.

## Make a release (maintainers)

```bash
git tag android-v1.2.1 && git push origin android-v1.2.1     # or a normal vX.Y.Z tag, which builds every platform
```

Signing: Android only updates an app in place when the new APK has the same signing key. Create a key once and store it as
repository secrets, then every release is signed with it:

```bash
keytool -genkeypair -v -keystore mute.jks -alias mute -keyalg RSA -keysize 4096 -validity 36500
base64 -w0 mute.jks        # paste into the secret MUTE_KEYSTORE_B64
```

Secrets: `MUTE_KEYSTORE_B64`, `MUTE_KEYSTORE_PASSWORD`, `MUTE_KEY_ALIAS` (default `mute`), `MUTE_KEY_PASSWORD`.
Keep `mute.jks` somewhere safe and never commit it. Without the secrets the workflow signs with a debug key, which
installs fine but changes between builds, so updates then need an uninstall first.

## Test the Python side without a phone

```bash
python tests/test_android_bridge.py
```

## Behaviour on Android

- Identity key and known-peers list live in the app's private storage; backups and device transfer are disabled.
- Received files go to the app's external files directory (`Android/data/hu.speeder.mute/files/Mute`).
- Files you send are copied to the app cache first and deleted on stop/PANIC.
- Screenshots, screen recording and the recent-apps thumbnail are blocked (`FLAG_SECURE`).
- Swiping the app away or pressing Stop ends the session: connection, Tor and the chat window are wiped.
- The foreground notification never shows message content.

## Status

Everything from the desktop version is in, except message notifications (deliberately left out; the foreground
notification only says the app is running):

- DIRECT and TOR modes, Tor bridges (pasted, built-in list, or fetched from the Tor Project with a captcha), SOCKS5 proxy
- burner identity, identity passphrase, amnesia mode, key-renewal interval
- fingerprint + 6-word verification, closed mode with allowlist, shared secret (PSK), onion client authorization
- chat with timestamps, per-peer colours and nicknames, group chat (several peers), relay hub, cover traffic profiles,
  constant-rate traffic
- file and folder sending (folders become a clean zip), progress, queue, pause/resume, cancel, speed limit, metadata scrubbing
- PANIC, WIPE (chat window only), lock screen with optional password, auto-lock on idle, auto-clear of old chat lines,
  clipboard cleared 30 s after copying, screenshot/recording block
- the 8 desktop themes (taken from `mute.THEMES`)

Options live in memory only (like on the desktop); only the identity key, the optional known-peers list and the theme
name are written to the app's private storage.

Not yet verified on a device: the Gradle build, the Kotlin sources (they have not been compiled), the Chaquopy wheel for
`cryptography>=42`, and the exact file names of the Briar binaries in `nativeLibraryDir` (the bridge looks for `libtor.so`
and `lib<name>.so` for the transports). The Python side is covered by `tests/test_android_bridge.py`.

## Third-party notes

`android/python/stem/` is the unmodified `stem` 1.8.2 source (LGPLv3, licence in `stem/LICENSE`). It is bundled because
PyPI only publishes `stem` as a source archive and Chaquopy installs wheels only.
