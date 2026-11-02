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
    MainActivity.kt            Jetpack Compose UI: setup, chat, fingerprint check
```

`mute.py` and `android/python/` are copied into `app/build/mute-python` at build time (`syncMutePython` task).

## Build

Needs Android Studio (or JDK 17 + Android SDK) and internet access for Gradle, Chaquopy's pip packages and the Tor binaries.

```bash
cd android
gradle wrapper          # once, if gradle/wrapper is missing (or just open the folder in Android Studio)
./gradlew assembleDebug # app/build/outputs/apk/debug/app-debug.apk
```

Tor comes from Briar's Android builds (`org.briarproject:tor-android`, `obfs4proxy-android`, `snowflake-android`).
They are executables packaged as `lib*.so`; the app starts them as child processes exactly like the desktop version
does. Versions are set in `gradle.properties` (`+` = newest; pin them after the first good build).

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

`android/wheels/stem-1.8.2-py3-none-any.whl` is the unmodified `stem` release (LGPLv3, licence text inside the wheel).
It is kept here because PyPI only publishes `stem` as a source archive and Chaquopy installs wheels only.
