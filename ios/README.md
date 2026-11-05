# Mute for iOS

The same Mute as on the desktop and Android (same protocol, they talk to each other): chat, files and folders, DIRECT and TOR
(Tor is built into the app), group chat with relay hub, closed mode, shared secret, cover and constant-rate traffic, themes,
lock screen, STOP and PANIC. The app is SwiftUI; `mute.py` runs unchanged inside an embedded CPython.

## Build (needs a Mac with Xcode)

```bash
brew install xcodegen cocoapods
cd ios
./setup.sh          # downloads the iOS Python runtime and wheels, generates Mute.xcodeproj, runs pod install
open Mute.xcworkspace
```

In Xcode choose the Mute target > Signing & Capabilities > your Team (a free Apple ID works for your own phone), pick your iPhone
(or a simulator) and press Run. With a free Apple ID the app expires after 7 days and must be installed again.

## What is the same, what differs

- Tor runs inside the app (Tor.framework). Onion client keys (restricted onion services) and plain Tor bridges work.
  obfs4, snowflake and the Tor Project captcha bridges are not available (they need a transport library that is not bundled).
- iOS suspends apps in the background: keep Mute open while you talk (the screen stays awake during a session). Message notifications
  are deliberately not included.
- Received files go to the Files app: On My iPhone > Mute. Sending uses the system file picker (files and folders).
- The app-switcher preview and screen recording show only a cover. iOS does not let apps block screenshots.

## Status

Nothing in `ios/` has been compiled yet: expect a few compile or setup errors on the first build and send them back to be fixed.
The Python side is covered by `tests/test_android_bridge.py`.
