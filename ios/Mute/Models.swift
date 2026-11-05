import Foundation
import SwiftUI

struct Peer: Identifiable, Equatable {
    let fp: String
    var name: String
    var color: Int
    var id: String { fp }
}

enum LineKind { case me, peer, sys, file }

struct ChatLine: Identifiable {
    let id: Int
    var who: String
    var text: String
    var kind: LineKind
    var ts = Date()
    var color = -1
    var via = ""
}

struct Transfer: Equatable {
    var label: String
    var done: Double
    var total: Double
}

struct QueueItem: Identifiable {
    let id: Int
    var name: String
    var state: String
}

struct ConfirmRequest: Identifiable {
    let fp: String
    let words: String
    var id: String { fp }
}

/// Options as the node reports them (state()["options"]).
struct OptionsState {
    var closed = false
    var relay = false
    var cover = false
    var shape = 0.0
    var paused = false
    var psk = false
    var amnesia = false
    var known = 0
    var clientAuthPub: String? = nil
    var bridges = 0
}

/// Everything the Python node can be configured with (Bridge.configure in android_bridge.py).
struct Options: Equatable {
    var closed = false
    var allow = ""            // fingerprints, one per line
    var psk = ""              // shared secret
    var relay = false
    var cover = false
    var coverProfile = "random"
    var shape = 0.0           // constant-rate frames per second, 0 = off
    var speedLimitKbs = 0
    var ratchet = 600         // seconds between key renewals, 0 = off
    var proxy = ""            // SOCKS5 host:port for DIRECT connections
    var scrub = true          // strip metadata from outgoing files
    var amnesia = false
    var bridges = ""          // plain Tor bridge lines, start only
    var allowedClients = ""   // onion client keys, start only

    /// JSON for Bridge.configure: everything on the first call (prev == nil), afterwards only what changed.
    func json(prev: Options?) -> [String: Any] {
        var o: [String: Any] = [:]
        let first = prev == nil
        if first || scrub != prev!.scrub { o["scrub"] = scrub }
        if first || amnesia != prev!.amnesia { o["amnesia"] = amnesia }
        if first || closed != prev!.closed { o["closed"] = closed }
        if !allow.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (first || allow != prev!.allow) { o["allow"] = allow }
        if psk != (prev?.psk ?? "") { o["psk"] = psk }
        if first || relay != prev!.relay { o["relay"] = relay }
        if first || cover != prev!.cover || coverProfile != prev!.coverProfile {
            o["cover"] = cover
            o["cover_profile"] = coverProfile
        }
        if first || shape != prev!.shape { o["shape"] = shape }
        if first || speedLimitKbs != prev!.speedLimitKbs { o["speed_limit_kbs"] = speedLimitKbs }
        if first || ratchet != prev!.ratchet { o["ratchet"] = ratchet }
        if first || proxy != prev!.proxy { o["proxy"] = proxy.trimmingCharacters(in: .whitespaces) }
        if first {
            if !bridges.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { o["bridges"] = bridges }
            if !allowedClients.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { o["allowed_clients"] = allowedClients }
        }
        return o
    }
}

/// App-side settings that never reach Python (memory only, like on the desktop).
struct AppSettings: Equatable {
    var clipboardClear = true     // clear the clipboard 30 s after copying
    var autoClearMin = 0          // delete chat lines older than N minutes, 0 = off
    var autoLockMin = 0           // lock after N idle minutes, 0 = off
    var lockPassword = ""         // empty = Unlock button only
}

struct CoverProfile: Identifiable {
    let name: String
    let text: String
    let estimate: String
    var id: String { name }
}

struct ShapeLabel: Identifiable {
    let label: String
    let rate: Double
    var id: String { label }
}
