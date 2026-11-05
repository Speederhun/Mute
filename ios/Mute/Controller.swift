import Foundation
import SwiftUI
import UIKit

enum Paths {
    /// Identity key, known peers, theme name. Private to the app and excluded from backups.
    static var appDir: URL {
        var u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Mute", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? u.setResourceValues(values)
        return u
    }
    /// Received files: visible in the Files app under "On My iPhone > Mute".
    static var downloads: URL {
        let u = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Mute", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    /// Copies of files being sent; deleted on stop.
    static var outgoing: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("mute_outgoing", isDirectory: true)
    }
}

func jsonString(_ obj: Any) -> String {
    guard let d = try? JSONSerialization.data(withJSONObject: obj, options: [.fragmentsAllowed]),
          let s = String(data: d, encoding: .utf8) else { return "{}" }
    return s
}

/// Owns the Python node, turns its events into published state, and implements the app-side features
/// (lock, auto-clear, clipboard expiry, themes). Everything protocol- and crypto-related happens in Python.
@MainActor
final class MuteController: ObservableObject {
    static let directPort = 5555
    private let maxLines = 500

    // boot
    @Published var booted = false
    @Published var bootError: String?
    @Published var idState = ""            // missing | plain | encrypted

    // session
    @Published var started = false
    @Published var busy = false
    @Published var error: String?
    @Published var statusLine = ""
    @Published var fp = ""
    @Published var words = ""
    @Published var ips: [String] = []
    @Published var transport = "direct"
    @Published var onion: String?
    @Published var listening = false
    @Published var burner = false
    @Published var options = OptionsState()
    @Published var peers: [Peer] = []
    @Published var lines: [ChatLine] = []
    @Published var queue: [QueueItem] = []
    @Published var confirm: ConfirmRequest?
    @Published var transfer: Transfer?
    @Published var namePrompt: Peer?

    // look and settings
    @Published var theme = ThemeColors.ice
    @Published var themes: [ThemeColors] = [.ice]
    @Published var coverProfiles: [CoverProfile] = []
    @Published var shapeLabels: [ShapeLabel] = [ShapeLabel(label: "off", rate: 0)]
    @Published var settings = AppSettings()
    @Published var opts = Options()        // edited on the start screen and in Settings
    @Published var locked = false
    @Published var captured = UIScreen.main.isCaptured

    private var applied: Options?
    private var polling = false
    private var nextId = 1
    private var peerColors: [String: Int] = [:]
    private var lastTouch = Date()
    private var timer: Timer?
    private var bgTask: UIBackgroundTaskIdentifier = .invalid

    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.maintenance() }
        }
        NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.captured = UIScreen.main.isCaptured }
        }
    }

    // MARK: boot

    func boot() {
        guard !booted else { return }
        Task.detached { [weak self] in
            if let err = Py.start() {
                await MainActor.run { self?.bootError = err }
                return
            }
            let app = Paths.appDir.path
            do {
                let id = (try Py.call("identity_state", [app]) as? String) ?? ""
                let themesObj = (try Py.json("themes") as? [String: Any]) ?? [:]
                let cover = (try Py.json("cover_profiles") as? [String: Any]) ?? [:]
                let shapes = (try Py.json("shape_labels") as? [[Any]]) ?? []
                let saved = (try? String(contentsOf: Paths.appDir.appendingPathComponent("theme.txt"), encoding: .utf8))?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                await MainActor.run {
                    guard let self else { return }
                    self.idState = id
                    let all = ThemeColors.parseAll(themesObj)
                    if !all.isEmpty { self.themes = all }
                    self.theme = all.first { $0.name == saved } ?? all.first { $0.name == "ice" } ?? .ice
                    self.coverProfiles = cover.keys.sorted().map { k in
                        let o = (cover[k] as? [String: Any]) ?? [:]
                        return CoverProfile(name: k, text: o.str("text"), estimate: o.str("estimate"))
                    }
                    let labels = shapes.compactMap { a -> ShapeLabel? in
                        guard a.count == 2, let l = a[0] as? String, let r = (a[1] as? NSNumber)?.doubleValue else { return nil }
                        return ShapeLabel(label: l, rate: r)
                    }
                    if !labels.isEmpty { self.shapeLabels = labels }
                    self.booted = true
                }
            } catch {
                await MainActor.run { self?.bootError = error.localizedDescription }
            }
        }
    }

    func setTheme(_ name: String, save: Bool) {
        guard let t = themes.first(where: { $0.name == name }) else { return }
        theme = t
        if save { try? name.write(to: Paths.appDir.appendingPathComponent("theme.txt"), atomically: true, encoding: .utf8) }
    }

    func shapeEstimate(_ rate: Double, tor: Bool) -> String {
        (try? Py.call("shape_estimate", [rate, tor]) as? String) ?? ""
    }

    // MARK: start / stop

    func start(passphrase: String, burner: Bool, tor: Bool) {
        guard !busy else { return }
        busy = true
        error = nil
        statusLine = "Starting..."
        let o = opts
        let kw: [String: Any] = [
            "app_dir": Paths.appDir.path, "download_dir": Paths.downloads.path,
            "passphrase": burner ? "" : passphrase, "burner": burner,
            "scrub": o.scrub, "amnesia": o.amnesia || burner,
        ]
        Task.detached { [weak self] in
            do {
                try Py.call("init", [kw])
                try Py.call("configure", [jsonString(o.json(prev: nil))])
                await MainActor.run {
                    guard let self else { return }
                    self.applied = o
                    self.lastTouch = Date()
                    self.startPolling()
                }
                if tor {
                    let (socks, ctrl) = try TorService.shared.start()
                    try Py.call("start_tor_external", [socks, ctrl])
                } else {
                    try Py.call("start_direct", [MuteController.directPort])
                }
                let st = try Py.dict("state")
                await MainActor.run {
                    guard let self else { return }
                    self.applyState(st)
                    self.burner = burner
                    self.started = true
                    self.busy = false
                    self.statusLine = ""
                    UIApplication.shared.isIdleTimerDisabled = true   // iOS suspends the connection when the screen locks
                }
            } catch {
                _ = try? Py.call("drop")
                await MainActor.run {
                    guard let self else { return }
                    self.stopPolling()
                    self.busy = false
                    self.statusLine = ""
                    self.error = error.localizedDescription
                }
            }
        }
    }

    /// STOP: ends the session (connections, onion service, chat) and returns to the start screen.
    func stop() {
        stopPolling()
        started = false
        busy = false
        locked = false
        lines = []
        peers = []
        queue = []
        confirm = nil
        transfer = nil
        namePrompt = nil
        onion = nil
        listening = false
        options = OptionsState()
        applied = nil
        peerColors = [:]
        statusLine = ""
        UIApplication.shared.isIdleTimerDisabled = false
        Task.detached {
            _ = try? Py.call("drop")
            try? FileManager.default.removeItem(at: Paths.outgoing)
        }
        // a stored identity may have been created meanwhile
        Task.detached { [weak self] in
            let id = (try? Py.call("identity_state", [Paths.appDir.path]) as? String) ?? ""
            await MainActor.run { self?.idState = id }
        }
    }

    /// PANIC: stop everything and quit the app.
    func panic() {
        stop()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { exit(0) }
    }

    // MARK: events

    private func startPolling() {
        polling = true
        Task.detached { [weak self] in
            while true {
                guard let me = self else { return }
                let go = await me.polling
                if !go { return }
                if let evs = try? Py.json("poll", [500]) as? [[String: Any]] {
                    for ev in evs { await me.handle(ev) }
                } else {
                    try? await Task.sleep(nanoseconds: 300_000_000)
                }
            }
        }
    }

    private func stopPolling() { polling = false }

    private func colorOf(_ fp: String) -> Int {
        if fp.isEmpty { return -1 }
        if let c = peerColors[fp] { return c }
        let c = peerColors.count
        peerColors[fp] = c
        return c
    }

    func addLine(who: String, text: String, kind: LineKind, color: Int = -1, via: String = "") {
        lines.append(ChatLine(id: nextId, who: who, text: text, kind: kind, color: color, via: via))
        nextId += 1
        if lines.count > maxLines { lines.removeFirst(lines.count - maxLines) }
    }

    private func handle(_ ev: [String: Any]) {
        switch ev.str("k") {
        case "sys":
            if busy { statusLine = ev.str("text") }
            addLine(who: "", text: ev.str("text"), kind: .sys)
        case "msg":
            addLine(who: ev.str("name"), text: ev.str("text"), kind: .peer, color: colorOf(ev.str("fp")))
        case "relayed":
            addLine(who: ev.str("name"), text: ev.str("text"), kind: .peer, color: colorOf(ev.str("fp")), via: ev.str("via"))
        case "connected":
            addLine(who: "", text: "\(ev.str("name")) connected securely", kind: .sys)
            let fp = ev.str("fp")
            refreshState { [weak self] in
                guard let self else { return }
                // offer to name the new peer right away (only you see it; a relay hub passes it on)
                self.namePrompt = self.peers.first { $0.fp == fp }
            }
        case "disconnected":
            addLine(who: "", text: "\(ev.str("name")) disconnected", kind: .sys)
            refreshState()
        case "file":
            let name = (ev.str("path") as NSString).lastPathComponent
            addLine(who: "", text: ev.bool("ok") ? "received \(name)" : "transfer failed: \(name)", kind: .file)
        case "progress":
            let total = ev.dbl("total"), done = ev.dbl("done")
            transfer = (total > 0 && done < total) ? Transfer(label: ev.str("label"), done: done, total: total) : nil
        case "queue":
            let items = (ev["items"] as? [[Any]]) ?? []
            queue = items.compactMap { a in
                guard a.count >= 3, let id = (a[0] as? NSNumber)?.intValue else { return nil }
                return QueueItem(id: id, name: "\(a[1])", state: "\(a[2])")
            }
        case "confirm":
            confirm = ConfirmRequest(fp: ev.str("fp"), words: ev.str("words"))
        default:
            break
        }
    }

    private func refreshState(_ then: (@MainActor () -> Void)? = nil) {
        Task.detached { [weak self] in
            guard let st = try? Py.dict("state") else { return }
            await MainActor.run {
                self?.applyState(st)
                then?()
            }
        }
    }

    private func applyState(_ o: [String: Any]) {
        fp = o.str("fp")
        words = o.str("words")
        ips = (o["ips"] as? [String]) ?? []
        transport = o.str("transport")
        onion = (o["onion"] as? String)
        listening = o.bool("listening")
        burner = o.bool("burner")
        peers = ((o["peers"] as? [[String: Any]]) ?? []).map {
            Peer(fp: $0.str("fp"), name: $0.str("name"), color: colorOf($0.str("fp")))
        }
        let op = (o["options"] as? [String: Any]) ?? [:]
        options = OptionsState(
            closed: op.bool("closed"), relay: op.bool("relay"), cover: op.bool("cover"),
            shape: op.dbl("shape"), paused: op.bool("paused"), psk: op.bool("psk"),
            amnesia: op.bool("amnesia"), known: op.int("known")
        )
    }

    // MARK: actions

    private func run(_ label: String = "Error", _ body: @escaping @Sendable () throws -> Void) {
        Task.detached { [weak self] in
            do { try body() } catch {
                await MainActor.run { self?.addLine(who: "", text: "\(label): \(error.localizedDescription)", kind: .sys) }
            }
        }
    }

    func connect(_ address: String, fingerprint: String) {
        addLine(who: "", text: "Connecting to \(address)...", kind: .sys)
        run("Could not connect") { try Py.call("connect", [address, fingerprint]) }
    }

    func sendText(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return }
        addLine(who: "me", text: t, kind: .me)
        run("Send failed") { try Py.call("send_text", [t]) }
    }

    /// Sends a file or a whole folder (folders become one clean zip). Works on a copy in the app's temp folder.
    func sendItem(_ url: URL) {
        guard started else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        Task.detached { [weak self] in
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let dir = Paths.outgoing.appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let dest = dir.appendingPathComponent(url.lastPathComponent)
                try FileManager.default.copyItem(at: url, to: dest)
                try Py.call("send_file", [dest.path])
            } catch {
                await MainActor.run { self?.addLine(who: "", text: "Send failed: \(error.localizedDescription)", kind: .sys) }
            }
        }
    }

    func answerConfirm(_ accept: Bool) {
        guard let c = confirm else { return }
        confirm = nil
        run { try Py.call("answer_confirm", [c.fp, accept]) }
    }

    func namePeer(_ fp: String, _ name: String) {
        Task.detached { [weak self] in
            _ = try? Py.call("name_peer", [fp, name])
            await MainActor.run { self?.refreshState() }
        }
    }

    func togglePause() {
        let method = options.paused ? "resume_transfers" : "pause_transfers"
        Task.detached { [weak self] in
            _ = try? Py.call(method)
            await MainActor.run { self?.refreshState() }
        }
    }

    func cancelTransfers() { run { try Py.call("cancel_transfers") } }

    func applyOptions() {
        let o = opts
        let prev = applied
        applied = o
        Task.detached { [weak self] in
            do {
                try Py.call("configure", [jsonString(o.json(prev: prev))])
                await MainActor.run { self?.refreshState() }
            } catch {
                await MainActor.run { self?.addLine(who: "", text: "Options: \(error.localizedDescription)", kind: .sys) }
            }
        }
    }

    func wipeChat() { lines = [] }

    // MARK: lock, clipboard, background

    func touch() { lastTouch = Date() }

    func lock() { if started { locked = true } }

    func unlock(_ password: String) -> Bool {
        if settings.lockPassword.isEmpty || password == settings.lockPassword {
            locked = false
            lastTouch = Date()
            return true
        }
        return false
    }

    func copy(_ text: String) {
        let pb = UIPasteboard.general
        if settings.clipboardClear {
            pb.setItems([["public.utf8-plain-text": text]],
                        options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(30)])
        } else {
            pb.string = text
        }
    }

    private func maintenance() {
        guard started else { return }
        if settings.autoClearMin > 0 {
            let limit = Date().addingTimeInterval(-Double(settings.autoClearMin) * 60)
            lines.removeAll { $0.ts < limit }
        }
        if settings.autoLockMin > 0, !locked, Date().timeIntervalSince(lastTouch) > Double(settings.autoLockMin) * 60 {
            locked = true
        }
    }

    /// iOS gives a few extra seconds in the background; the connection does not survive a long suspension.
    func appBackgrounded() {
        guard started, bgTask == .invalid else { return }
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "mute-session") { [weak self] in
            Task { @MainActor in self?.endBackgroundTask() }
        }
    }

    func appForegrounded() { endBackgroundTask() }

    private func endBackgroundTask() {
        if bgTask != .invalid {
            UIApplication.shared.endBackgroundTask(bgTask)
            bgTask = .invalid
        }
    }
}
