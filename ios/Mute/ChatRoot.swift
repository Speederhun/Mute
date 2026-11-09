import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum MainTab: String, CaseIterable, Identifiable {
    case chat = "CHAT", connect = "CONNECT", files = "FILES", settings = "SETTINGS"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .chat: return "bubble.left.and.bubble.right"
        case .connect: return "link"
        case .files: return "doc.on.doc"
        case .settings: return "slider.horizontal.3"
        }
    }
}

/// The running session: header with LOCK / STOP / PANIC, four tabs, and the new-peer naming dialog.
struct ChatRoot: View {
    @EnvironmentObject var ctl: MuteController
    @State private var tab = MainTab.chat
    @State private var nameText = ""
    @State private var confirmPanic = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Group {
                switch tab {
                case .chat: ChatTab()
                case .connect: ConnectTab(onConnect: { tab = .chat })
                case .files: FilesTab()
                case .settings: SettingsTab()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            tabBar
        }
        .alert("Name this peer", isPresented: Binding(get: { ctl.namePrompt != nil }, set: { if !$0 { ctl.namePrompt = nil } })) {
            TextField("Nickname (only you see it)", text: $nameText)
            Button("Save") {
                if let p = ctl.namePrompt, !nameText.trimmingCharacters(in: .whitespaces).isEmpty { ctl.namePeer(p.fp, nameText) }
                nameText = ""
                ctl.namePrompt = nil
            }
            Button("Skip", role: .cancel) { nameText = ""; ctl.namePrompt = nil }
        } message: {
            Text("\(ctl.namePrompt?.name ?? "") connected. A relay hub also passes this name on to the group.")
        }
        .alert("PANIC", isPresented: $confirmPanic) {
            Button("Stop and quit", role: .destructive) { ctl.panic() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Ends every connection, wipes the chat and closes the app.")
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text("MUTE").font(.system(size: 18, weight: .bold, design: .monospaced)).foregroundStyle(ctl.theme.acc)
                Text(ctl.transport == "tor" ? "TOR" : "DIRECT")
                    .font(.system(size: 10, weight: .semibold)).tracking(1).foregroundStyle(ctl.theme.dim)
            }
            Spacer()
            HeaderButton(title: "LOCK", color: ctl.theme.btn, text: ctl.theme.fg) { ctl.lock() }
            HeaderButton(title: "STOP", color: ctl.theme.red.opacity(0.25), text: ctl.theme.red) { ctl.stop() }
            HeaderButton(title: "PANIC", color: ctl.theme.red, text: ctl.theme.bg) { confirmPanic = true }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(ctl.theme.bg)
    }

    private var tabBar: some View {
        HStack {
            ForEach(MainTab.allCases) { t in
                Button { tab = t } label: {
                    VStack(spacing: 3) {
                        Image(systemName: t.icon).font(.system(size: 18))
                        Text(t.rawValue).font(.system(size: 9, weight: .semibold)).tracking(0.5)
                    }
                    .frame(maxWidth: .infinity)
                    .foregroundStyle(tab == t ? ctl.theme.acc : ctl.theme.dim)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.top, 8).padding(.bottom, 4)
        .background(ctl.theme.chat)
    }
}

struct HeaderButton: View {
    let title: String
    let color: Color
    let text: Color
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: 12, weight: .bold))
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(color, in: Capsule())
                .foregroundStyle(text)
        }
        .buttonStyle(.plain)
    }
}

// MARK: chat

struct ChatTab: View {
    @EnvironmentObject var ctl: MuteController
    @State private var draft = ""
    @FocusState private var focused: Bool
    private static let fmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm"; return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            if let c = ctl.call { CallPanel(call: c) }
            else if !ctl.peers.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(ctl.peers) { p in
                            Button { ctl.startCall(p.fp) } label: {
                                Label(p.name.isEmpty ? "peer" : p.name, systemImage: "phone.fill").font(.system(size: 13))
                            }.buttonStyle(.bordered).tint(ctl.theme.peerColor(p.color))
                        }
                    }.padding(.horizontal, 12).padding(.vertical, 6)
                }
                .background(ctl.theme.chat)
            }
            if ctl.options.relay || ctl.peers.count > 1 {
                Text(ctl.options.relay
                     ? "You are the relay hub: messages are passed between all connected peers."
                     : "Group chat: names come from the hub; you can rename people on the Connect tab.")
                    .font(.system(size: 11)).foregroundStyle(ctl.theme.dim)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 14).padding(.vertical, 6)
                    .background(ctl.theme.chat)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if ctl.lines.isEmpty {
                            Text("No messages yet. Open the Connect tab to share your address or to connect to someone.")
                                .font(.system(size: 13)).foregroundStyle(ctl.theme.dim).padding(.top, 24)
                        }
                        ForEach(ctl.lines) { l in bubble(l).id(l.id) }
                    }
                    .padding(12)
                }
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: ctl.lines.count) { _ in
                    if let last = ctl.lines.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                }
            }
            if let t = ctl.transfer {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(t.label)  \(Int(t.done / max(t.total, 1) * 100))%").font(.system(size: 11)).foregroundStyle(ctl.theme.dim)
                    ProgressView(value: t.done, total: t.total).tint(ctl.theme.acc)
                }
                .padding(.horizontal, 14).padding(.vertical, 6)
            }
            inputBar
        }
    }

    private func bubble(_ l: ChatLine) -> some View {
        Group {
            switch l.kind {
            case .sys, .file:
                Text(l.text).font(.system(size: 12)).foregroundStyle(l.kind == .file ? ctl.theme.acc : ctl.theme.dim)
                    .frame(maxWidth: .infinity, alignment: .center).multilineTextAlignment(.center)
            case .me, .peer:
                let mine = l.kind == .me
                let c = mine ? ctl.theme.acc : ctl.theme.peerColor(l.color)
                VStack(alignment: mine ? .trailing : .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(mine ? "me" : l.who).font(.system(size: 11, weight: .semibold)).foregroundStyle(c)
                        if !l.via.isEmpty { Text("via \(l.via)").font(.system(size: 10)).foregroundStyle(ctl.theme.dim) }
                        Text(Self.fmt.string(from: l.ts)).font(.system(size: 10)).foregroundStyle(ctl.theme.dim)
                    }
                    Text(l.text).font(.system(size: 16)).textSelection(.enabled)
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .background(c.opacity(mine ? 0.16 : 0.10), in: RoundedRectangle(cornerRadius: 16))
                        .contextMenu { Button("Copy") { ctl.copy(l.text) } }
                }
                .frame(maxWidth: .infinity, alignment: mine ? .trailing : .leading)
            }
        }
    }

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .lineLimit(1...6)
                .focused($focused)
                .font(.system(size: 17))
                .padding(.horizontal, 14).padding(.vertical, 12)
                .background(ctl.theme.ent, in: RoundedRectangle(cornerRadius: 20))
            Button {
                ctl.sendText(draft)
                draft = ""
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 38))
                    .foregroundStyle(draft.trimmingCharacters(in: .whitespaces).isEmpty ? ctl.theme.dim : ctl.theme.acc)
            }
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(ctl.theme.bg)
    }
}

// MARK: connect

struct ConnectTab: View {
    @EnvironmentObject var ctl: MuteController
    /// Called after CONNECT is pressed: the app jumps to the Chat tab so the progress is visible.
    var onConnect: () -> Void = {}
    @State private var address = ""
    @State private var expected = ""
    @State private var renaming: Peer?
    @State private var renameText = ""

    private var myAddresses: [String] {
        if let o = ctl.onion { return [o] }
        return ctl.ips.map { "\($0):\(MuteController.directPort)" }
    }

    private var shareText: String {
        var t = "Mute address: \(myAddresses.first ?? "-")"
        t += "\nFingerprint: \(ctl.fp)"
        return t
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                SectionCard(title: "YOUR ADDRESS") {
                    if myAddresses.isEmpty {
                        Hint(ctl.transport == "tor" ? "Waiting for the onion address..." : "No network address found. Connect to Wi-Fi.")
                    }
                    ForEach(myAddresses, id: \.self) { a in
                        Text(a).font(.system(size: 14, design: .monospaced)).textSelection(.enabled)
                        HStack {
                            Button("Copy") { ctl.copy(a) }.buttonStyle(.bordered)
                            ShareLink(item: shareText) { Text("SHARE") }.buttonStyle(.borderedProminent)
                        }
                    }
                    if ctl.transport != "tor" {
                        Hint("Direct mode: the other device must reach this address (same Wi-Fi, port forward or VPN).")
                    }
                }

                SectionCard(title: "YOUR FINGERPRINT") {
                    Text(ctl.words).font(.system(size: 17, weight: .semibold, design: .monospaced)).foregroundStyle(ctl.theme.acc)
                    Text(ctl.fp).font(.system(size: 11, design: .monospaced)).foregroundStyle(ctl.theme.dim).textSelection(.enabled)
                    Hint("Read the six words to the other person over a call: when they match, nobody is in the middle.")
                    if let pub = ctl.options.clientAuthPub {
                        Divider()
                        Text("Onion client key").font(.system(size: 13, weight: .semibold))
                        Text(pub).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        Button("Copy key") { ctl.copy(pub) }.buttonStyle(.bordered)
                    }
                }

                SectionCard(title: "CONNECT TO SOMEONE") {
                    HStack {
                        TextField(ctl.transport == "tor" ? "xxxx.onion:5555" : "192.168.1.20:5555", text: $address)
                            .textFieldStyle(.roundedBorder)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("PASTE") { paste() }.buttonStyle(.bordered)
                    }
                    TextField("Expected fingerprint (optional, recommended)", text: $expected)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button {
                        ctl.connect(address.trimmingCharacters(in: .whitespacesAndNewlines),
                                    fingerprint: expected.trimmingCharacters(in: .whitespacesAndNewlines))
                        onConnect()
                    } label: { Text("CONNECT").bold().frame(maxWidth: .infinity) }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(address.trimmingCharacters(in: .whitespaces).isEmpty)
                    Hint("Paste the whole message the other person sent with SHARE: address and fingerprint are picked out for you.")
                }

                SectionCard(title: "CONNECTED (\(ctl.peers.count))") {
                    if ctl.peers.isEmpty { Hint("Nobody yet.") }
                    ForEach(ctl.peers) { p in
                        HStack {
                            Circle().fill(ctl.theme.peerColor(p.color)).frame(width: 10, height: 10)
                            Text(p.name).font(.system(size: 15))
                            Spacer()
                            Button("Rename") { renameText = p.name; renaming = p }.buttonStyle(.bordered)
                        }
                    }
                }
            }
            .padding(14)
        }
        .scrollDismissesKeyboard(.interactively)
        .alert("Rename", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Nickname", text: $renameText)
            Button("Save") {
                if let p = renaming, !renameText.trimmingCharacters(in: .whitespaces).isEmpty { ctl.namePeer(p.fp, renameText) }
                renaming = nil
            }
            Button("Cancel", role: .cancel) { renaming = nil }
        }
    }

    private func paste() {
        guard let t = UIPasteboard.general.string, !t.isEmpty else { return }
        let p = parseShared(t)
        address = p.addr
        if !p.fp.isEmpty { expected = p.fp }
    }
}

// MARK: files

struct FilesTab: View {
    @EnvironmentObject var ctl: MuteController
    @State private var picking = false
    @State private var pickingFolder = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                SectionCard(title: "SEND") {
                    HStack {
                        Button { picking = true } label: { Text("FILE").bold().frame(maxWidth: .infinity) }
                            .buttonStyle(.borderedProminent)
                        Button { pickingFolder = true } label: { Text("FOLDER").bold().frame(maxWidth: .infinity) }
                            .buttonStyle(.bordered)
                    }
                    .controlSize(.large)
                    Hint("A folder is sent as one clean zip. Files are copied to a temporary place first and removed on STOP.")
                    if ctl.peers.isEmpty { Hint("Connect to someone first.") }
                }

                if let t = ctl.transfer {
                    SectionCard(title: "TRANSFER") {
                        Text(t.label).font(.system(size: 13))
                        ProgressView(value: t.done, total: t.total).tint(ctl.theme.acc)
                    }
                }

                SectionCard(title: "QUEUE (\(ctl.queue.count))") {
                    if ctl.queue.isEmpty { Hint("Nothing waiting.") }
                    ForEach(ctl.queue) { q in
                        HStack {
                            Text(q.name).font(.system(size: 14)).lineLimit(1)
                            Spacer()
                            Text(q.state).font(.system(size: 12)).foregroundStyle(ctl.theme.dim)
                        }
                    }
                    HStack {
                        Button(ctl.options.paused ? "RESUME" : "PAUSE") { ctl.togglePause() }.buttonStyle(.bordered)
                        Button("CANCEL ALL", role: .destructive) { ctl.cancelTransfers() }.buttonStyle(.bordered)
                    }
                }

                SectionCard(title: "RECEIVED FILES") {
                    Hint("Received files are in the Files app: On My iPhone > Mute.")
                    let got = ctl.lines.filter { $0.kind == .file }
                    ForEach(got.suffix(20)) { l in
                        Text(l.text).font(.system(size: 13)).foregroundStyle(ctl.theme.acc)
                    }
                }
            }
            .padding(14)
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.item], allowsMultipleSelection: true) { res in
            if case .success(let urls) = res { urls.forEach { ctl.sendItem($0) } }
        }
        .fileImporter(isPresented: $pickingFolder, allowedContentTypes: [.folder], allowsMultipleSelection: false) { res in
            if case .success(let urls) = res { urls.forEach { ctl.sendItem($0) } }
        }
    }
}

// MARK: settings

struct SettingsTab: View {
    @EnvironmentObject var ctl: MuteController
    @State private var applied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                OptionsForm(tor: ctl.transport == "tor", saveTheme: !(ctl.burner || ctl.options.amnesia))

                VoiceSettings()

                if ctl.transport == "tor" {
                    SectionCard(title: "ONION CLIENT KEY") {
                        Hint("If the person you connect to restricts their onion service to listed keys, create your key here and give them the public part. It is shown on the Connect tab and kept in memory only.")
                        Button("Create new key") { ctl.newClientAuth() }.buttonStyle(.bordered)
                    }
                }

                Button {
                    ctl.applyOptions()
                    applied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { applied = false }
                } label: { Text(applied ? "APPLIED" : "APPLY").bold().frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large)

                HStack {
                    Button { ctl.wipeChat() } label: { Text("WIPE CHAT").frame(maxWidth: .infinity) }
                        .buttonStyle(.bordered)
                    Button(role: .destructive) { ctl.stop() } label: { Text("STOP SESSION").bold().frame(maxWidth: .infinity) }
                        .buttonStyle(.bordered)
                }
                .controlSize(.large)
                Hint("Closed mode, shared secret, bridges and key lists take effect for new connections. Options are kept in memory only.")
            }
            .padding(14)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}
