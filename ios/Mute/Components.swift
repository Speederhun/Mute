import SwiftUI

struct SectionCard<Content: View>: View {
    @EnvironmentObject var ctl: MuteController
    let title: String
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 11, weight: .semibold)).tracking(1).foregroundStyle(ctl.theme.acc)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(ctl.theme.chat, in: RoundedRectangle(cornerRadius: 16))
    }
}

struct Hint: View {
    @EnvironmentObject var ctl: MuteController
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.system(size: 12)).foregroundStyle(ctl.theme.dim).fixedSize(horizontal: false, vertical: true)
    }
}

struct SwitchRow: View {
    @EnvironmentObject var ctl: MuteController
    let title: String
    var hint: String? = nil
    @Binding var isOn: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: $isOn) { Text(title).font(.system(size: 15)) }
                .tint(ctl.theme.acc)
            if let hint { Hint(hint) }
        }
    }
}

struct IntField: View {
    @EnvironmentObject var ctl: MuteController
    let title: String
    @Binding var value: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 13)).foregroundStyle(ctl.theme.dim)
            TextField("0", value: $value, format: .number)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
        }
    }
}

struct ChipRow<T: Hashable>: View {
    @EnvironmentObject var ctl: MuteController
    let items: [(String, T)]
    let selected: T
    let onSelect: (T) -> Void

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    let on = item.1 == selected
                    Button { onSelect(item.1) } label: {
                        Text(item.0).font(.system(size: 13))
                            .padding(.horizontal, 12).padding(.vertical, 7)
                            .background(on ? ctl.theme.acc.opacity(0.2) : ctl.theme.btn, in: Capsule())
                            .overlay(Capsule().stroke(on ? ctl.theme.acc : Color.clear, lineWidth: 1.5))
                            .foregroundStyle(on ? ctl.theme.acc : ctl.theme.fg)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

/// All options of the desktop Options window that apply before and during a session.
/// (obfs4/snowflake bridges and the Moat captcha need a transport library that the iOS app does not include.)
struct OptionsForm: View {
    @EnvironmentObject var ctl: MuteController
    let tor: Bool
    let saveTheme: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionCard(title: "ACCESS CONTROL") {
                SwitchRow(title: "Closed mode", hint: "Only allowlisted fingerprints can connect, no prompts.", isOn: $ctl.opts.closed)
                TextField("Allowlist: fingerprints, one per line", text: $ctl.opts.allow, axis: .vertical)
                    .lineLimit(2...6).textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Shared secret (both sides must enter the same)", text: $ctl.opts.psk)
                    .textFieldStyle(.roundedBorder)
                Hint("Stops man-in-the-middle even if the fingerprint check is skipped. Use a long passphrase.")
            }

            if tor && !ctl.started {
                SectionCard(title: "TOR") {
                    TextField("Plain bridges, one per line (IP:port fingerprint)", text: $ctl.opts.bridges, axis: .vertical)
                        .lineLimit(2...6).textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Hint("Hide that you use Tor. obfs4, snowflake and the Tor Project's bridge captcha are not available on iOS (no transport library): only plain bridges work.")
                    TextField("Onion client keys that may reach you (52 characters each, one per line)", text: $ctl.opts.allowedClients, axis: .vertical)
                        .lineLimit(2...5).textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Hint("With keys listed, only their holders can even find your onion service.")
                }
            }

            SectionCard(title: "GROUP CHAT") {
                SwitchRow(title: "Relay hub", hint: "Forward messages between peers who are not connected to each other.", isOn: $ctl.opts.relay)
                SwitchRow(title: "Cover traffic", hint: "Dummy frames that imitate a usage pattern. Adds noise, does not hide when you really talk.", isOn: $ctl.opts.cover)
                if ctl.opts.cover && !ctl.coverProfiles.isEmpty {
                    ChipRow(items: ctl.coverProfiles.map { ($0.name, $0.name) }, selected: ctl.opts.coverProfile) { ctl.opts.coverProfile = $0 }
                    if let p = ctl.coverProfiles.first(where: { $0.name == ctl.opts.coverProfile }) {
                        Hint("\(p.text) - \(p.estimate)")
                    }
                }
                Text("Constant-rate traffic").font(.system(size: 15))
                ChipRow(items: ctl.shapeLabels.map { ($0.label, $0.rate) }, selected: ctl.opts.shape) { ctl.opts.shape = $0 }
                Hint(ctl.opts.shape > 0
                     ? ctl.shapeEstimate(ctl.opts.shape, tor: tor)
                     : "Every frame the same size on a fixed clock: nobody can see when or how much you talk. Costs bandwidth and speed.")
            }

            SectionCard(title: "FILES") {
                IntField(title: "Speed limit per peer (KB/s, 0 = unlimited)", value: $ctl.opts.speedLimitKbs)
                SwitchRow(title: "Scrub metadata", hint: "Strip EXIF, document properties etc. from outgoing files.", isOn: $ctl.opts.scrub)
            }

            SectionCard(title: "PRIVACY") {
                SwitchRow(title: "Amnesia (save nothing)", hint: "Trusted peers are not remembered between starts.", isOn: $ctl.opts.amnesia)
                IntField(title: "Key renewal every N seconds (0 = off)", value: $ctl.opts.ratchet)
                if !tor {
                    TextField("SOCKS5 proxy for direct connections (host:port)", text: $ctl.opts.proxy)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }
            }

            SectionCard(title: "APP") {
                SwitchRow(title: "Clear clipboard 30 s after copying", isOn: $ctl.settings.clipboardClear)
                IntField(title: "Auto-clear chat after N minutes (0 = off)", value: $ctl.settings.autoClearMin)
                IntField(title: "Auto-lock after N idle minutes (0 = off)", value: $ctl.settings.autoLockMin)
                SecureField("Lock password (empty = Unlock button only)", text: $ctl.settings.lockPassword)
                    .textFieldStyle(.roundedBorder)
                Text("Theme").font(.system(size: 15))
                ChipRow(items: ctl.themes.map { ($0.name, $0.name) }, selected: ctl.theme.name) { ctl.setTheme($0, save: saveTheme) }
            }
        }
    }
}

/// Pulls the address and (if present) the fingerprint out of pasted text, e.g. the message made by SHARE.
func parseShared(_ text: String) -> (addr: String, fp: String) {
    var addr = "", fp = ""
    for raw in text.components(separatedBy: .newlines) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        let lower = line.lowercased()
        if lower.hasPrefix("mute address:") {
            addr = String(line.dropFirst("mute address:".count)).trimmingCharacters(in: .whitespaces)
        } else if lower.hasPrefix("fingerprint:") {
            fp = String(line.dropFirst("fingerprint:".count)).trimmingCharacters(in: .whitespaces)
        }
    }
    if addr.isEmpty {
        if let r = text.range(of: "[a-z2-7]{16,56}\\.onion(:\\d{1,5})?", options: [.regularExpression, .caseInsensitive]) {
            addr = String(text[r])
        } else {
            let first = text.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: .newlines).first ?? ""
            addr = first.trimmingCharacters(in: .whitespaces).components(separatedBy: .whitespaces).last ?? ""
        }
    }
    return (addr.replacingOccurrences(of: " ", with: ""), fp)
}
