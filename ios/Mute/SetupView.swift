import SwiftUI

struct SetupView: View {
    @EnvironmentObject var ctl: MuteController
    @State private var tor = false
    @State private var burner = false
    @State private var pass = ""
    @State private var showOptions = false

    private var needsPass: Bool { ctl.idState == "encrypted" && !burner }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("MUTE").font(.system(size: 34, weight: .bold)).foregroundStyle(ctl.theme.acc)
                Text("Serverless end-to-end encrypted chat and file transfer.")
                    .font(.system(size: 14)).foregroundStyle(ctl.theme.dim)

                Text("1. Choose connection").font(.system(size: 16, weight: .semibold))
                HStack(spacing: 12) {
                    ModeCard(title: "DIRECT", subtitle: "Plain TCP, port 5555.\nLAN, port forward or VPN.", selected: !tor) { tor = false }
                    ModeCard(title: "TOR", subtitle: "Onion address.\nHides both IP addresses.", selected: tor) { tor = true }
                }
                if tor {
                    Hint("Tor starts when you press START (up to a minute). After start you get your .onion address; to reach someone, enter their .onion address on the Connect tab.")
                }

                Text("2. Identity").font(.system(size: 16, weight: .semibold))
                SwitchRow(title: "Burner identity (random key, nothing saved)", isOn: $burner)
                if !burner {
                    SecureField(
                        ctl.idState == "encrypted" ? "Identity passphrase"
                            : ctl.idState == "missing" ? "New identity passphrase (empty = none)"
                            : "Identity passphrase (not needed)",
                        text: $pass
                    )
                    .textFieldStyle(.roundedBorder)
                    .disabled(ctl.idState == "plain")
                }

                Button { withAnimation { showOptions.toggle() } } label: {
                    Text(showOptions ? "Hide options" : "Options").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered).controlSize(.large)
                if showOptions { OptionsForm(tor: tor, saveTheme: !(burner || ctl.opts.amnesia)) }

                if let e = ctl.error {
                    Text(e).font(.system(size: 13)).foregroundStyle(ctl.theme.red).textSelection(.enabled)
                }
                if ctl.busy, !ctl.statusLine.isEmpty {
                    Text(ctl.statusLine).font(.system(size: 13)).foregroundStyle(ctl.theme.dim)
                }

                Button {
                    ctl.start(passphrase: pass, burner: burner, tor: tor)
                } label: {
                    HStack {
                        if ctl.busy { ProgressView().tint(ctl.theme.bg) }
                        Text(ctl.busy ? "Starting..." : (tor ? "START TOR" : "START DIRECT")).bold()
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(ctl.busy || (needsPass && pass.isEmpty))
            }
            .padding(16)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}

struct ModeCard: View {
    @EnvironmentObject var ctl: MuteController
    let title: String
    let subtitle: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.system(size: 20, weight: .bold))
                    .foregroundStyle(selected ? ctl.theme.acc : ctl.theme.fg)
                Text(subtitle).font(.system(size: 12)).foregroundStyle(ctl.theme.dim)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(selected ? ctl.theme.acc.opacity(0.16) : ctl.theme.chat, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(selected ? ctl.theme.acc : ctl.theme.dim.opacity(0.5), lineWidth: selected ? 2 : 1))
        }
        .buttonStyle(.plain)
    }
}
