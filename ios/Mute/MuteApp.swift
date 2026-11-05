import SwiftUI

@main
struct MuteApp: App {
    @StateObject private var ctl = MuteController()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(ctl)
                .preferredColorScheme(ctl.theme.isLight ? .light : .dark)
                .tint(ctl.theme.acc)
                .onAppear { ctl.boot() }
        }
    }
}

private var introPlayed = false

struct RootView: View {
    @EnvironmentObject var ctl: MuteController
    @Environment(\.scenePhase) private var phase
    @State private var intro = !introPlayed

    var body: some View {
        ZStack {
            ctl.theme.bg.ignoresSafeArea()
            if let err = ctl.bootError {
                VStack(spacing: 12) {
                    Text("Could not start").font(.title2.bold())
                    Text(err).font(.footnote).multilineTextAlignment(.center)
                }
                .foregroundStyle(ctl.theme.red)
                .padding(24)
            } else if !ctl.booted {
                ProgressView().tint(ctl.theme.acc)
            } else if ctl.started {
                ChatRoot()
            } else {
                SetupView()
            }

            if ctl.locked { LockView() }
            // nothing sensitive in the app switcher snapshot or in a screen recording
            if (phase != .active && ctl.started) || ctl.captured { PrivacyCover() }
            if intro { IntroView { introPlayed = true; intro = false } }
        }
        .foregroundStyle(ctl.theme.fg)
        .simultaneousGesture(TapGesture().onEnded { ctl.touch() })
        .onChange(of: phase) { p in
            if p == .active { ctl.appForegrounded() } else if p == .background { ctl.appBackgrounded() }
        }
        .sheet(item: Binding(get: { ctl.locked ? nil : ctl.confirm }, set: { _ in })) { c in
            ConfirmView(request: c).interactiveDismissDisabled()
        }
    }
}

struct PrivacyCover: View {
    @EnvironmentObject var ctl: MuteController
    var body: some View {
        ZStack {
            ctl.theme.bg.ignoresSafeArea()
            Text("MUTE").font(.system(size: 34, weight: .bold, design: .monospaced)).foregroundStyle(ctl.theme.acc)
        }
    }
}

// MARK: start-up animation (~2.6 s, tap to skip): sonar rings + the name "decrypting" from random symbols

struct IntroView: View {
    @EnvironmentObject var ctl: MuteController
    let onDone: () -> Void
    @State private var start = Date()
    @State private var finished = false
    private let word = Array("MUTE")
    private let glyphs = Array("01#%&@$<>/\\|=+*?!~")
    private let duration = 2.6

    var body: some View {
        TimelineView(.animation) { tl in
            let p = min(1, tl.date.timeIntervalSince(start) / duration)
            let fade = p > 0.88 ? 1 - (p - 0.88) / 0.12 : 1
            let frame = Int(p * 46)
            let tagline = max(0, min(1, (p - 0.62) / 0.16))
            ZStack {
                ctl.theme.bg.ignoresSafeArea()
                Canvas { ctx, size in
                    let maxR = max(size.width, size.height) * 0.55
                    let c = CGPoint(x: size.width / 2, y: size.height / 2)
                    for k in 0..<3 {
                        let t = (p * 1.6 + Double(k) / 3).truncatingRemainder(dividingBy: 1)
                        let r = maxR * t
                        let path = Path(ellipseIn: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
                        ctx.stroke(path, with: .color(ctl.theme.acc.opacity((1 - t) * 0.35)), lineWidth: 2)
                    }
                }
                .ignoresSafeArea()
                VStack(spacing: 14) {
                    Text(scramble(p: p, frame: frame))
                        .font(.system(size: 56, weight: .bold, design: .monospaced))
                        .tracking(10)
                        .foregroundStyle(ctl.theme.acc)
                    Text("end-to-end encrypted · serverless")
                        .font(.system(size: 13)).tracking(2)
                        .foregroundStyle(ctl.theme.fg).opacity(tagline)
                    Text("no accounts · no servers · no trace")
                        .font(.system(size: 11)).tracking(1)
                        .foregroundStyle(ctl.theme.dim).opacity(tagline)
                }
            }
            .opacity(fade)
            .onChange(of: p >= 1) { done in if done { finish() } }
        }
        .contentShape(Rectangle())
        .onTapGesture { finish() }
        .onAppear { start = Date() }
    }

    private func finish() {
        guard !finished else { return }
        finished = true
        onDone()
    }

    private func scramble(p: Double, frame: Int) -> String {
        var s = ""
        for i in 0..<word.count {
            if p >= 0.22 + Double(i) * 0.13 {
                s.append(word[i])
            } else {
                let x = sin(Double(frame * 31 + i * 7) * 12.9898) * 43758.5453
                let frac = x - x.rounded(.down)
                s.append(glyphs[Int(frac * Double(glyphs.count)) % glyphs.count])
            }
        }
        return s
    }
}

// MARK: lock screen and fingerprint confirmation

struct LockView: View {
    @EnvironmentObject var ctl: MuteController
    @State private var attempt = ""
    @State private var wrong = false

    var body: some View {
        ZStack {
            ctl.theme.bg.ignoresSafeArea()
            VStack(spacing: 16) {
                Text("LOCKED").font(.system(size: 28, weight: .bold, design: .monospaced)).foregroundStyle(ctl.theme.acc)
                Text("The connection stays up. Messages keep arriving but are hidden.")
                    .font(.footnote).foregroundStyle(ctl.theme.dim).multilineTextAlignment(.center)
                if !ctl.settings.lockPassword.isEmpty {
                    SecureField("Password", text: $attempt)
                        .textFieldStyle(.roundedBorder).frame(maxWidth: 280)
                        .onSubmit { tryUnlock() }
                    if wrong { Text("Wrong password").foregroundStyle(ctl.theme.red).font(.footnote) }
                }
                Button("Unlock") { tryUnlock() }
                    .buttonStyle(.borderedProminent)
            }
            .padding(24)
        }
    }

    private func tryUnlock() {
        if ctl.unlock(attempt) { attempt = ""; wrong = false } else { wrong = true }
    }
}

struct ConfirmView: View {
    @EnvironmentObject var ctl: MuteController
    let request: ConfirmRequest

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("New peer").font(.title2.bold())
            Text("Compare these six words with the other person, over a call or in person. If they match, accept.")
                .font(.subheadline).foregroundStyle(ctl.theme.dim)
            Text(request.words)
                .font(.system(size: 22, weight: .semibold, design: .monospaced))
                .foregroundStyle(ctl.theme.acc)
            Text("Fingerprint").font(.caption).foregroundStyle(ctl.theme.dim)
            Text(request.fp).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            Spacer()
            HStack(spacing: 12) {
                Button(role: .destructive) { ctl.answerConfirm(false) } label: { Text("Reject").frame(maxWidth: .infinity) }
                    .buttonStyle(.bordered)
                Button { ctl.answerConfirm(true) } label: { Text("Accept").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)
        }
        .padding(24)
        .background(ctl.theme.bg.ignoresSafeArea())
        .foregroundStyle(ctl.theme.fg)
        .presentationDetents([.medium, .large])
    }
}
