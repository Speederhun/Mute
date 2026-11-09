import AVFoundation
import SwiftUI

struct CallUi: Equatable {
    var state: String            // incoming | ringing | active
    var fp: String
    var name: String
    var muted = false
    var remoteMuted = false
    var speaker = false
    var since = Date()
}

struct AudioPrefs: Equatable {
    var sounds = true
    var soundVolume = 70
    var volume = 100
    var micGain = 100
    var ptt = false

    init() {}
    init(_ o: [String: Any]) {
        sounds = o["sounds"] as? Bool ?? true
        soundVolume = o.int("sound_volume")
        volume = o.int("volume")
        micGain = o.int("mic_gain")
        ptt = o["ptt"] as? Bool ?? false
    }
    var json: [String: Any] {
        ["sounds": sounds, "sound_volume": soundVolume, "volume": volume, "mic_gain": micGain, "ptt": ptt]
    }
}

private let callEndText = [
    "rejected": "Call declined", "busy": "Busy - the other side is already in a call", "noanswer": "No answer",
    "missed": "Missed call", "ended": "Call ended", "ended-remote": "Call ended by the other side",
]

extension MuteController {
    // MARK: actions

    func startCall(_ fp: String) {
        guard call == nil else { return }
        withMic { [weak self] ok in
            guard ok else { self?.addLine(who: "", text: "Microphone access is off: allow it in Settings > Mute.", kind: .sys); return }
            Task.detached {
                do { try Py.call("call_peer", [fp]) } catch {
                    await MainActor.run { self?.addLine(who: "", text: "Call failed: \(error.localizedDescription)", kind: .sys) }
                }
            }
        }
    }

    func acceptCall() {
        withMic { [weak self] ok in
            if ok { Task.detached { _ = try? Py.call("call_accept") } } else {
                self?.addLine(who: "", text: "Microphone access is off: allow it in Settings > Mute.", kind: .sys)
                self?.rejectCall()
            }
        }
    }

    func rejectCall() { Task.detached { _ = try? Py.call("call_reject") } }
    func hangUp() { Task.detached { _ = try? Py.call("call_hangup") } }

    func toggleMute() {
        guard var c = call else { return }
        c.muted.toggle()
        call = c
        let on = c.muted
        Task.detached { _ = try? Py.call("call_mute", [on]) }
    }

    /// Speakerphone: loudspeaker output, and the microphone is muted while the other side talks (no echo).
    func toggleSpeaker() {
        guard var c = call else { return }
        c.speaker.toggle()
        call = c
        CallAudio.shared.setSpeaker(c.speaker)
        let on = c.speaker
        Task.detached { _ = try? Py.call("call_duck", [on]) }
    }

    /// Push to talk: true while the talk button is held.
    func ptt(_ down: Bool) { Task.detached { _ = try? Py.call("call_ptt", [down]) } }

    func setAudio(_ a: AudioPrefs, save: Bool = true) {
        audio = a
        let j = jsonString(a.json)
        Task.detached { _ = try? Py.call("set_audio_prefs", [j, save]) }
    }

    func testSound() { Sounds.shared.play("message", volume: audio.soundVolume) }

    private func withMic(_ done: @escaping @MainActor (Bool) -> Void) {
        AVAudioSession.sharedInstance().requestRecordPermission { ok in
            Task.detached { _ = try? Py.call("set_mic_permission", [ok]) }
            Task { @MainActor in done(ok) }
        }
    }

    // MARK: events

    func onCallEvent(state: String, fp: String, name: String, detail: String) {
        let vol = audio.soundVolume
        let on = audio.sounds
        switch state {
        case "incoming":
            call = CallUi(state: "incoming", fp: fp, name: name)
            if on { Sounds.shared.loop("ring", volume: vol, every: 2.4) }
            UIApplication.shared.isIdleTimerDisabled = true
        case "ringing":
            call = CallUi(state: "ringing", fp: fp, name: name)
            if on { Sounds.shared.loop("ringback", volume: vol, every: 3.5) }
        case "active":
            Sounds.shared.stopLoop()
            if on { Sounds.shared.play("connected", volume: vol) }
            var c = call ?? CallUi(state: "active", fp: fp, name: name)
            c.state = "active"
            c.since = Date()
            call = c
        case "remote-mute":
            call?.remoteMuted = (detail == "1")
        default:                                                // the call is over, whatever the reason
            Sounds.shared.stopLoop()
            if on { Sounds.shared.play(state == "error" ? "error" : "ended", volume: vol) }
            var secs: Int?
            if let c = call, c.state == "active" { secs = Int(Date().timeIntervalSince(c.since)) }
            var text = state == "error" ? "Call failed: \(detail)" : (callEndText[state] ?? "Call ended")
            if let s = secs { text += String(format: " (%d:%02d)", s / 60, s % 60) }
            if state == "missed", !name.isEmpty { text += " from \(name)" }
            addLine(who: "", text: text, kind: .sys)
            call = nil
        }
    }

    func onAudioEvent(_ action: String) {
        if action == "start" {
            if let err = CallAudio.shared.start(speaker: call?.speaker == true) {
                addLine(who: "", text: "Audio error: \(err)", kind: .sys)
                hangUp()
            }
        } else {
            CallAudio.shared.stop()
        }
    }

    func endCallLocally() {
        Sounds.shared.stopLoop()
        CallAudio.shared.stop()
        call = nil
    }
}

// MARK: views

struct CallPanel: View {
    @EnvironmentObject var ctl: MuteController
    let call: CallUi
    @State private var held = false

    var body: some View {
        VStack(spacing: 10) {
            Text(title).font(.system(size: 15, weight: .semibold)).foregroundStyle(ctl.theme.fg)
            if call.state == "active" {
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    let s = Int(Date().timeIntervalSince(call.since))
                    Text(String(format: "%d:%02d", s / 60, s % 60) + (call.remoteMuted ? "   (muted on the other side)" : ""))
                        .font(.system(size: 13, design: .monospaced)).foregroundStyle(ctl.theme.dim)
                }
            }
            switch call.state {
            case "incoming":
                HStack(spacing: 12) {
                    Button { ctl.rejectCall() } label: { Label("Decline", systemImage: "phone.down.fill").frame(maxWidth: .infinity) }
                        .buttonStyle(.borderedProminent).tint(ctl.theme.red)
                    Button { ctl.acceptCall() } label: { Label("Accept", systemImage: "phone.fill").frame(maxWidth: .infinity) }
                        .buttonStyle(.borderedProminent).tint(.green)
                }
            case "ringing":
                Button { ctl.hangUp() } label: { Label("Cancel", systemImage: "phone.down.fill").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).tint(ctl.theme.red)
            default:
                if ctl.audio.ptt { talkButton }
                HStack(spacing: 10) {
                    if !ctl.audio.ptt {
                        Button { ctl.toggleMute() } label: {
                            Label(call.muted ? "Unmute" : "Mute", systemImage: call.muted ? "mic.slash.fill" : "mic.fill").frame(maxWidth: .infinity)
                        }.buttonStyle(.bordered)
                    }
                    Button { ctl.toggleSpeaker() } label: {
                        Label("Speaker", systemImage: call.speaker ? "speaker.wave.3.fill" : "speaker.fill").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(call.speaker ? ctl.theme.acc : nil)
                    Button { ctl.hangUp() } label: { Label("Hang up", systemImage: "phone.down.fill").frame(maxWidth: .infinity) }
                        .buttonStyle(.borderedProminent).tint(ctl.theme.red)
                }
                HStack(spacing: 8) {
                    Image(systemName: "speaker.fill").foregroundStyle(ctl.theme.dim)
                    Slider(value: Binding(get: { Double(ctl.audio.volume) },
                                          set: { var a = ctl.audio; a.volume = Int($0); ctl.setAudio(a, save: false) }),
                           in: 0...200, onEditingChanged: { editing in if !editing { ctl.setAudio(ctl.audio) } })
                        .tint(ctl.theme.acc)
                    Text("\(ctl.audio.volume)%").font(.system(size: 12)).foregroundStyle(ctl.theme.dim).frame(width: 44, alignment: .trailing)
                }
            }
        }
        .controlSize(.regular)
        .padding(12)
        .background(ctl.theme.chat)
    }

    private var title: String {
        let n = call.name.isEmpty ? "peer" : call.name
        switch call.state {
        case "incoming": return "\(n) is calling"
        case "ringing": return "Calling \(n)..."
        default: return "In call with \(n)"
        }
    }

    /// Hold to talk: the microphone only transmits while the finger is down.
    private var talkButton: some View {
        Text(held ? "TALKING..." : "HOLD TO TALK")
            .font(.system(size: 17, weight: .bold)).foregroundStyle(held ? ctl.theme.bg : ctl.theme.fg)
            .frame(maxWidth: .infinity, minHeight: 64)
            .background(held ? ctl.theme.acc : ctl.theme.btn, in: RoundedRectangle(cornerRadius: 16))
            .gesture(DragGesture(minimumDistance: 0)
                .onChanged { _ in if !held { held = true; ctl.ptt(true) } }
                .onEnded { _ in held = false; ctl.ptt(false) })
            .onDisappear { if held { held = false; ctl.ptt(false) } }
    }
}

struct VoiceSettings: View {
    @EnvironmentObject var ctl: MuteController

    private func slider(_ label: String, _ value: Int, _ range: ClosedRange<Double>, _ set: @escaping (inout AudioPrefs, Int) -> Void) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(label): \(value)%").font(.system(size: 14)).foregroundStyle(ctl.theme.fg)
            Slider(value: Binding(get: { Double(value) },
                                  set: { var a = ctl.audio; set(&a, Int($0)); ctl.setAudio(a, save: false) }),
                   in: range, onEditingChanged: { editing in if !editing { ctl.setAudio(ctl.audio) } })
                .tint(ctl.theme.acc)
        }
    }

    var body: some View {
        SectionCard(title: "VOICE CALLS AND SOUNDS") {
            slider("Call volume", ctl.audio.volume, 0...200) { $0.volume = $1 }
            slider("Microphone gain", ctl.audio.micGain, 0...300) { $0.micGain = $1 }
            SwitchRow(title: "Push to talk", hint: "A big hold-to-talk button replaces Mute: the microphone only transmits while you press it.",
                      isOn: Binding(get: { ctl.audio.ptt }, set: { var a = ctl.audio; a.ptt = $0; ctl.setAudio(a) }))
            SwitchRow(title: "Sounds", hint: "Short tones for new messages, connected peers, received files and calls.",
                      isOn: Binding(get: { ctl.audio.sounds }, set: { var a = ctl.audio; a.sounds = $0; ctl.setAudio(a) }))
            slider("Sound volume", ctl.audio.soundVolume, 0...100) { $0.soundVolume = $1 }
            Button("Test sound") { ctl.testSound() }.buttonStyle(.bordered)
            Hint("Calls only work while the app is open: iOS suspends it in the background. Keep the screen on during a call.")
        }
    }
}
