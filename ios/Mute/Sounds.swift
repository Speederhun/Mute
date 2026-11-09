import AVFoundation
import Foundation

/// Short notification tones. The waveforms are made in Python (the same ones the desktop app plays).
@MainActor
final class Sounds {
    static let shared = Sounds()
    private var cache: [String: Data] = [:]
    private var players: [AVAudioPlayer] = []
    private var loopPlayer: AVAudioPlayer?
    private var loopTimer: Timer?

    private func wav(_ name: String, _ volume: Int) -> Data? {
        let key = "\(name)@\(volume)"
        if let d = cache[key] { return d }
        guard let s = try? Py.call("sound_wav_b64", [name, volume]) as? String, let d = Data(base64Encoded: s) else { return nil }
        cache[key] = d
        return d
    }

    /// Without a running call the sounds follow the silent switch; during a call the audio session stays as the call set it.
    private func prepareSession() {
        let s = AVAudioSession.sharedInstance()
        if s.category != .playAndRecord { try? s.setCategory(.ambient, options: [.mixWithOthers]); try? s.setActive(true) }
    }

    func play(_ name: String, volume: Int) {
        guard volume > 0, let d = wav(name, volume) else { return }
        prepareSession()
        guard let p = try? AVAudioPlayer(data: d) else { return }
        p.volume = 1
        p.play()
        players.removeAll { !$0.isPlaying }
        players.append(p)
    }

    /// Repeats a sound (ringing, ringback) every `every` seconds until stopLoop().
    func loop(_ name: String, volume: Int, every: TimeInterval) {
        stopLoop()
        play(name, volume: volume)
        loopTimer = Timer.scheduledTimer(withTimeInterval: every, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.play(name, volume: volume) }
        }
    }

    func stopLoop() {
        loopTimer?.invalidate()
        loopTimer = nil
        loopPlayer?.stop()
        loopPlayer = nil
    }
}
