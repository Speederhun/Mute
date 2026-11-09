import AVFoundation
import Foundation

/// Microphone and speaker for voice calls. Python owns the codec and the timing: this class only moves
/// 16 kHz mono 16-bit blocks (320 samples = 20 ms) in and out through the bridge.
final class CallAudio: @unchecked Sendable {
    static let shared = CallAudio()

    private let blockSamples = 320
    private let lock = NSLock()
    private var engine: AVAudioEngine?
    private var running = false
    private var ring: [Float] = []                 // playback samples waiting to be rendered
    private var micPending: [Int16] = []           // captured samples that do not yet fill a block
    private let micQueue = DispatchQueue(label: "mute.mic")
    private var converter: AVAudioConverter?
    private var speaker = false
    private var useVP = true
    private var observer: NSObjectProtocol?
    private var micBlocks = 0, outBlocks = 0, restarts = 0
    private var lastError = ""
    private var micFormat = ""

    /// Returns an error text or nil.
    func start(speaker: Bool) -> String? {
        stop()
        self.speaker = speaker
        micBlocks = 0; outBlocks = 0; restarts = 0; lastError = ""
        useVP = true
        var err = build()
        if err != nil {                                   // voice processing can be refused: try again with the plain microphone
            teardown()
            useVP = false
            err = build()
        }
        if err != nil { return err }
        observer = NotificationCenter.default.addObserver(forName: .AVAudioEngineConfigurationChange, object: nil, queue: .main) { [weak self] _ in
            guard let self, self.running else { return }
            self.restarts += 1
            self.reconfigure(attempt: 0)
        }
        let t = Thread { [weak self] in self?.pump() }
        t.name = "mute.pump"
        t.qualityOfService = .userInteractive
        t.start()
        return nil
    }

    var diagnostics: String {
        "mic \(micBlocks) out \(outBlocks) · \(useVP ? "VP" : "plain") \(micFormat)" + (restarts > 0 ? " · restarts \(restarts)" : "") + (lastError.isEmpty ? "" : " · \(lastError)")
    }

    private func build() -> String? {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth, .allowBluetoothA2DP])
            try session.setPreferredSampleRate(16000)
            try session.setActive(true)
        } catch { return "audio session: \(error.localizedDescription)" }

        let eng = AVAudioEngine()
        let input = eng.inputNode
        if useVP { try? input.setVoiceProcessingEnabled(true) }          // echo cancellation and noise suppression
        guard let wire = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: 16000, channels: 1, interleaved: false) else {
            return "audio format"
        }
        let inFmt = input.outputFormat(forBus: 0)
        guard inFmt.sampleRate > 0, inFmt.channelCount > 0 else { return "no microphone input" }
        micFormat = "\(Int(inFmt.sampleRate))Hz/\(inFmt.channelCount)ch"
        converter = AVAudioConverter(from: inFmt, to: wire)
        lock.lock(); ring = []; micPending = []; lock.unlock()

        input.installTap(onBus: 0, bufferSize: 1024, format: inFmt) { [weak self] buf, _ in
            self?.capture(buf, wire: wire)
        }
        let src = AVAudioSourceNode(format: wire) { [weak self] _, _, frames, abl -> OSStatus in
            guard let self else { return noErr }
            let list = UnsafeMutableAudioBufferListPointer(abl)
            guard let out = list.first?.mData?.assumingMemoryBound(to: Float.self) else { return noErr }
            self.lock.lock()
            let n = min(Int(frames), self.ring.count)
            for i in 0..<n { out[i] = self.ring[i] }
            if n > 0 { self.ring.removeFirst(n) }
            self.lock.unlock()
            if n < Int(frames) { for i in n..<Int(frames) { out[i] = 0 } }
            return noErr
        }
        eng.attach(src)
        eng.connect(src, to: eng.mainMixerNode, format: wire)
        do { try eng.start() } catch { input.removeTap(onBus: 0); return "audio engine: \(error.localizedDescription)" }
        engine = eng
        running = true
        setSpeaker(speaker)
        return nil
    }

    /// The route or format changed (loudspeaker, headphones, Bluetooth, voice processing) and the engine stopped.
    /// Keep the same engine and its nodes: re-read the microphone format, put the tap back and start again.
    /// The format can read as 0 Hz for a moment, so retry a few times.
    private func reconfigure(attempt: Int) {
        guard running, let eng = engine else { return }
        let input = eng.inputNode
        input.removeTap(onBus: 0)
        let inFmt = input.outputFormat(forBus: 0)
        if inFmt.sampleRate > 0, inFmt.channelCount > 0,
           let wire = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: 16000, channels: 1, interleaved: false) {
            micFormat = "\(Int(inFmt.sampleRate))Hz/\(inFmt.channelCount)ch"
            converter = AVAudioConverter(from: inFmt, to: wire)
            lock.lock(); micPending = []; lock.unlock()
            input.installTap(onBus: 0, bufferSize: 1024, format: inFmt) { [weak self] buf, _ in
                self?.capture(buf, wire: wire)
            }
            do {
                if !eng.isRunning { try eng.start() }
                lastError = ""
                return
            } catch { lastError = "restart: \(error.localizedDescription)" }
        } else {
            lastError = "no microphone input (try \(attempt + 1))"
        }
        if attempt < 8 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.reconfigure(attempt: attempt + 1) }
        }
    }

    private func teardown(keepRunning: Bool = false) {
        if !keepRunning { running = false }
        engine?.inputNode.removeTap(onBus: 0)
        engine?.stop()
        engine = nil
        converter = nil
        lock.lock(); ring = []; micPending = []; lock.unlock()
    }

    func stop() {
        guard running || engine != nil else { return }
        if let o = observer { NotificationCenter.default.removeObserver(o); observer = nil }
        teardown()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    func setSpeaker(_ on: Bool) {
        speaker = on
        try? AVAudioSession.sharedInstance().overrideOutputAudioPort(on ? .speaker : .none)
    }

    // MARK: microphone -> Python

    private func capture(_ buf: AVAudioPCMBuffer, wire: AVAudioFormat) {
        guard let conv = converter else { return }
        let ratio = wire.sampleRate / buf.format.sampleRate
        let cap = AVAudioFrameCount(Double(buf.frameLength) * ratio) + 32
        guard let out = AVAudioPCMBuffer(pcmFormat: wire, frameCapacity: cap) else { return }
        var fed = false
        var err: NSError?
        conv.convert(to: out, error: &err) { _, status in
            if fed { status.pointee = .noDataNow; return nil }
            fed = true
            status.pointee = .haveData
            return buf
        }
        guard err == nil, let ch = out.floatChannelData?[0] else { return }
        let n = Int(out.frameLength)
        var blocks: [[Int16]] = []
        lock.lock()
        for i in 0..<n {
            let v = max(-1, min(1, ch[i]))
            micPending.append(Int16(v * 32767))
            if micPending.count == blockSamples { blocks.append(micPending); micPending.removeAll(keepingCapacity: true) }
        }
        lock.unlock()
        for b in blocks {
            let data = b.withUnsafeBufferPointer { Data(buffer: $0) }          // little endian on every Apple device
            let s = data.base64EncodedString()
            micBlocks += 1
            micQueue.async { _ = try? Py.call("audio_in_b64", [s]) }
        }
    }

    // MARK: Python -> speaker

    private func pump() {
        while running {
            lock.lock(); let have = ring.count; lock.unlock()
            if have >= blockSamples * 3 { Thread.sleep(forTimeInterval: 0.006); continue }
            guard let s = try? Py.call("audio_out_b64") as? String, let d = Data(base64Encoded: s) else {
                Thread.sleep(forTimeInterval: 0.01); continue
            }
            var floats = [Float](repeating: 0, count: d.count / 2)
            d.withUnsafeBytes { raw in
                let p = raw.bindMemory(to: Int16.self)
                for i in 0..<floats.count { floats[i] = Float(Int16(littleEndian: p[i])) / 32768 }
            }
            outBlocks += 1
            lock.lock(); ring.append(contentsOf: floats); lock.unlock()
        }
    }
}
