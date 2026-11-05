import Foundation
import Tor
import Darwin

/// Runs Tor inside the app process (iOS cannot start a separate tor program). Tor can only be started
/// once per process, so the same instance serves every session; Python just publishes and removes
/// an onion service through its control port.
final class TorService {
    static let shared = TorService()

    private var thread: TorThread?
    private(set) var socksPort = 0
    private(set) var controlPort = 0

    /// Starts Tor if needed and returns (socksPort, controlPort) once the control port answers. Blocking: call off the main thread.
    func start() throws -> (Int, Int) {
        if thread != nil { return (socksPort, controlPort) }

        socksPort = Self.freePort()
        controlPort = Self.freePort()
        guard socksPort > 0, controlPort > 0 else { throw PyError.message("No free local port for Tor") }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("mute_tor", isDirectory: true)
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])

        let conf = TorConfiguration()
        conf.ignoreMissingTorrc = true
        conf.cookieAuthentication = true
        conf.dataDirectory = dir
        // set through KVC so it works whether the property is typed NSArray or NSMutableArray
        conf.setValue(NSMutableArray(array: [
            "--SocksPort", "127.0.0.1:\(socksPort)",
            "--ControlPort", "127.0.0.1:\(controlPort)",
            "--ClientOnly", "1",
            "--AvoidDiskWrites", "1",
            "--SafeLogging", "1",
        ]), forKey: "arguments")

        let t = TorThread(configuration: conf)
        thread = t
        t.start()

        // wait for the control port to accept connections
        let end = Date().addingTimeInterval(30)
        while Date() < end {
            if Self.canConnect(port: controlPort) { return (socksPort, controlPort) }
            Thread.sleep(forTimeInterval: 0.25)
        }
        throw PyError.message("Tor did not start (control port stayed closed)")
    }

    static func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return 0 }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { return 0 }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let got = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard got == 0 else { return 0 }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    static func canConnect(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = UInt16(port).bigEndian
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return r == 0
    }
}
