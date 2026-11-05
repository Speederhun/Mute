import Foundation

enum PyError: Error, LocalizedError {
    case message(String)
    var errorDescription: String? {
        if case .message(let m) = self { return m }
        return nil
    }
}

/// Swift side of the embedded Python runtime. Every call goes through ios_entry.call (see python/ios_entry.py).
enum Py {
    /// Starts the interpreter once. Returns an error message or nil.
    static func start() -> String? {
        PyBridge.start(withBundlePath: Bundle.main.bundlePath)
    }

    /// Calls a Python function and returns the "ok" value (String, Number, Bool, ...). Throws the Python error message.
    @discardableResult
    static func call(_ method: String, _ args: [Any] = []) throws -> Any {
        let data = try JSONSerialization.data(withJSONObject: args)
        let json = String(data: data, encoding: .utf8) ?? "[]"
        let reply = PyBridge.call(method, args: json)
        guard let d = reply.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: d) as? [String: Any] else {
            throw PyError.message("Unreadable answer from Python")
        }
        if let e = obj["error"] as? String { throw PyError.message(e) }
        return obj["ok"] ?? NSNull()
    }

    /// For bridge methods that return JSON text: calls and parses it.
    static func json(_ method: String, _ args: [Any] = []) throws -> Any {
        let v = try call(method, args)
        guard let s = v as? String, let d = s.data(using: .utf8) else { return v }
        return try JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed])
    }

    static func dict(_ method: String, _ args: [Any] = []) throws -> [String: Any] {
        (try json(method, args) as? [String: Any]) ?? [:]
    }
}

extension Dictionary where Key == String, Value == Any {
    func str(_ k: String) -> String { (self[k] as? String) ?? "" }
    func int(_ k: String) -> Int { (self[k] as? NSNumber)?.intValue ?? 0 }
    func dbl(_ k: String) -> Double { (self[k] as? NSNumber)?.doubleValue ?? 0 }
    func bool(_ k: String) -> Bool { (self[k] as? NSNumber)?.boolValue ?? false }
}
