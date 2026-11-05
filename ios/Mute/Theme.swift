import SwiftUI

extension Color {
    init(hex: String) {
        var h = hex.trimmingCharacters(in: .whitespaces)
        if h.hasPrefix("#") { h.removeFirst() }
        var v: UInt64 = 0
        Scanner(string: h).scanHexInt64(&v)
        self.init(.sRGB,
                  red: Double((v >> 16) & 0xFF) / 255,
                  green: Double((v >> 8) & 0xFF) / 255,
                  blue: Double(v & 0xFF) / 255,
                  opacity: 1)
    }
}

/// Same roles as mute.THEMES on the desktop: bg, fg (text), dim, acc, red, btn, ent, chat + peer palette.
struct ThemeColors: Equatable {
    var name: String
    var bg: Color, fg: Color, dim: Color, acc: Color, red: Color, btn: Color, ent: Color, chat: Color
    var pal: [Color]
    var isLight: Bool

    func peerColor(_ index: Int) -> Color {
        (index < 0 || pal.isEmpty) ? acc : pal[index % pal.count]
    }

    static let ice = ThemeColors(
        name: "ice", bg: Color(hex: "#04080f"), fg: Color(hex: "#9fd8ff"), dim: Color(hex: "#5b86a8"),
        acc: Color(hex: "#4fffe3"), red: Color(hex: "#ff6b81"), btn: Color(hex: "#0b1a2b"),
        ent: Color(hex: "#07111d"), chat: Color(hex: "#060d17"),
        pal: ["#4fffe3", "#ffd166", "#ff9ecf", "#b39bff", "#ffa94d", "#8bf5a8", "#7fb6ff", "#ff8fa3"].map { Color(hex: $0) },
        isLight: false
    )

    static func luminance(_ hex: String) -> Double {
        var h = hex; if h.hasPrefix("#") { h.removeFirst() }
        var v: UInt64 = 0
        Scanner(string: h).scanHexInt64(&v)
        func lin(_ c: Double) -> Double { c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4) }
        let r = lin(Double((v >> 16) & 0xFF) / 255), g = lin(Double((v >> 8) & 0xFF) / 255), b = lin(Double(v & 0xFF) / 255)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    /// Parses the JSON of mute.THEMES, keeping its order of names.
    static func parseAll(_ obj: [String: Any]) -> [ThemeColors] {
        var out: [ThemeColors] = []
        for name in obj.keys.sorted() {
            guard let t = obj[name] as? [String: Any] else { continue }
            let pal = (t["pal"] as? [String] ?? []).map { Color(hex: $0) }
            let bg = (t["bg"] as? String) ?? "#000000"
            out.append(ThemeColors(
                name: name, bg: Color(hex: bg), fg: Color(hex: t.str("fg")), dim: Color(hex: t.str("dim")),
                acc: Color(hex: t.str("acc")), red: Color(hex: t.str("red")), btn: Color(hex: t.str("btn")),
                ent: Color(hex: t.str("ent")), chat: Color(hex: t.str("chat")),
                pal: pal, isLight: luminance(bg) > 0.5
            ))
        }
        return out
    }
}
