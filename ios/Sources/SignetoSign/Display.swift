// docs/protocol.md §3.6: the display escape rule, byte for byte the same as `@signeto/protocol` displayEscape and
// fixed by the shared vectors in public/packages/protocol/vectors/display-escape/. Every string a card, list or
// notification shows from a request, a relay or a pairing goes through `Display.escape` first.
import Foundation

public enum Display {
    /// True for a scalar shown as an escape instead of itself (§3.6): C0 U+0000–U+001F (TAB, LF, CR included),
    /// DEL U+007F, C1 U+0080–U+009F, U+061C, U+200B–U+200F, U+2028–U+202E, U+2060–U+2069 and U+FEFF.
    /// (Lone surrogates, also escaped by the TypeScript rule, cannot occur in a Swift String.)
    public static func isEscaped(_ v: UInt32) -> Bool {
        v <= 0x1F || (v >= 0x7F && v <= 0x9F) || v == 0x061C || (v >= 0x200B && v <= 0x200F)
            || (v >= 0x2028 && v <= 0x202E) || (v >= 0x2060 && v <= 0x2069) || v == 0xFEFF
    }

    /// `s` with every escaped scalar replaced by `\n`, `\r`, `\t` or `\u{XX}` (uppercase hex, at least two
    /// digits); nothing else changes, a backslash included. Display only: never for bytes that are hashed or signed.
    public static func escape(_ s: String) -> String {
        guard s.unicodeScalars.contains(where: { isEscaped($0.value) }) else { return s }
        var out = String.UnicodeScalarView()
        for sc in s.unicodeScalars {
            guard isEscaped(sc.value) else { out.append(sc); continue }
            let e: String
            switch sc.value {
            case 0x0A: e = "\\n"
            case 0x0D: e = "\\r"
            case 0x09: e = "\\t"
            default:
                let hex = String(sc.value, radix: 16, uppercase: true)
                e = "\\u{" + (hex.count < 2 ? "0" + hex : hex) + "}"
            }
            out.append(contentsOf: e.unicodeScalars)
        }
        return String(out)
    }

    /// True when `escape(s) == s`.
    public static func isSafe(_ s: String) -> Bool { !s.unicodeScalars.contains(where: { isEscaped($0.value) }) }

    /// A value as a surface shows it outside the template line: `Templates.renderValue`, then `escape`.
    public static func value(_ v: JSONValue) -> String { escape(Templates.renderValue(v)) }
}
