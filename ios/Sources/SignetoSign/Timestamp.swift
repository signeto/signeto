// docs/protocol.md §2.5: RFC 3339 UTC with exactly three fractional digits and `Z`.
// Mirrors src/timestamps.ts: regex shape plus a round-trip check (no normalised dates such as
// 2026-02-30, no 24:00, no leap second 60). Epoch milliseconds in the proleptic Gregorian calendar.
import Foundation

public enum Timestamp {
    /// Clock-skew tolerance for receipts, relay request `ts`, and device-side checks.
    public static let clockSkewMs: Int64 = 60_000
    /// Default `expires_at - issued_at`.
    public static let defaultExpiryMs: Int64 = 180_000
    /// Hard maximum `expires_at - issued_at`.
    public static let maxExpiryMs: Int64 = 300_000

    /// Epoch milliseconds, or nil when `s` is not exactly `YYYY-MM-DDTHH:mm:ss.sssZ` for a real instant.
    public static func parse(_ s: String) -> Int64? {
        let u = Array(s.utf8)
        guard u.count == 24, u[4] == 0x2D, u[7] == 0x2D, u[10] == 0x54, u[13] == 0x3A, u[16] == 0x3A, u[19] == 0x2E, u[23] == 0x5A else { return nil }
        func num(_ r: Range<Int>) -> Int? {
            var v = 0
            for i in r {
                guard Chars.isDigit(u[i]) else { return nil }
                v = v * 10 + Int(u[i] - 0x30)
            }
            return v
        }
        guard let y = num(0..<4), let mo = num(5..<7), let d = num(8..<10), let h = num(11..<13), let mi = num(14..<16), let se = num(17..<19), let ms = num(20..<23) else { return nil }
        guard (1...12).contains(mo), d >= 1, d <= daysInMonth(y, mo), h <= 23, mi <= 59, se <= 59 else { return nil }
        let days = daysFromCivil(y, mo, d)
        return Int64(days) * 86_400_000 + Int64(h) * 3_600_000 + Int64(mi) * 60_000 + Int64(se) * 1000 + Int64(ms)
    }

    /// `Date.prototype.toISOString` for years 0000–9999.
    public static func format(ms: Int64) -> String {
        var days = ms / 86_400_000
        var rem = ms % 86_400_000
        if rem < 0 { rem += 86_400_000; days -= 1 }
        let (y, mo, d) = civilFromDays(Int(days))
        let h = Int(rem / 3_600_000), mi = Int(rem / 60_000 % 60), se = Int(rem / 1000 % 60), msec = Int(rem % 1000)
        func p(_ v: Int, _ w: Int) -> String {
            let s = String(v)
            return String(repeating: "0", count: max(0, w - s.count)) + s
        }
        return "\(p(y, 4))-\(p(mo, 2))-\(p(d, 2))T\(p(h, 2)):\(p(mi, 2)):\(p(se, 2)).\(p(msec, 3))Z"
    }

    public static func format(_ date: Date) -> String { format(ms: milliseconds(date)) }

    /// Milliseconds since the epoch, truncated like `Date.now()`.
    public static func milliseconds(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded(.down)) }

    public static func date(_ s: String) -> Date? { parse(s).map { Date(timeIntervalSince1970: Double($0) / 1000) } }

    static func isLeap(_ y: Int) -> Bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }
    static func daysInMonth(_ y: Int, _ m: Int) -> Int {
        switch m {
        case 2: return isLeap(y) ? 29 : 28
        case 4, 6, 9, 11: return 30
        default: return 31
        }
    }

    // Howard Hinnant's days_from_civil / civil_from_days.
    static func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int {
        let y = m <= 2 ? y0 - 1 : y0
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    static func civilFromDays(_ z0: Int) -> (Int, Int, Int) {
        let z = z0 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp + (mp < 10 ? 3 : -9)
        return (m <= 2 ? y + 1 : y, m, d)
    }
}
