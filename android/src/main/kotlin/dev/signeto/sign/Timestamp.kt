// docs/protocol.md §2.5: RFC 3339 UTC with exactly three fractional digits and `Z`.
// Mirrors src/timestamps.ts: regex shape plus a round-trip check (no normalised dates such as
// 2026-02-30, no 24:00, no leap second 60). Epoch milliseconds in the proleptic Gregorian calendar.
// No java.time (Android API 26+ only without desugaring). Port of SignetoSign Timestamp.swift.
package dev.signeto.sign

object Timestamp {
    /** Clock-skew tolerance for receipts, relay request `ts`, and device-side checks. */
    const val CLOCK_SKEW_MS: Long = 60_000
    /** Default `expires_at - issued_at`. */
    const val DEFAULT_EXPIRY_MS: Long = 180_000
    /** Hard maximum `expires_at - issued_at`. */
    const val MAX_EXPIRY_MS: Long = 300_000

    /** Epoch milliseconds, or null when `s` is not exactly `YYYY-MM-DDTHH:mm:ss.sssZ` for a real instant. */
    fun parse(s: String): Long? {
        if (s.length != 24 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != '.' || s[23] != 'Z') return null
        fun num(from: Int, to: Int): Int? {
            var v = 0
            for (i in from until to) {
                val c = s[i]
                if (c !in '0'..'9') return null
                v = v * 10 + (c - '0')
            }
            return v
        }
        val y = num(0, 4) ?: return null
        val mo = num(5, 7) ?: return null
        val d = num(8, 10) ?: return null
        val h = num(11, 13) ?: return null
        val mi = num(14, 16) ?: return null
        val se = num(17, 19) ?: return null
        val ms = num(20, 23) ?: return null
        if (mo !in 1..12 || d < 1 || d > daysInMonth(y, mo) || h > 23 || mi > 59 || se > 59) return null
        val days = daysFromCivil(y, mo, d)
        return days * 86_400_000L + h * 3_600_000L + mi * 60_000L + se * 1000L + ms
    }

    /** `Date.prototype.toISOString` for years 0000–9999. */
    fun format(ms: Long): String {
        var days = ms / 86_400_000
        var rem = ms % 86_400_000
        if (rem < 0) { rem += 86_400_000; days -= 1 }
        val (y, mo, d) = civilFromDays(days)
        val h = rem / 3_600_000
        val mi = rem / 60_000 % 60
        val se = rem / 1000 % 60
        val msec = rem % 1000
        fun p(v: Long, w: Int): String = v.toString().padStart(w, '0')
        return "${p(y, 4)}-${p(mo, 2)}-${p(d, 2)}T${p(h, 2)}:${p(mi, 2)}:${p(se, 2)}.${p(msec, 3)}Z"
    }

    /** `Date.now()` formatted. */
    fun now(): String = format(System.currentTimeMillis())

    internal fun isLeap(y: Int): Boolean = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    internal fun daysInMonth(y: Int, m: Int): Int = when (m) {
        2 -> if (isLeap(y)) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }

    // Howard Hinnant's days_from_civil / civil_from_days.
    internal fun daysFromCivil(y0: Int, m: Int, d: Int): Long {
        val y = (if (m <= 2) y0 - 1 else y0).toLong()
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val doy = (153L * (m + (if (m > 2) -3 else 9)) + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    internal fun civilFromDays(z0: Long): Triple<Long, Long, Long> {
        val z = z0 + 719_468
        val era = (if (z >= 0) z else z - 146_096) / 146_097
        val doe = z - era * 146_097
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        val y = yoe + era * 400
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val d = doy - (153 * mp + 2) / 5 + 1
        val m = mp + (if (mp < 10) 3 else -9)
        return Triple(if (m <= 2) y + 1 else y, m, d)
    }
}
