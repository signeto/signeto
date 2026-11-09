// Shortest round-trip decimal digits of a double, as ECMA-262 Number::toString defines them (§6.1.6.1.20 step 5):
// the fewest digits k such that s × 10^(n−k) rounds to x, and among those the s closest to x, an even s on a tie.
//
// `Double.toString()` is not that on Android (ART's formatting is not shortest round-trip), so this computes it
// exactly with BigDecimal instead of vendoring a Ryu/Schubfach port: the set of decimals that read back as x is the
// interval between the midpoints to its neighbours (endpoints included when x's significand is even, since
// parsing rounds half to even), and for each k the k-digit numbers nearest x from below and above are the only
// candidates. Slower than Ryu, exact by construction, and far below what a phone needs for JSON-sized payloads.
// Fixtures/numbers.json (~3,500 doubles formatted by JavaScript) and vectors/canonical/ gate it.
package dev.signeto.sign

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode

internal object Shortest {
    private val TWO = BigDecimal(2)

    /** For finite x > 0: the digit string s (no leading or trailing zeros) and n with x ≈ 0.s × 10^n. */
    fun digits(x: Double): Pair<String, Int> {
        require(x > 0 && x.isFinite())
        // Fast path: integers up to 2^53 are exact and their decimal digits are the shortest.
        if (x < 9.007199254740992E15 && x == Math.floor(x)) {
            val t = x.toLong().toString()
            val trimmed = t.trimEnd('0')
            return trimmed to t.length
        }
        val v = BigDecimal(x)
        val lower = BigDecimal(Math.nextDown(x))
        val upper = if (x == Double.MAX_VALUE) v.add(v.subtract(lower)) else BigDecimal(Math.nextUp(x))
        val lo = v.add(lower).divide(TWO)
        val hi = v.add(upper).divide(TWO)
        val inclusive = (java.lang.Double.doubleToRawLongBits(x) and 1L) == 0L

        fun inside(d: BigDecimal): Boolean {
            val a = d.compareTo(lo)
            val b = d.compareTo(hi)
            return if (inclusive) a >= 0 && b <= 0 else a > 0 && b < 0
        }

        for (k in 1..17) {
            val down = v.round(MathContext(k, RoundingMode.FLOOR))
            val up = v.round(MathContext(k, RoundingMode.CEILING))
            val dIn = inside(down)
            val uIn = inside(up)
            if (!dIn && !uIn) continue
            val pick = when {
                dIn && !uIn -> down
                uIn && !dIn -> up
                else -> {
                    val c = v.subtract(down).compareTo(up.subtract(v))
                    when {
                        c < 0 -> down
                        c > 0 -> up
                        else -> if (down.unscaledValue().testBit(0)) up else down
                    }
                }
            }
            val p = pick.stripTrailingZeros()
            val s = p.unscaledValue().toString()
            // p = s × 10^(−scale) = 0.s × 10^(len(s) − scale)
            return s to (s.length - p.scale())
        }
        error("no shortest representation for $x") // unreachable: 17 digits always round-trip
    }
}
