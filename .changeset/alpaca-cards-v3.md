---
"@signeto/adapter-alpaca": minor
"@signeto/protocol": minor
---

Alpaca order cards say the order's terms in words ("buy 3 AAPL at market", "limit 150.00, good till canceled")
instead of "limit price null, time in force day", with the last trade on a second line: `alpaca.place_order` v3 and
`alpaca.cancel_order` v2 are in the builtin registries, and the adapter sends them. The order's type, limit price and
time in force stay signed; execute refuses an order whose signed terms don't match it. A buy limit order now reads
the latest trade too (shown, not used to value it).
