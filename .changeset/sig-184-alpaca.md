---
"@signeto/adapter-alpaca": minor
"@signeto/protocol": minor
---

New `@signeto/adapter-alpaca`, a custody adapter for Alpaca paper trading: place and cancel orders, read positions and orders. At most one write request per approval, with the action id as `client_order_id`; a lost order answer is looked up, never resent, and reported as an unknown outcome when it can't be confirmed. Orders are valued at the price they can trade at (a sell limit at the higher of its limit and the latest trade), sells must reduce a long position (no shorting), market orders need an open market and a recent trade, and orders valued from the market are refused past 5% drift. `@signeto/protocol` bundles the `alpaca.cancel_order`, `alpaca.read_positions` and `alpaca.read_orders` v1 templates.
