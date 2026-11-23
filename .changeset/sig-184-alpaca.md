---
"@signeto/adapter-alpaca": minor
"@signeto/protocol": minor
---

SIG-184: new `@signeto/adapter-alpaca`, a custody adapter for Alpaca paper trading (place and cancel orders, read positions and orders; one write request per approval, the action id as `client_order_id`, market orders re-priced and refused past 5% drift). `@signeto/protocol` bundles the `alpaca.cancel_order`, `alpaca.read_positions` and `alpaca.read_orders` v1 templates.
