# @signeto/adapter-alpaca

Signeto adapter for [Alpaca](https://alpaca.markets) **paper trading**. Your agent can read positions and orders and
place or cancel orders, and each order your policy gates waits for you to sign the exact order on your phone.

Paper only: the adapter talks to `paper-api.alpaca.markets` and `data.alpaca.markets` and nothing else, and it refuses
a key whose account is not a paper account (`PA…`).

## Custody mode, honestly

Alpaca keys are all or nothing: there is no short-lived or read-only key to mint. So this is a **custody** adapter
(docs/adapters.md §3.3). The key pair lives in your gateway's credential store, never in the agent, and the gateway
narrows it by discipline, not by upstream scope:

- `resolve` reads (GET only, to an allowlist of paths) the account, the asset and a price. Nothing is sent.
- After approval, `custody` hands the key to `execute` for that one action, labelled `custody: …` in the ledger.
- `execute` sends **exactly one write request**: the order, or the cancel. The order carries the action id as
  Alpaca's `client_order_id`, so Alpaca itself refuses a second order for the same approval. If the answer is lost,
  the adapter looks the order up by that id instead of sending it again.
- A market order is re-priced just before it is sent and refused if its value moved more than 5% from what you
  signed.
- The gateway calls `revoke` when execute is done, and the key is dropped from the credential.

Because the gateway holds a long-lived key, the policy must say so (see Policy). Signeto Cloud never runs custody
adapters: Alpaca is for self-hosted gateways only.

## Tools

| Tool | Effect | What the approver signs |
| --- | --- | --- |
| `alpaca.place_order` | write | `Place order: buy 10 AAPL market, limit price null, time in force day, on paper (notional 1895 USD)` |
| `alpaca.cancel_order` | write | `Cancel order 6b2c…: buy 5 AAPL limit on paper` |
| `alpaca.read_positions` | read | `Read positions on paper` |
| `alpaca.read_orders` | read | `Read open orders on paper (at most 50)` |

Orders are whole-share US equity orders, `market` or `limit`, `day` or `gtc`. `notional_usd` is quantity × the limit
price, or × the latest trade for a market order, in exact cents. It is a number in the signed args so policy can set
thresholds on it.

## Setup

```sh
signeto secrets set alpaca key_id       # your paper trading key id
signeto secrets set alpaca secret_key   # its secret (prompted, never echoed)
signeto connect claude-code --adapters github,alpaca
```

## Policy

Tiers by order value, first matching rule wins:

```yaml
rules:
  - tool: alpaca.place_order
    when: { notional_usd: { gt: 5000 } }
    tier: 3                 # large orders: jason signs on a hardware-backed device
    approver: jason
  - tool: alpaca.place_order
    when: { notional_usd: { gt: 500 } }
    tier: 2                 # mid-size: any approver signs
  - tool: alpaca.place_order
    tier: 1                 # small orders run without asking, and are logged
  - tool: alpaca.cancel_order
    tier: 1
  - tool: alpaca.read_*
    tier: 1

credentials:
  alpaca:
    mode: custody
    acknowledge: "the gateway holds a long-lived credential for this adapter"
```

`signeto policy lint --adapters github,alpaca` warns that the tier 1 rule auto-approves a write; that is the point
of a small-order threshold, and the warning stays so you see it.

## License

Apache-2.0
