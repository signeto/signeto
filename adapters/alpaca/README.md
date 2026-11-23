# @signeto/adapter-alpaca

Signeto adapter for [Alpaca](https://alpaca.markets) **paper trading**. Your agent can read positions and orders and
place or cancel orders, and each order your policy gates waits for you to sign the exact order on your phone.

Paper only: the adapter's code talks to `paper-api.alpaca.markets` and `data.alpaca.markets` and has no other host.
A live key doesn't work against the paper host, and placing an order also checks that the account is a paper account
(`PA…`).

## Custody mode, plainly

Alpaca keys are all or nothing: there is no short-lived or read-only key to mint. So this is a **custody** adapter
(see [docs/security.md](../../docs/security.md)). The key pair lives in your gateway's credential store, never in the
agent, and the gateway narrows its use by the adapter's discipline, not by an upstream scope:

- Before approval, `resolve` reads, with GET only and to a fixed list of paths: the account, the market clock (for a
  market order or a sell), the asset, your position in it (for a sell) and the latest trade (shown on every card; it
  values a market order or a sell). These requests carry the key, as every Alpaca request
  must, but **no write is sent**.
- After approval, `custody` hands the key to `execute` for that one action, labelled `custody: …` in the ledger.
- `execute` sends **at most one write request**: the order, or the cancel. The order carries the action id as Alpaca's
  `client_order_id`, so Alpaca refuses a second order for the same approval.
- If the order's answer is lost (no answer, a server error, an unreadable answer), the adapter looks the order up by
  that id and never sends it again. If the lookup can't confirm it either way, the result says **the outcome is
  unknown**, is not marked retryable, and tells the agent to read the orders before trying again.
- An order valued from the market (a market order, or any sell) is re-priced just before it is sent and refused if
  its value moved more than 5% from what you signed.
- The gateway calls `revoke` when execute is done, and the adapter drops its reference to the key.

Because the gateway holds a long-lived key, the policy must say so (see Policy). Signeto Cloud never runs custody
adapters: Alpaca is for self-hosted gateways only.

## Tools

| Tool | Effect | What the approver signs |
| --- | --- | --- |
| `alpaca.place_order` | write | `Place order on paper: buy 10 AAPL at market (value 3489.1 USD)`, with a second line `Last trade 348.91 USD at 2026-11-23 20:06 UTC.` |
| `alpaca.cancel_order` | write | `Cancel order on paper: buy 5 AAPL limit 150.00, good till canceled`, with the order id on the second line |
| `alpaca.read_positions` | read | `Read positions on paper` |
| `alpaca.read_orders` | read | `Read open orders on paper (at most 50)` |

The card states the order's terms in words: `at market`, `limit 150.00, today only` (a day order),
`… , good till canceled` (gtc). The order's `type`, `limit_price` and `time_in_force` are signed too, so policy can test
them, and the app lists them under the card's hidden fields. Before sending, the adapter checks that the signed terms
say exactly what the order says, and refuses (nothing sent) if they don't.

These cards are template v3 (place) and v2 (cancel), in the apps from iOS 1.1.1 (16) and Android 1.1.1 (8). An older
app shows them as "unverified template": the exact signed values, still approvable.

Orders are whole-share US equity orders, `market` or `limit`, `day` or `gtc`.

**`notional_usd`**, the order's value, is quantity × the price it can trade at, in exact cents. It is a number in the
signed args so policy can set thresholds on it:

| Order | Valued at |
| --- | --- |
| buy limit | the limit price (it can't fill above it) |
| market | the latest trade |
| sell limit | the higher of the limit price and the latest trade (a sell limit below the market fills at the market) |

What the adapter refuses, before anything is approved:

- **Sells that don't reduce a long position you hold.** Shorting is refused, so "sell" on the card always means
  selling shares you own (up to the quantity available to sell).
- **Market orders and sells while the market is closed**, or valued from a trade older than 15 minutes. An order
  queued for the open would fill at whatever the open is, and a stale trade (a thin symbol on the IEX feed) could
  value it far below what it fills at. A buy limit order is taken any time, since it can't fill above its limit.
- **Orders worth less than $1.**
- **Cancelling an order that wasn't placed through Signeto** (a person's own order). The adapter has an option,
  `cancelAnyOrder`, to allow it; the `signeto` CLI doesn't expose it.

Just before the order is sent, with the key, the adapter checks again: the market is still open and the trade recent
(market orders and sells), the shares are still there (sells, so two approved sells can't open a short), the value
hasn't moved more than 5%, and there is enough time left before the approval expires to send the order and look it up
(at least 10 seconds; an approval that arrives later is refused and nothing is sent).

Reads always fetch fresh data: the gateway never answers a read from its cache of earlier calls.

## Setup

Run these on the computer that runs the gateway. The value is prompted for and not echoed:

```sh
signeto secrets set alpaca key_id       # your paper trading Key (starts with PK)
signeto secrets set alpaca secret_key   # its Secret, shown once by Alpaca when the key is made
signeto stop                            # a running gateway picks the key up on its next start
signeto connect claude-code --adapters github,alpaca
```

With a system-mode gateway, run `sudo signeto secrets set …` instead; the gateway re-reads its store on its own.
Avoid `--value KEY`: it puts the key in your shell history. A value with a line break or another control character
is refused.

## Policy

Tiers by order value, first matching rule wins:

```yaml
rules:
  - tool: alpaca.place_order
    when: { notional_usd: { gt: 5000 } }
    tier: 3                 # large orders: alice signs on a hardware-backed device
    approver: alice
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

`signeto policy lint --adapters github,alpaca` warns that a tier 1 rule auto-approves a write; that is the point of a
small-order threshold, and the warning stays so you see it. `signeto policy dry-run alpaca.place_order --args '…'
--adapters github,alpaca` prices the order with your key (reads only) and shows the tier it would get.

Rules can also test `side`, `symbol`, `type` and `qty`, for example to require approval for every sell.

### What thresholds don't do

Know these before relying on tier 1 for writes:

- **No totals.** Each order is tested on its own. An agent can place many orders just under a threshold, each at
  tier 1. Signeto has no daily or per-session limit yet. If that matters, don't give writes a tier 1 rule.
- **The 5% drift allowance.** An order signed just under a threshold can execute up to 5% above it.
- **An unknown outcome.** When an order's answer is lost and it can't be looked up, the agent is told the outcome is
  unknown and not to retry before reading the orders. That is advice to the agent: a retry is a new action, and at
  tier 1 nothing stops it.
- **Tier 1 cancels.** With the rule above, the agent can cancel any open order it placed through Signeto without
  asking.

## License

Apache-2.0
