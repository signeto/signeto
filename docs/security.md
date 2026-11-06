# Security model

What Signeto promises, per deployment mode, and the limits of those promises.

## Always true

- **The agent holds no credentials.** It can only call tools on the gateway. A prompt-injected agent has nothing to act with.
- **You sign what runs.** The gateway builds the canonical action (resolved IDs, the commit SHA a merge will use, the amount) and your device signs a hash of those bytes. At execution the gateway uses its frozen copy; the agent cannot resend anything.
- **Requests are signed by the gateway.** Your device verifies each approval request against the gateway key it pinned at pairing before showing it. Nothing the relay sends can put a fake request in front of you.
- **Single use, short lived.** Every action carries a nonce and expires within 5 minutes. A receipt cannot be replayed.
- **Fail closed.** Timeouts, bad signatures, expired requests, a freeze, a policy change mid-approval, or a ledger write failure all mean the action does not run.
- **Tamper-evident record.** Every request, decision, credential mint and execution is a hash-chained ledger entry with signed chain heads; any edit breaks verification. Receipts verify without Signeto ([receipts.md](receipts.md)).
- **The relay cannot approve.** It carries requests and receipts but holds no approver keys and no credentials.

## Self-hosted gateway

The gateway runs on your infrastructure and holds your credentials. Signeto's hosted relay and apps never see a credential and cannot cause an action to run. **Even a fully compromised Signeto cannot act on your systems.**

## Signeto Cloud

Signeto runs your gateway in an isolated tenant and acts through Signeto's own GitHub App, whose private key lives in a cloud KMS and is never exported. Every action still requires your device's signature over the exact bytes, and every credential is a GitHub installation token scoped to the repositories you chose, expiring within an hour and revoked after use. Signeto staff have no approval path. **The difference from self-hosted:** Signeto is the holder of the App key, so you are trusting Signeto's operation of it. Cloud never offers stored-key (custody) adapters such as brokerage or payment keys. You can move to a self-hosted gateway at any time without re-pairing devices.

## Not covered

- An approver who approves something they shouldn't. Signeto shows exactly what will run; it can't make anyone read it. Fatigue defences (duplicate suppression, escalation, cooling-off) reduce the risk.
- A compromised approver device with the user's biometric.
- Tools Signeto doesn't front. Approvals on those are labelled *advisory*.
- What the upstream allows. Signeto decides *when* a credential is used, not what the upstream permits it to do.

Report vulnerabilities to security@signeto.dev ([SECURITY.md](../SECURITY.md)).
