# Integration guide

How an agent talks to Signeto, what it gets back, and how to plug in new systems.

1. [How it works](#how-it-works)
2. [Connect an agent](#connect-an-agent)
3. [What the agent sees](#what-the-agent-sees)
4. [Choosing a deployment mode](#choosing-a-deployment-mode)
5. [Policies in one page](#policies-in-one-page)
6. [Write an adapter](#write-an-adapter)
7. [Verify receipts](#verify-receipts)

## How it works

```
agent ──MCP──▶ Signeto gateway ──signed request──▶ your phone / laptop
                     │                                   │ you read the exact action,
                     │                                   │ Face ID / Touch ID / passkey
                     │◀──────────── signed receipt ──────┘
                     │ verify signature against your enrolled key
                     │ mint a credential for this one action (e.g. a GitHub token for one repo)
                     ▼
                 upstream API  ──▶  result back to the agent, receipt into a hash-chained ledger
```

- The agent never sees a credential. It calls tools on the gateway; the gateway holds or mints credentials.
- What you sign is the gateway's canonical bytes for the action, not the agent's description of it. Your device renders those bytes with a pinned template and signs a hash of them.
- Anything that goes wrong (timeout, bad signature, expired request, freeze switch) means the action does not run.

## Connect an agent

Signeto is an MCP server. Any MCP client can use it.

**Claude Code** (`.mcp.json` in your project, or `claude mcp add`):

```json
{
  "mcpServers": {
    "signeto": { "command": "signeto", "args": ["serve"] }
  }
}
```

**Signeto Cloud** uses a remote MCP endpoint instead of a local command; the portal shows the exact URL and token for your workspace.

Remove direct credentials for anything Signeto fronts (a `GITHUB_TOKEN` in the agent's environment, a GitHub MCP server with write scopes). Signeto only helps if it is the agent's only path to that system. See [Enforce and advisory](#enforce-and-advisory).

More snippets: [`examples/`](../../examples).

## What the agent sees

**Tool names.** Each adapter tool appears as `<adapter>__<tool>`, e.g. `github__merge_pull_request`. Arguments are the adapter's input schema; unknown arguments are rejected. One extra tool, `signeto__check_approval`, polls an approval started in async mode.

**While waiting.** A tool call that needs approval blocks until it is approved, denied or times out. Clients that send an MCP `progressToken` receive progress notifications at least every 15 seconds:

```json
{ "status": "pending", "action_id": "act_01JC…", "expires_at": "2026-11-06T18:07:09.123Z", "seconds_remaining": 142 }
```

**Results.**

| Outcome | `isError` | Text the agent reads | `structuredContent` |
|---|---|---|---|
| Executed | false | The upstream result | `{ action_id, tier, evidence }` |
| Denied | true | `Denied by approver: <reason>` (the approver's words, if any) | `{ code: "denied", retryable: false, action_id }` |
| Expired | true | `expired: Approval expired` | `{ code: "expired", retryable: true, action_id }` |
| Still pending when the wait ended | true | `timeout: …` | `{ code: "timeout", retryable: true, action_id }` |
| Approvals frozen | true | `frozen: approvals are frozen` | `{ code: "frozen", retryable: true }` |
| Anything else that failed closed | true | `<code>: <message>` | `{ code, retryable, action_id? }` |
| Async mode | false | `{ "status": "pending", "action_id": …, "check": "signeto.check_approval" }` | same |

The result never says which policy rule matched, so an agent can't learn how to phrase a request to dodge it.

**Retries.** A retry of the same call while an approval is pending reattaches to it instead of asking again; a retry after it executed returns the stored result without running it twice. Retry after a denial or expiry starts a fresh approval.

## Choosing a deployment mode

| | Signeto Cloud | Self-hosted gateway |
|---|---|---|
| Setup | Sign up, install the Signeto GitHub App, add the MCP endpoint, pair your phone | Run the gateway on your machine or cluster, register your own GitHub App, pair your phone |
| Who holds credentials | Signeto holds its GitHub App key (in a KMS) and mints per-action tokens | You. Signeto never sees a credential |
| Systems | Mint-mode adapters only (scoped, short-lived tokens) | All, including stored-key ("custody") adapters |
| Best for | Trying Signeto, small teams, GitHub-centric agents | Production systems, regulated data, money movement |

Details and the exact guarantees per mode: [security.md](../security.md).

## Policies in one page

A policy file decides which tool calls need approval and from whom. First matching rule wins; unmatched tools fall to the default tier.

```yaml
version: 1
approvers:
  jason:
    devices: [iphone, macbook]
defaults:
  tier: 2            # unknown tools need any approver
  expiry: 3m         # approval window, 5m maximum
  timeout: 3m        # how long the agent's call waits
rules:
  - tool: github.merge_pull_request
    when: { base: main }
    tier: 3          # named approver only
    approver: jason
  - tool: github.read_pull_request
    tier: 1          # runs without approval, still ledgered
```

Tier 1 runs and is recorded. Tier 2 needs any enrolled approver. Tier 3 needs a named approver. Predicates (`when`) test the *resolved* arguments the adapter produced, so `base: main` is checked against what GitHub says the PR targets, not what the agent claimed.

### Enforce and advisory

Signeto *enforces* only where it stands between the agent and the credential. If you also attach Signeto to tools it doesn't front (for example a Claude Code `PreToolUse` hook on shell commands), that is *advisory*: a shell can go around it. Signeto labels advisory approvals as such everywhere they appear.

## Write an adapter

An adapter brings one upstream system under Signeto. It declares its tools, turns the agent's arguments into exact resolved arguments, obtains a credential for one approved action, and executes it. The gateway does everything else: policy, approval, ledger, retries.

```ts
import { AdapterError, type Adapter } from "@signeto/adapter-sdk";

export const tickets: Adapter = {
  manifest: {
    name: "tickets", version: "0.1.0", mode: "mint", egress: ["api.tickets.example"],
    secrets: [{ name: "client_secret", description: "OAuth client secret" }],
    tools: [{
      name: "close_ticket", description: "Close a ticket", effect: "write", classification: "internal",
      input:    { type: "object", additionalProperties: false, required: ["id"], properties: { id: { type: "string" } } },
      resolved: { type: "object", additionalProperties: false, required: ["id", "title"],
                  properties: { id: { type: "string" }, title: { type: "string" } } },
      template: { id: "tickets.close_ticket", version: 1, text: "Close ticket {id}: {title}" },
    }],
  },
  async resolve(ctx, tool, args) {
    // Read-only lookups only. Same input + same upstream state => byte-identical output.
    const t = await lookup(ctx.upstream, (args as { id: string }).id);
    if (!t) throw new AdapterError("resolve_failed", "no such ticket");
    return { args: { id: t.id, title: t.title } };
  },
  async mint(ctx, action) {
    // A credential for exactly this action, expiring within the hour.
    return exchangeForScopedToken(ctx, action.args.id as string);
  },
  async execute(ctx, action, cred) {
    // Use the frozen action only; never re-derive arguments.
    const res = await ctx.fetch(`https://api.tickets.example/tickets/${action.args.id}/close`, { method: "POST", headers: { authorization: `Bearer ${cred.material}` } });
    if (!res.ok) throw new AdapterError("upstream_rejected", `HTTP ${res.status}`);
    return { content: "closed", evidence: { id: action.args.id } };
  },
};
```

Rules the SDK's `validateAdapter` enforces: input schemas are closed (`additionalProperties: false`); read tools are named `read_*`, `list_*` or `get_*`; the template id equals `<adapter>.<tool>`; every placeholder is a required resolved property; every resolved property is either shown by the template or listed in `template.elide`. That last rule stops an adapter hiding an argument from the person approving it.

`mint` adapters get a fresh, scoped credential from the upstream per action (GitHub installation tokens, Vault dynamic credentials, AWS STS). `custody` adapters unlock a stored long-lived key for one request (Alpaca, Stripe); they run only on self-hosted gateways and must be acknowledged in policy. [`adapters/github`](../../adapters/github) is a complete mint adapter with tests.

## Verify receipts

Every approval and denial is a signed receipt you can check without Signeto: see [receipts.md](../receipts.md).
