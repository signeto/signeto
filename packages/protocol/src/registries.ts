// Bundled registries of the reference adapters (§3.1). Templates are immutable; any change to a hashed
// member (text, elide, note, links, link_hosts) → bump the version and keep the old one for older gateways.
import { templateSha256, type Template, type TemplateBody, type TemplateRegistry } from "./template.js";

function t(template_id: string, template_version: number, text: string, elide?: string[], extra: Omit<TemplateBody, "text" | "elide"> = {}): Template {
  const body: TemplateBody = { text, ...(elide ? { elide } : {}), ...extra };
  return { template_id, template_version, text, sha256: templateSha256(body), ...(elide ? { elide } : {}), ...extra };
}

/** Hosts the bundled github templates may link to (§3.5). */
export const GITHUB_LINK_HOSTS = ["github.com"];

export const githubRegistry: TemplateRegistry = {
  adapter: "github",
  templates: [
    t("github.merge_pull_request", 1, "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}"),
    t("github.merge_pull_request", 2, "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}", undefined, {
      note: "Approving commit {head_sha:short}. If the PR changes, this approval will not merge it.",
      links: [
        { label: "View pull request", url: "https://github.com/{repo:path}/pull/{pr}" },
        { label: "Files changed", url: "https://github.com/{repo:path}/pull/{pr}/files" },
        { label: "Code at approved commit", url: "https://github.com/{repo:path}/tree/{head_sha}" },
      ],
      link_hosts: GITHUB_LINK_HOSTS,
    }),
    // Bundled from v3 (SIG-92 N9: the inputs are in the sentence; v2 elided them and was only ever pinned at pairing),
    // so devices built against this package render it without a pin. Byte-identical to the github adapter's manifest.
    t("github.dispatch_workflow", 3, "Run {workflow} on {ref} ({ref_sha}) in {repo} with inputs {inputs}", undefined, {
      links: [
        { label: "Workflow file at approved commit", url: "https://github.com/{repo:path}/blob/{ref_sha}/.github/workflows/{workflow}" },
        { label: "Actions", url: "https://github.com/{repo:path}/actions" },
      ],
      link_hosts: GITHUB_LINK_HOSTS,
    }),
    // v4 (SIG-185): the same request when it has no inputs, without "with inputs {}". Nothing is elided: `inputs` is not
    // in the resolved args at all, so a v4 request that does carry inputs fails the unreferenced-key rule (§3.4) and the
    // card shows "unverified template" instead of hiding them. Bundled in the apps first; the adapter sends it later,
    // once approvers that know it are out.
    t("github.dispatch_workflow", 4, "Run {workflow} on {ref} ({ref_sha}) in {repo}", undefined, {
      links: [
        { label: "Workflow file at approved commit", url: "https://github.com/{repo:path}/blob/{ref_sha}/.github/workflows/{workflow}" },
        { label: "Actions", url: "https://github.com/{repo:path}/actions" },
      ],
      link_hosts: GITHUB_LINK_HOSTS,
    }),
    t("github.create_deployment", 1, "Deploy {ref} to {environment} on {repo}", ["description"]),
  ],
};

export const postgresRegistry: TemplateRegistry = {
  adapter: "postgres",
  templates: [t("postgres.execute", 1, "{statement_kind} on {database}@{host}: {statement}")],
};

export const alpacaRegistry: TemplateRegistry = {
  adapter: "alpaca",
  templates: [
    // v1 hid limit_price and time_in_force (SIG-92 N9). Kept for gateways that still send it.
    t("alpaca.place_order", 1, "Place order: {side} {qty} {symbol} {type} on {account} (notional {notional_usd} USD)", ["limit_price", "time_in_force"]),
    // v2: every argument in the sentence. The adapter always resolves limit_price (null for a market order).
    t("alpaca.place_order", 2, "Place order: {side} {qty} {symbol} {type}, limit price {limit_price}, time in force {time_in_force}, on {account} (notional {notional_usd} USD)"),
    // v3: the order's terms in words ("at market", "limit 349.50, today only") instead of "limit price null", and the
    // last trade on the note line. Bundled in the apps from iOS 1.1.1 (16) and Android 1.1.1 (8); the adapter sends it
    // once those builds are out. Byte-identical to the alpaca adapter's manifest.
    t("alpaca.place_order", 3, "Place order on {account}: {side} {qty} {symbol} {terms} (value {notional_usd} USD)", ["type", "limit_price", "time_in_force", "last_price", "last_trade_at"], {
      note: "Last trade {last_price} USD at {last_trade_at}.",
    }),
    // Cancelling an open order, described by what it cancels. v1 is in the app builds from 2026-11-23 on.
    t("alpaca.cancel_order", 1, "Cancel order {order_id}: {side} {qty} {symbol} {type} on {account}"),
    // v2: the cancelled order's terms in words, as on the order card; the order id on the note line. Bundled with
    // place_order v3.
    t("alpaca.cancel_order", 2, "Cancel order on {account}: {side} {qty} {symbol} {terms}", ["order_id", "type", "limit_price", "time_in_force"], {
      note: "Order {order_id}.",
    }),
    // Reads, for a policy that asks before an agent sees the account. Bundled with cancel_order.
    t("alpaca.read_positions", 1, "Read positions on {account}"),
    t("alpaca.read_orders", 1, "Read {status} orders on {account} (at most {limit})"),
  ],
};

/**
 * `signeto test` (CLI): a harmless request that exercises push, the card, the device signature and receipt
 * verification end to end. Nothing executes upstream. `code` is shown in the terminal too, so the approver can
 * check that the card on the phone is the request they just started.
 */
export const signetoRegistry: TemplateRegistry = {
  adapter: "signeto",
  templates: [
    t("signeto.test", 1, "Test request from {gateway}, code {code}", undefined, {
      note: "Nothing runs when you approve this. It checks that this phone receives, shows and signs requests.",
    }),
    // Gateway succession (protocol.md §5.6, SIG-160): bundled, not pinned, because the device that approves it pins the
    // successor with it. The successor's key is elided: its thumbprint is the gateway id in the sentence, and a device
    // checks that binding before it pins anything (`verifyHandoffForDevice`).
    t("signeto.gateway_handoff", 1, "Move this gateway to {successor_name} ({successor_gateway_id})", ["ledger_head", "ledger_seq", "policy_hash", "successor_public_key"], {
      note: "Its ledger continues from entry {ledger_seq} ({ledger_head:short}) under policy {policy_hash:short}. This phone keeps approving for the new gateway, and this one stops once the move completes. Approve only if you started this move.",
    }),
    // A new MCP token for a hosted gateway (protocol.md §3.1, SIG-163): bundled, because the phone's approval is the
    // only thing that lets a new agent reach the gateway. Both arguments are in the sentence and nothing is elided, so
    // a request that carries anything else (the token's hash, say) renders unverified. `key_id` is the first 12
    // characters of the token's secret, which the page that made the token shows next to it.
    t("signeto.agent_token_add", 1, "Let a new agent connect to this gateway: {name} (key {key_id})"),
  ],
};

export const builtinRegistries: readonly TemplateRegistry[] = [githubRegistry, postgresRegistry, alpacaRegistry, signetoRegistry];
