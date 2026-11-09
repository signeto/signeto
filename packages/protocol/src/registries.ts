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
  ],
};

export const builtinRegistries: readonly TemplateRegistry[] = [githubRegistry, postgresRegistry, alpacaRegistry, signetoRegistry];
