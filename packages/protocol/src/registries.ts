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
    t("alpaca.place_order", 1, "Place order: {side} {qty} {symbol} {type} on {account} (notional {notional_usd} USD)", ["limit_price", "time_in_force"]),
  ],
};

export const builtinRegistries: readonly TemplateRegistry[] = [githubRegistry, postgresRegistry, alpacaRegistry];
