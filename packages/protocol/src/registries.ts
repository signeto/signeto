// Bundled registries of the reference adapters (§3.1). Templates are immutable; change text → bump version.
import { templateSha256, type TemplateRegistry } from "./template.js";

function t(template_id: string, template_version: number, text: string, elide?: string[]) {
  return { template_id, template_version, text, sha256: templateSha256(text), ...(elide ? { elide } : {}) };
}

export const githubRegistry: TemplateRegistry = {
  adapter: "github",
  templates: [
    t("github.merge_pull_request", 1, "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}"),
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
