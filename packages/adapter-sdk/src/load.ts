// Manifest validation at startup (docs/adapters.md §2, §3). The gateway refuses to start on any failure.
import { templateLinksError, templateSha256, tokenizeTemplate, type TemplateBody, type TemplateRegistry } from "@signeto/protocol";
import type { Adapter, AdapterManifest, ToolSpec } from "./types.js";

export interface AdapterLoadError {
  adapter: string;
  tool?: string;
  message: string;
}

const NAME_RE = /^[a-z0-9-]+$/;
const TOOL_RE = /^[a-z0-9_]+$/;
const READ_PREFIX = /^(read_|list_|get_)/;

export function validateAdapter(adapter: Adapter): AdapterLoadError[] {
  const m = adapter.manifest;
  const errs: AdapterLoadError[] = [];
  const err = (message: string, tool?: string) => errs.push(tool ? { adapter: m.name, tool, message } : { adapter: m.name, message });
  if (!NAME_RE.test(m.name)) err(`adapter name must match ${NAME_RE}`);
  if (m.mode === "mint" && (typeof adapter.mint !== "function" || typeof adapter.custody === "function")) err("mint adapter must implement mint and not custody");
  if (m.mode === "custody" && (typeof adapter.custody !== "function" || typeof adapter.mint === "function")) err("custody adapter must implement custody and not mint");
  if (!Array.isArray(m.egress)) err("egress must be an array of hostnames");
  const seen = new Set<string>();
  for (const t of m.tools) {
    if (!TOOL_RE.test(t.name)) err(`tool name must match ${TOOL_RE}`, t.name);
    if (seen.has(t.name)) err("duplicate tool name", t.name);
    seen.add(t.name);
    if (t.effect === "read" && !READ_PREFIX.test(t.name)) err("read tools must start with read_, list_ or get_", t.name);
    if (t.effect === "write" && READ_PREFIX.test(t.name)) err("write tools must not use a read_/list_/get_ prefix", t.name);
    if ((t.input as { additionalProperties?: unknown }).additionalProperties !== false) err("input schema must set additionalProperties: false", t.name);
    const fq = `${m.name}.${t.name}`;
    if (t.template.id !== fq) err(`template id must equal the fully qualified tool name ${fq}`, t.name);
    if (!Number.isInteger(t.template.version) || t.template.version < 1) err("template version must be a positive integer", t.name);
    errs.push(...checkPlaceholders(m.name, t));
  }
  return errs;
}

function checkPlaceholders(adapterName: string, t: ToolSpec): AdapterLoadError[] {
  const out: AdapterLoadError[] = [];
  const err = (message: string) => out.push({ adapter: adapterName, tool: t.name, message });
  const toks = tokenizeTemplate(t.template.text);
  if (!toks) return [{ adapter: adapterName, tool: t.name, message: "template text has a stray brace or invalid placeholder" }];
  const props = ((t.resolved as { properties?: Record<string, unknown> }).properties ?? {}) as Record<string, unknown>;
  const required = new Set(((t.resolved as { required?: string[] }).required ?? []) as string[]);
  const referenced = new Set<string>();
  // `where` names the part of the template; note and link placeholders must resolve too, but only `text`
  // placeholders count as mentioning an argument (protocol.md §3.4).
  const check = (tokens: NonNullable<ReturnType<typeof tokenizeTemplate>>, where: string, mention: boolean) => {
    for (const tok of tokens) {
      if (tok.kind !== "ph") continue;
      const root = tok.path[0] as string;
      if (mention) referenced.add(root);
      if (!(root in props)) err(`${where} placeholder {${tok.path.join(".")}} is not a resolved property`);
      else if (!required.has(root)) err(`${where} placeholder {${root}} must be a required resolved property`);
    }
  };
  check(toks, "template", true);
  if (t.template.note !== undefined) {
    const nt = tokenizeTemplate(t.template.note, ["short"]);
    if (!nt) err("template note has a stray brace, an invalid placeholder or a formatter other than :short");
    else check(nt, "template note", false);
  }
  const linksError = templateLinksError(bodyOf(t));
  if (linksError) err(`template links are invalid (protocol.md §3.5): ${linksError}`);
  else for (const l of t.template.links ?? []) check(tokenizeTemplate(l.url, ["path"]) ?? [], `template link "${l.label}"`, false);
  const elide = new Set(t.template.elide ?? []);
  for (const k of Object.keys(props)) {
    if (!referenced.has(k) && !elide.has(k)) err(`resolved property "${k}" is neither referenced by the template nor listed in elide`);
  }
  return out;
}

/** The hashed members of a tool's template (protocol.md §3.1). */
function bodyOf(t: ToolSpec): TemplateBody {
  const d = t.template;
  return {
    text: d.text,
    ...(d.elide ? { elide: d.elide } : {}),
    ...(d.note !== undefined ? { note: d.note } : {}),
    ...(d.links ? { links: d.links } : {}),
    ...(d.link_hosts ? { link_hosts: d.link_hosts } : {}),
  };
}

/** sha256 of a tool's template as pinned at pairing and sent in `template_source` (protocol.md §3.1, §5.4). */
export function toolTemplateSha256(t: ToolSpec): string {
  return templateSha256(bodyOf(t));
}

/** Build the protocol template registry entry for an adapter so the gateway renders with the same code as every approver. */
export function registryFromManifest(m: AdapterManifest): TemplateRegistry {
  return {
    adapter: m.name,
    templates: m.tools.map((t) => {
      const { text, ...rest } = bodyOf(t);
      return { template_id: t.template.id, template_version: t.template.version, text, sha256: toolTemplateSha256(t), ...rest };
    }),
  };
}

export function fullyQualified(m: AdapterManifest, t: ToolSpec): string {
  return `${m.name}.${t.name}`;
}
