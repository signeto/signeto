// Manifest validation at startup (docs/adapters.md §2, §3). The gateway refuses to start on any failure.
import { templateSha256, tokenizeTemplate, type TemplateRegistry } from "@signeto/protocol";
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
  const toks = tokenizeTemplate(t.template.text);
  if (!toks) return [{ adapter: adapterName, tool: t.name, message: "template text has a stray brace or invalid placeholder" }];
  const props = ((t.resolved as { properties?: Record<string, unknown> }).properties ?? {}) as Record<string, unknown>;
  const required = new Set(((t.resolved as { required?: string[] }).required ?? []) as string[]);
  const referenced = new Set<string>();
  for (const tok of toks) {
    if (tok.kind !== "ph") continue;
    const root = tok.path[0] as string;
    referenced.add(root);
    if (!(root in props)) out.push({ adapter: adapterName, tool: t.name, message: `template placeholder {${tok.path.join(".")}} is not a resolved property` });
    else if (!required.has(root)) out.push({ adapter: adapterName, tool: t.name, message: `template placeholder {${root}} must be a required resolved property` });
  }
  const elide = new Set(t.template.elide ?? []);
  for (const k of Object.keys(props)) {
    if (!referenced.has(k) && !elide.has(k)) out.push({ adapter: adapterName, tool: t.name, message: `resolved property "${k}" is neither referenced by the template nor listed in elide` });
  }
  return out;
}

/** Build the protocol template registry entry for an adapter so the gateway renders with the same code as every approver. */
export function registryFromManifest(m: AdapterManifest): TemplateRegistry {
  return {
    adapter: m.name,
    templates: m.tools.map((t) => ({
      template_id: t.template.id,
      template_version: t.template.version,
      text: t.template.text,
      sha256: templateSha256(t.template.text),
      ...(t.template.elide ? { elide: t.template.elide } : {}),
    })),
  };
}

export function fullyQualified(m: AdapterManifest, t: ToolSpec): string {
  return `${m.name}.${t.name}`;
}
