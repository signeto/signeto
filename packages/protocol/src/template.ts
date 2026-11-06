// docs/protocol.md §3: display templates and the renderer. Two inputs only: canonical bytes and the registry.
import { canonicalize } from "./jcs.js";
import { sha256hex } from "./encoding.js";
import { parseCanonicalAction } from "./action.js";

export interface Template {
  template_id: string;
  template_version: number;
  text: string;
  /** SHA-256 of the UTF-8 text. */
  sha256: string;
  /** args_resolved keys the template intentionally does not mention (§3.4). */
  elide?: string[];
}

export interface TemplateRegistry {
  adapter: string;
  templates: Template[];
}

export function templateSha256(text: string): string {
  return sha256hex(text);
}

export type UnverifiedReason =
  | "action_malformed"
  | "unknown_template"
  | "template_hash_mismatch"
  | "malformed_template"
  | "unresolved_placeholder"
  | "unreferenced_key";

export type RenderResult =
  | { status: "ok"; text: string; template: Template; hidden: string[] }
  | { status: "unverified"; reason: UnverifiedReason; detail?: string; canonical_bytes: string };

export function findTemplate(registries: readonly TemplateRegistry[], id: string, version: number): Template | undefined {
  for (const r of registries) for (const t of r.templates) if (t.template_id === id && t.template_version === version) return t;
  return undefined;
}

type Token = { kind: "lit"; text: string } | { kind: "ph"; path: string[] };

/** §3.2 placeholder grammar. Returns null on a stray brace or empty/invalid path. */
export function tokenizeTemplate(text: string): Token[] | null {
  const out: Token[] = [];
  let lit = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === "{") {
      if (text[i + 1] === "{") {
        lit += "{";
        i += 2;
        continue;
      }
      const end = text.indexOf("}", i + 1);
      if (end < 0) return null;
      const path = text.slice(i + 1, end);
      if (!/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/.test(path)) return null;
      if (lit) out.push({ kind: "lit", text: lit });
      lit = "";
      out.push({ kind: "ph", path: path.split(".") });
      i = end + 1;
      continue;
    }
    if (c === "}") {
      if (text[i + 1] === "}") {
        lit += "}";
        i += 2;
        continue;
      }
      return null;
    }
    lit += c;
    i++;
  }
  if (lit) out.push({ kind: "lit", text: lit });
  return out;
}

function lookup(args: Record<string, unknown>, path: string[]): { found: true; value: unknown } | { found: false } {
  let cur: unknown = args;
  for (const seg of path) {
    if (Array.isArray(cur)) {
      if (!/^[0-9]+$/.test(seg)) return { found: false };
      const idx = Number(seg);
      if (idx >= cur.length) return { found: false };
      cur = cur[idx];
    } else if (typeof cur === "object" && cur !== null) {
      if (!Object.prototype.hasOwnProperty.call(cur, seg)) return { found: false };
      cur = (cur as Record<string, unknown>)[seg];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: cur };
}

/** §3.2 value rendering: strings verbatim, everything else as its JCS text. */
export function renderValue(v: unknown): string {
  return typeof v === "string" ? v : canonicalize(v);
}

/**
 * Render the template line for canonical bytes. Never accepts a pre-rendered string.
 * Byte-identical output across gateway, CLI, phone and web for the same bytes and registry.
 */
export function renderTemplate(canonicalBytes: string, registries: readonly TemplateRegistry[]): RenderResult {
  const parsed = parseCanonicalAction(canonicalBytes);
  if (!parsed.ok) return { status: "unverified", reason: "action_malformed", detail: parsed.code, canonical_bytes: canonicalBytes };
  const a = parsed.value.action;
  const t = findTemplate(registries, a.template_id, a.template_version);
  if (!t) return { status: "unverified", reason: "unknown_template", canonical_bytes: canonicalBytes };
  if (templateSha256(t.text) !== t.sha256) return { status: "unverified", reason: "template_hash_mismatch", canonical_bytes: canonicalBytes };
  const tokens = tokenizeTemplate(t.text);
  if (!tokens) return { status: "unverified", reason: "malformed_template", canonical_bytes: canonicalBytes };

  const referenced = new Set<string>();
  let out = "";
  for (const tok of tokens) {
    if (tok.kind === "lit") {
      out += tok.text;
      continue;
    }
    referenced.add(tok.path[0] as string);
    const r = lookup(a.args_resolved, tok.path);
    if (!r.found) return { status: "unverified", reason: "unresolved_placeholder", detail: tok.path.join("."), canonical_bytes: canonicalBytes };
    out += renderValue(r.value);
  }
  const elide = new Set(t.elide ?? []);
  const hidden: string[] = [];
  for (const k of Object.keys(a.args_resolved)) {
    if (referenced.has(k)) continue;
    if (elide.has(k)) hidden.push(k);
    else return { status: "unverified", reason: "unreferenced_key", detail: k, canonical_bytes: canonicalBytes };
  }
  return { status: "ok", text: out, template: t, hidden };
}
