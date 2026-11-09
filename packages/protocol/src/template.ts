// docs/protocol.md §3: display templates and the renderer. Two inputs only: canonical bytes and the registry.
import { canonicalize, type JsonValue } from "./jcs.js";
import { sha256hex, utf8 } from "./encoding.js";
import { parseCanonicalAction } from "./action.js";
import { displayEscape } from "./display.js";

/** A review link (§3.5): a literal label and a URL template over `args_resolved`. */
export interface TemplateLink {
  label: string;
  url: string;
}

export interface Template {
  template_id: string;
  template_version: number;
  text: string;
  /** SHA-256 of the template's hash input (§3.1): the UTF-8 text when text-only, else JCS of text and the other members. */
  sha256: string;
  /** args_resolved keys the template intentionally does not mention (§3.4). */
  elide?: string[];
  /** Optional second line, same placeholder rules as `text` plus the `:short` formatter (§3.2). */
  note?: string;
  /** Optional review links, at most 4 (§3.5). */
  links?: TemplateLink[];
  /** Exact hostnames the links may point to (§3.5). Required when `links` is non-empty. */
  link_hosts?: string[];
}

/** The members of a template that its `sha256` covers (§3.1). */
export type TemplateBody = Pick<Template, "text" | "elide" | "note" | "links" | "link_hosts">;

export interface TemplateRegistry {
  adapter: string;
  templates: Template[];
}

export const MAX_LINKS = 4;
export const MAX_LINK_HOSTS = 8;
export const MAX_LINK_LABEL_BYTES = 64;
export const MAX_LINK_URL_LENGTH = 2048;
/** `{path:short}`: the first 7 code points of a string value (note only). */
export const SHORT_LENGTH = 7;

/** A member counts as present when it is not absent, null, "" or []. */
function present(v: unknown): boolean {
  return v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0);
}

/** True when the template has any member beyond `text` (a non-empty `elide`, `note`, `links` or `link_hosts`), so it hashes in the extended form. */
export function isExtendedTemplate(t: TemplateBody): boolean {
  return present(t.elide) || present(t.note) || present(t.links) || present(t.link_hosts);
}

/**
 * §3.1 hash input. A text-only template hashes its UTF-8 text. Otherwise it hashes the JCS object of `text`
 * and every present member (`elide`, `note`, `links` as `{label, url}` objects, `link_hosts`): `elide` widens
 * what the card hides, so it is always covered. JCS text starts with `{"`, which is never valid template
 * text, so the two forms cannot collide.
 */
export function templateHashInput(t: string | TemplateBody): string {
  if (typeof t === "string") return t;
  if (!isExtendedTemplate(t)) return t.text;
  const o: Record<string, unknown> = { text: t.text };
  if (present(t.elide)) o["elide"] = t.elide;
  if (present(t.note)) o["note"] = t.note;
  if (present(t.links)) {
    o["links"] = Array.isArray(t.links)
      ? t.links.map((l: unknown) => {
          const r = l as Record<string, unknown> | null;
          return r && typeof r === "object" && typeof r["label"] === "string" && typeof r["url"] === "string" ? { label: r["label"], url: r["url"] } : l;
        })
      : t.links;
  }
  if (present(t.link_hosts)) o["link_hosts"] = t.link_hosts;
  return canonicalize(o as JsonValue);
}

/** SHA-256 (lowercase hex) of a template's hash input. A string is hashed as the text of a text-only template. */
export function templateSha256(t: string | TemplateBody): string {
  try {
    return sha256hex(templateHashInput(t));
  } catch {
    return ""; // not JSON-serialisable: matches no pin and no registry entry
  }
}

export type UnverifiedReason =
  | "action_malformed"
  | "unknown_template"
  | "template_hash_mismatch"
  | "malformed_template"
  | "unresolved_placeholder"
  | "unreferenced_key";

/** Why a template's links were dropped as a whole (§3.5). The card itself still renders. */
export type LinksError =
  | "links_malformed"
  | "too_many_links"
  | "link_hosts_invalid"
  | "label_invalid"
  | "url_invalid"
  | "url_not_https"
  | "host_not_literal"
  | "host_not_allowed";

export interface RenderedLink {
  label: string;
  url: string;
}

export type RenderResult =
  | {
      status: "ok";
      text: string;
      template: Template;
      hidden: string[];
      /** The rendered note line, when the template has one. */
      note?: string;
      /** Review links built from the canonical args (§3.5). Empty when none render. */
      links: RenderedLink[];
      /** Set when the template's links are invalid and were all dropped: show a warning. */
      links_error?: LinksError;
    }
  | { status: "unverified"; reason: UnverifiedReason; detail?: string; canonical_bytes: string };

export function findTemplate(registries: readonly TemplateRegistry[], id: string, version: number): Template | undefined {
  for (const r of registries) for (const t of r.templates) if (t.template_id === id && t.template_version === version) return t;
  return undefined;
}

type Token = { kind: "lit"; text: string } | { kind: "ph"; path: string[]; fmt?: string };

/**
 * §3.2 placeholder grammar. Returns null on a stray brace, an empty/invalid path, or a formatter not in
 * `formatters` (`{path:name}`; `text` allows none, `note` allows `short`, link URLs allow `path`).
 */
export function tokenizeTemplate(text: string, formatters: readonly string[] = []): Token[] | null {
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
      const m = /^([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)(?::([a-z]+))?$/.exec(text.slice(i + 1, end));
      if (!m) return null;
      const fmt = m[2];
      if (fmt !== undefined && !formatters.includes(fmt)) return null;
      if (lit) out.push({ kind: "lit", text: lit });
      lit = "";
      out.push(fmt !== undefined ? { kind: "ph", path: (m[1] as string).split("."), fmt } : { kind: "ph", path: (m[1] as string).split(".") });
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

/** §3.2 value rendering: strings verbatim, everything else as its JCS text. Not yet display-escaped (§3.6). */
export function renderValue(v: unknown): string {
  return typeof v === "string" ? v : canonicalize(v);
}

/** A value as an approver surface shows it outside the template line (argument rows): `renderValue`, then §3.6. */
export function displayValue(v: unknown): string {
  return displayEscape(renderValue(v));
}

// ---- §3.5 links -------------------------------------------------------------------------------------

const isAsciiAlnum = (c: number): boolean => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
const isHexDigit = (c: number): boolean => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
/** RFC 3986 unreserved: ALPHA DIGIT - . _ ~ */
const isUnreserved = (c: number): boolean => isAsciiAlnum(c) || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e;
/** Literal URL characters outside placeholders: unreserved, `:/?#@!$&'()*+,;=`, and `%XX`. */
const URL_LITERAL_EXTRA = new Set(Array.from(":/?#@!$&'()*+,;=", (ch) => ch.charCodeAt(0)));

function isValidUrlLiteral(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (isUnreserved(c) || URL_LITERAL_EXTRA.has(c)) continue;
    if (c === 0x25 && i + 2 < s.length && isHexDigit(s.charCodeAt(i + 1)) && isHexDigit(s.charCodeAt(i + 2))) {
      i += 2;
      continue;
    }
    return false;
  }
  return true;
}

/** Lowercase LDH labels of 1–63, at least two labels, the last starting with a letter, at most 253 in all. */
export function isValidLinkHost(h: string): boolean {
  if (h.length < 1 || h.length > 253) return false;
  const labels = h.split(".");
  if (labels.length < 2) return false;
  for (const l of labels) {
    if (l.length < 1 || l.length > 63) return false;
    for (let i = 0; i < l.length; i++) {
      const c = l.charCodeAt(i);
      const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x7a) || (c === 0x2d && i > 0 && i < l.length - 1);
      if (!ok) return false;
    }
  }
  const last = (labels[labels.length - 1] as string).charCodeAt(0);
  return last >= 0x61 && last <= 0x7a;
}

const LONE_SURROGATE = /\p{Cs}/u;

/** Non-empty, at most 64 UTF-8 bytes, no control (C0, DEL, C1) or bidirectional formatting characters. */
export function isValidLinkLabel(s: string): boolean {
  if (s.length === 0 || LONE_SURROGATE.test(s) || utf8.encode(s).length > MAX_LINK_LABEL_BYTES) return false;
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x200e || c === 0x200f || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return false;
  }
  return true;
}

interface ParsedLink {
  label: string;
  host: string;
  tokens: Token[];
}

function parseLinkUrl(url: string, hosts: readonly string[]): { ok: true; host: string; tokens: Token[] } | { ok: false; code: LinksError } {
  if (url.length > MAX_LINK_URL_LENGTH) return { ok: false, code: "url_invalid" };
  const tokens = tokenizeTemplate(url, ["path"]);
  if (!tokens) return { ok: false, code: "url_invalid" };
  let fragments = 0;
  for (const t of tokens) {
    if (t.kind !== "lit") continue;
    if (!isValidUrlLiteral(t.text)) return { ok: false, code: "url_invalid" };
    for (const ch of t.text) if (ch === "#") fragments++;
  }
  if (fragments > 1) return { ok: false, code: "url_invalid" };
  const first = tokens[0];
  if (!first || first.kind !== "lit" || !first.text.startsWith("https://")) return { ok: false, code: "url_not_https" };
  const rest = first.text.slice("https://".length);
  const slash = rest.indexOf("/");
  if (slash < 0) return { ok: false, code: "host_not_literal" };
  const host = rest.slice(0, slash);
  if (!hosts.includes(host)) return { ok: false, code: "host_not_allowed" };
  return { ok: true, host, tokens };
}

function parseLinks(t: TemplateBody): { ok: true; links: ParsedLink[] } | { ok: false; code: LinksError } {
  const rawLinks: unknown = t.links;
  const rawHosts: unknown = t.link_hosts;
  const isLink = (l: unknown): l is TemplateLink =>
    typeof l === "object" && l !== null && typeof (l as Record<string, unknown>)["label"] === "string" && typeof (l as Record<string, unknown>)["url"] === "string";
  if (rawLinks != null && (!Array.isArray(rawLinks) || !rawLinks.every(isLink))) return { ok: false, code: "links_malformed" };
  if (rawHosts != null && (!Array.isArray(rawHosts) || !rawHosts.every((h) => typeof h === "string"))) return { ok: false, code: "links_malformed" };
  const links = (rawLinks ?? []) as TemplateLink[];
  const hosts = (rawHosts ?? []) as string[];
  if (links.length > MAX_LINKS) return { ok: false, code: "too_many_links" };
  if (hosts.length > MAX_LINK_HOSTS || !hosts.every(isValidLinkHost) || (links.length > 0 && hosts.length === 0)) return { ok: false, code: "link_hosts_invalid" };
  const out: ParsedLink[] = [];
  for (const l of links) {
    if (!isValidLinkLabel(l.label)) return { ok: false, code: "label_invalid" };
    const p = parseLinkUrl(l.url, hosts);
    if (!p.ok) return p;
    out.push({ label: l.label, host: p.host, tokens: p.tokens });
  }
  return { ok: true, links: out };
}

/** §3.5 template-level link rules. null when the links (and hosts) are valid or absent. */
export function templateLinksError(t: TemplateBody): LinksError | null {
  const r = parseLinks(t);
  return r.ok ? null : r.code;
}

/** RFC 3986 percent-encoding of the UTF-8 bytes; unreserved characters stay, hex digits uppercase. */
export function encodeLinkSegment(s: string): string {
  let out = "";
  for (const b of utf8.encode(s)) out += isUnreserved(b) ? String.fromCharCode(b) : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  return out;
}

/** One link for these args, or null when a value does not fit the rules (the link is dropped). */
function renderLink(l: ParsedLink, args: Record<string, unknown>): string | null {
  let out = "";
  for (const tok of l.tokens) {
    if (tok.kind === "lit") {
      out += tok.text;
      continue;
    }
    const r = lookup(args, tok.path);
    if (!r.found) return null;
    let s: string;
    if (typeof r.value === "string") s = r.value;
    else if (typeof r.value === "number" && Number.isSafeInteger(r.value)) s = canonicalize(r.value);
    else return null;
    if (LONE_SURROGATE.test(s)) return null;
    const segments = tok.fmt === "path" ? s.split("/") : [s];
    for (const seg of segments) if (seg === "" || seg === "." || seg === "..") return null;
    out += segments.map(encodeLinkSegment).join("/");
  }
  if (out.length > MAX_LINK_URL_LENGTH) return null;
  let u: URL;
  try {
    u = new URL(out);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.hostname !== l.host || u.username !== "" || u.password !== "" || u.port !== "") return null;
  return out;
}

/** §3.5: the review links for these args. Invalid links never fail the card; they are dropped with a code. */
export function renderLinks(t: TemplateBody, args: Record<string, unknown>): { links: RenderedLink[]; error?: LinksError } {
  const p = parseLinks(t);
  if (!p.ok) return { links: [], error: p.code };
  const links: RenderedLink[] = [];
  for (const l of p.links) {
    const url = renderLink(l, args);
    if (url !== null) links.push({ label: l.label, url });
  }
  return { links };
}

/**
 * Every rule a published template must meet (bundled registries, adapter manifests): `text` and `note`
 * tokenize with their formatters, and the links are valid. Returns problems, empty when the template is valid.
 */
export function templateProblems(t: TemplateBody): string[] {
  const out: string[] = [];
  if (!tokenizeTemplate(t.text)) out.push("text has a stray brace, an invalid placeholder or a formatter");
  if (t.note !== undefined && (typeof t.note !== "string" || !tokenizeTemplate(t.note, ["short"]))) out.push("note has a stray brace, an invalid placeholder or a formatter other than :short");
  const le = templateLinksError(t);
  if (le) out.push(`links are invalid: ${le}`);
  return out;
}

/** Substitute values into tokens; `:short` takes the first 7 code points of a string. */
function substitute(tokens: Token[], args: Record<string, unknown>): { ok: true; text: string } | { ok: false; path: string } {
  let out = "";
  for (const tok of tokens) {
    if (tok.kind === "lit") {
      out += tok.text;
      continue;
    }
    const r = lookup(args, tok.path);
    if (!r.found) return { ok: false, path: tok.path.join(".") };
    if (tok.fmt === "short") {
      if (typeof r.value !== "string") return { ok: false, path: tok.path.join(".") };
      out += Array.from(r.value).slice(0, SHORT_LENGTH).join("");
    } else {
      out += renderValue(r.value);
    }
  }
  return { ok: true, text: out };
}

/**
 * §3.4 unreferenced-key rule, nested: every leaf of `args_resolved` (a scalar, or an empty object or array) must be
 * under a `text` placeholder path (a placeholder covers everything beneath it: `{order}` covers `order.qty`), unless
 * its top-level key is in `elide`. Object members are walked in ECMAScript key order, array elements by index.
 * Returns the first uncovered leaf as a dotted path, and the elided top-level keys no placeholder names exactly.
 */
export function unreferenced(args: Record<string, unknown>, refs: readonly (readonly string[])[], elide: ReadonlySet<string>): { path?: string; hidden: string[] } {
  const covered = (path: readonly string[]) => refs.some((r) => r.length <= path.length && r.every((seg, i) => seg === path[i]));
  const walk = (v: unknown, path: string[]): string | undefined => {
    if (covered(path)) return undefined;
    if (Array.isArray(v) && v.length > 0) {
      for (let i = 0; i < v.length; i++) {
        const r = walk(v[i], [...path, String(i)]);
        if (r !== undefined) return r;
      }
      return undefined;
    }
    if (v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 0) {
      for (const k of Object.keys(v)) {
        const r = walk((v as Record<string, unknown>)[k], [...path, k]);
        if (r !== undefined) return r;
      }
      return undefined;
    }
    return path.join(".");
  };
  const hidden: string[] = [];
  for (const k of Object.keys(args)) {
    if (covered([k])) continue;
    if (elide.has(k)) {
      hidden.push(k);
      continue;
    }
    const r = walk(args[k], [k]);
    if (r !== undefined) return { path: r, hidden };
  }
  return { hidden };
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
  if (templateSha256(t) !== t.sha256) return { status: "unverified", reason: "template_hash_mismatch", canonical_bytes: canonicalBytes };
  const tokens = tokenizeTemplate(t.text);
  const hasNote = present(t.note);
  const noteTokens = hasNote ? (typeof t.note === "string" ? tokenizeTemplate(t.note, ["short"]) : null) : [];
  if (!tokens || !noteTokens) return { status: "unverified", reason: "malformed_template", canonical_bytes: canonicalBytes };

  const text = substitute(tokens, a.args_resolved);
  if (!text.ok) return { status: "unverified", reason: "unresolved_placeholder", detail: text.path, canonical_bytes: canonicalBytes };
  const note = substitute(noteTokens, a.args_resolved);
  if (!note.ok) return { status: "unverified", reason: "unresolved_placeholder", detail: note.path, canonical_bytes: canonicalBytes };

  // Only `text` placeholders count: the sentence must mention every argument (§3.4), not the note or a link.
  const refs = tokens.filter((tok): tok is Extract<Token, { kind: "ph" }> => tok.kind === "ph").map((tok) => tok.path);
  const u = unreferenced(a.args_resolved, refs, new Set(t.elide ?? []));
  if (u.path !== undefined) return { status: "unverified", reason: "unreferenced_key", detail: u.path, canonical_bytes: canonicalBytes };
  const hidden = u.hidden;
  const links = renderLinks(t, a.args_resolved);
  return {
    status: "ok",
    text: displayEscape(text.text),
    template: t,
    hidden,
    ...(hasNote ? { note: displayEscape(note.text) } : {}),
    links: links.links,
    ...(links.error ? { links_error: links.error } : {}),
  };
}
