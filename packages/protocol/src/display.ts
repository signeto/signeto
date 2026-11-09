// docs/protocol.md §3.6: the display escape rule. One rule for every surface that shows a string from a request,
// a relay or a pairing (CLI card, iPhone, web approver, account pages, rendered templates), mirrored byte for byte by
// SignetoSign `Display.escape` and fixed by `vectors/display-escape/`.

/**
 * True for a code point that is shown as an escape instead of itself (§3.6):
 * C0 controls U+0000–U+001F (including TAB, LF, CR), DEL U+007F, C1 controls U+0080–U+009F,
 * ARABIC LETTER MARK U+061C, zero-width and directional marks U+200B–U+200F, LINE / PARAGRAPH SEPARATOR and the
 * bidi embeddings and overrides U+2028–U+202E, word joiner, invisible operators and bidi isolates U+2060–U+2069,
 * ZERO WIDTH NO-BREAK SPACE (BOM) U+FEFF, and lone surrogates U+D800–U+DFFF (a JavaScript string can hold them).
 */
export function isDisplayEscaped(cp: number): boolean {
  return (
    cp <= 0x1f ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0x061c ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x2028 && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2069) ||
    cp === 0xfeff ||
    (cp >= 0xd800 && cp <= 0xdfff)
  );
}

/** The escape for one code point in the escaped set: `\n`, `\r`, `\t`, else `\u{XX}` (uppercase hex, at least 2 digits). */
function escapeCodePoint(cp: number): string {
  if (cp === 0x0a) return "\\n";
  if (cp === 0x0d) return "\\r";
  if (cp === 0x09) return "\\t";
  return `\\u{${cp.toString(16).toUpperCase().padStart(2, "0")}}`;
}

/**
 * §3.6: `s` with every code point in the escaped set replaced by a visible escape; nothing else changes (a backslash
 * stays a backslash). The result has no character that moves the cursor, starts a new line, reorders text or is
 * invisible, so one value cannot overwrite, hide or visually reorder another on a card. Display only: never applied
 * to bytes that are hashed, signed or compared.
 */
export function displayEscape(s: string): string {
  let out = "";
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let cp = c;
    let width = 1;
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        width = 2;
      }
    }
    if (isDisplayEscaped(cp)) {
      out += s.slice(start, i) + escapeCodePoint(cp);
      start = i + width;
    }
    i += width - 1;
  }
  return start === 0 ? s : out + s.slice(start);
}

/** True when `s` contains no code point in the escaped set, i.e. `displayEscape(s) === s`. */
export function isDisplaySafe(s: string): boolean {
  return displayEscape(s) === s;
}
