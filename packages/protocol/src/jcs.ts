// RFC 8785 JSON Canonicalization Scheme (JCS).
// docs/protocol.md §2.3. Frozen for protocol_version MAJOR 1.

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

/** Serialize a JSON-compatible value to its JCS string. Throws on non-JSON input. */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new JcsError("non-finite number");
      // ES Number::toString, which JSON.stringify delegates to for finite numbers.
      return JSON.stringify(value);
    case "string":
      // JSON.stringify applies exactly the escaping RFC 8785 §3.2.2.2 requires
      // (short escapes for \b \f \n \r \t, lowercase \u00xx for other controls, no other escapes).
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new JcsError(`unsupported type ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  // Default Array.prototype.sort compares UTF-16 code units, which is the JCS member order.
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const parts: string[] = [];
  for (const k of keys) parts.push(JSON.stringify(k) + ":" + canonicalize(obj[k]));
  return "{" + parts.join(",") + "}";
}

/** True when `text` is already the JCS serialization of the value it parses to. */
export function isCanonical(text: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  try {
    return canonicalize(parsed) === text;
  } catch {
    return false;
  }
}

export class JcsError extends Error {
  override name = "JcsError";
}
