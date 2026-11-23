// Small JSON Schema (draft 2020-12) helpers. Every object schema closes additionalProperties (docs/adapters.md §2).
import type { JSONSchema } from "@signeto/adapter-sdk";

export function obj(properties: Record<string, JSONSchema>, required: string[]): JSONSchema {
  return { type: "object", additionalProperties: false, properties, required };
}

export function str(pattern?: string, maxLength?: number): JSONSchema {
  return { type: "string", minLength: 1, ...(pattern ? { pattern } : {}), ...(maxLength !== undefined ? { maxLength } : {}) };
}

export function int(minimum?: number, maximum?: number): JSONSchema {
  return { type: "integer", ...(minimum !== undefined ? { minimum } : {}), ...(maximum !== undefined ? { maximum } : {}) };
}

export function num(minimum?: number, maximum?: number): JSONSchema {
  return { type: "number", ...(minimum !== undefined ? { minimum } : {}), ...(maximum !== undefined ? { maximum } : {}) };
}

export function enm(...values: string[]): JSONSchema {
  return { type: "string", enum: values };
}

/** A string or a number the adapter normalises (a price the agent may send either way). */
export function decimalInput(): JSONSchema {
  return { anyOf: [{ type: "string", pattern: "^[0-9]+(\\.[0-9]+)?$", maxLength: 20 }, { type: "number", exclusiveMinimum: 0 }] };
}

/** A decimal string, or null (`limit_price` of a market order). */
export function nullableDecimal(pattern: string): JSONSchema {
  return { anyOf: [{ type: "string", pattern }, { type: "null" }] };
}
