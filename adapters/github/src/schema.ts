// Small JSON Schema (draft 2020-12) helpers. Every object schema closes additionalProperties (docs/adapters.md §2).
import type { JSONSchema } from "@signeto/adapter-sdk";

export function obj(properties: Record<string, JSONSchema>, required: string[]): JSONSchema {
  return { type: "object", additionalProperties: false, properties, required };
}

export function str(pattern?: string, maxLength?: number): JSONSchema {
  return { type: "string", minLength: 1, ...(pattern ? { pattern } : {}), ...(maxLength !== undefined ? { maxLength } : {}) };
}

export function int(minimum?: number): JSONSchema {
  return { type: "integer", ...(minimum !== undefined ? { minimum } : {}) };
}

export function enm(...values: string[]): JSONSchema {
  return { type: "string", enum: values };
}

/** A flat map of string workflow inputs, as GitHub's `workflow_dispatch` endpoint accepts them. */
export function stringMap(maxProperties = 25): JSONSchema {
  return { type: "object", additionalProperties: { type: "string", maxLength: 65535 }, maxProperties };
}
