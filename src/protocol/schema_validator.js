import { readFileSync } from "node:fs";

const SCHEMA_CACHE = new Map();

/**
 * Load and return the envelope JSON Schema (draft 2020-12).
 *
 * The schema is cached after first load for subsequent calls.
 *
 * @returns {object} Parsed JSON Schema object
 */
export function loadEnvelopeSchema() {
  const key = "envelope-v1.1";
  if (SCHEMA_CACHE.has(key)) {
    return SCHEMA_CACHE.get(key);
  }

  const schemaUrl = new URL("./schemas/envelope-v1.1.schema.json", import.meta.url);
  const schema = JSON.parse(readFileSync(schemaUrl, "utf-8"));
  SCHEMA_CACHE.set(key, schema);
  return schema;
}

/**
 * List available schema names.
 *
 * @returns {string[]}
 */
export function listAvailableSchemas() {
  return ["envelope-v1.1"];
}
