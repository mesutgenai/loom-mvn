// ─── Context Window / State Compression ─────────────────────────────────────
// Pure validation functions for context-window management across agent
// conversations: embedding vectors, token budgets, and thread snapshots.

export const CONTEXT_VECTOR_MIN_DIMENSIONS = 8;
export const CONTEXT_VECTOR_MAX_DIMENSIONS = 4096;
export const TOKEN_LIMIT_MIN = 1;
export const TOKEN_LIMIT_MAX = 10_000_000;

// ─── Context Vector Validation ──────────────────────────────────────────────

export function validateContextVector(contextVector) {
  const errors = [];
  if (!Array.isArray(contextVector)) {
    errors.push({ field: "meta.context_vector", reason: "must be an array of numbers" });
    return errors;
  }
  if (contextVector.length < CONTEXT_VECTOR_MIN_DIMENSIONS) {
    errors.push({
      field: "meta.context_vector",
      reason: `must have at least ${CONTEXT_VECTOR_MIN_DIMENSIONS} dimensions`
    });
    return errors;
  }
  if (contextVector.length > CONTEXT_VECTOR_MAX_DIMENSIONS) {
    errors.push({
      field: "meta.context_vector",
      reason: `must not exceed ${CONTEXT_VECTOR_MAX_DIMENSIONS} dimensions`
    });
    return errors;
  }
  for (let i = 0; i < contextVector.length; i++) {
    if (typeof contextVector[i] !== "number" || !Number.isFinite(contextVector[i])) {
      errors.push({
        field: "meta.context_vector",
        reason: `element at index ${i} must be a finite number`
      });
      return errors;
    }
  }
  return errors;
}

// ─── Context Window Budget Validation ───────────────────────────────────────

export function validateContextWindowBudget(budget) {
  const errors = [];
  if (!budget || typeof budget !== "object" || Array.isArray(budget)) {
    errors.push({ field: "context_window_budget", reason: "must be an object" });
    return errors;
  }
  if (
    typeof budget.token_limit !== "number" ||
    !Number.isInteger(budget.token_limit) ||
    budget.token_limit < TOKEN_LIMIT_MIN ||
    budget.token_limit > TOKEN_LIMIT_MAX
  ) {
    errors.push({
      field: "context_window_budget.token_limit",
      reason: `must be an integer between ${TOKEN_LIMIT_MIN} and ${TOKEN_LIMIT_MAX}`
    });
  }
  return errors;
}

// ─── Snapshot Parameters Validation ─────────────────────────────────────────

export function validateSnapshotParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }
  if (typeof parameters.cutoff_envelope_id !== "string" || !parameters.cutoff_envelope_id.startsWith("env_")) {
    errors.push({
      field: "parameters.cutoff_envelope_id",
      reason: "must be a valid envelope ID (env_...)"
    });
  }
  if (typeof parameters.summary_text !== "string" || parameters.summary_text.trim().length === 0) {
    errors.push({
      field: "parameters.summary_text",
      reason: "must be a non-empty string"
    });
  }
  return errors;
}
