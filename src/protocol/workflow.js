// ─── Workflow Orchestration — Intent Validation & State Management ───────────

export const WORKFLOW_INTENTS = Object.freeze({
  EXECUTE: "workflow.execute@v1",
  STEP_COMPLETE: "workflow.step_complete@v1",
  COMPLETE: "workflow.complete@v1",
  FAILED: "workflow.failed@v1"
});

const WORKFLOW_INTENT_SET = new Set(Object.values(WORKFLOW_INTENTS));

export const WORKFLOW_STATES = Object.freeze({
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed"
});

// ─── Predicate ──────────────────────────────────────────────────────────────

export function isWorkflowOrchestrationIntent(intent) {
  return WORKFLOW_INTENT_SET.has(intent);
}

// ─── Parameter Validation ───────────────────────────────────────────────────

export function validateWorkflowExecuteParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!parameters.workflow_id || typeof parameters.workflow_id !== "string") {
    errors.push({ field: "workflow_id", reason: "required non-empty string" });
  }

  if (!parameters.definition || typeof parameters.definition !== "object") {
    errors.push({ field: "definition", reason: "required object" });
  } else if (!Array.isArray(parameters.definition.steps)) {
    errors.push({ field: "definition.steps", reason: "required array" });
  } else if (parameters.definition.steps.length === 0) {
    errors.push({ field: "definition.steps", reason: "must contain at least one step" });
  } else {
    for (let i = 0; i < parameters.definition.steps.length; i++) {
      const step = parameters.definition.steps[i];
      if (!step || typeof step !== "object") {
        errors.push({ field: `definition.steps[${i}]`, reason: "must be an object" });
      } else if (!step.step_id || typeof step.step_id !== "string") {
        errors.push({ field: `definition.steps[${i}].step_id`, reason: "required non-empty string" });
      }
    }
  }

  return errors;
}

export function validateWorkflowStepCompleteParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!parameters.workflow_id || typeof parameters.workflow_id !== "string") {
    errors.push({ field: "workflow_id", reason: "required non-empty string" });
  }

  if (!parameters.step_id || typeof parameters.step_id !== "string") {
    errors.push({ field: "step_id", reason: "required non-empty string" });
  }

  if (parameters.result === undefined) {
    errors.push({ field: "result", reason: "required" });
  }

  return errors;
}

export function validateWorkflowCompleteParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!parameters.workflow_id || typeof parameters.workflow_id !== "string") {
    errors.push({ field: "workflow_id", reason: "required non-empty string" });
  }

  return errors;
}

export function validateWorkflowFailedParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!parameters.workflow_id || typeof parameters.workflow_id !== "string") {
    errors.push({ field: "workflow_id", reason: "required non-empty string" });
  }

  if (!parameters.error || typeof parameters.error !== "object") {
    errors.push({ field: "error", reason: "required object" });
  } else if (!parameters.error.message || typeof parameters.error.message !== "string") {
    errors.push({ field: "error.message", reason: "required non-empty string" });
  }

  return errors;
}

// ─── State Builders ─────────────────────────────────────────────────────────

export function buildInitialWorkflowState(parameters) {
  return {
    workflow_id: parameters.workflow_id,
    status: WORKFLOW_STATES.RUNNING,
    definition: parameters.definition,
    step_states: {},
    started_at: new Date().toISOString(),
    completed_at: null,
    failed_at: null,
    error: null
  };
}

export function applyStepComplete(workflowState, parameters) {
  return {
    ...workflowState,
    step_states: {
      ...workflowState.step_states,
      [parameters.step_id]: {
        status: "completed",
        result: parameters.result,
        completed_at: new Date().toISOString()
      }
    }
  };
}

export function applyWorkflowComplete(workflowState, parameters) {
  return {
    ...workflowState,
    status: WORKFLOW_STATES.COMPLETED,
    completed_at: new Date().toISOString(),
    ...(parameters.result !== undefined ? { result: parameters.result } : {})
  };
}

export function applyWorkflowFailed(workflowState, parameters) {
  return {
    ...workflowState,
    status: WORKFLOW_STATES.FAILED,
    failed_at: new Date().toISOString(),
    error: parameters.error
  };
}

// ─── Intent → Validator Map ─────────────────────────────────────────────────

export const WORKFLOW_INTENT_VALIDATORS = Object.freeze({
  [WORKFLOW_INTENTS.EXECUTE]: validateWorkflowExecuteParameters,
  [WORKFLOW_INTENTS.STEP_COMPLETE]: validateWorkflowStepCompleteParameters,
  [WORKFLOW_INTENTS.COMPLETE]: validateWorkflowCompleteParameters,
  [WORKFLOW_INTENTS.FAILED]: validateWorkflowFailedParameters
});
