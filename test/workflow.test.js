import test from "node:test";
import assert from "node:assert/strict";

import {
  WORKFLOW_INTENTS,
  WORKFLOW_STATES,
  WORKFLOW_INTENT_VALIDATORS,
  isWorkflowOrchestrationIntent,
  validateWorkflowExecuteParameters,
  validateWorkflowStepCompleteParameters,
  validateWorkflowCompleteParameters,
  validateWorkflowFailedParameters,
  buildInitialWorkflowState,
  applyStepComplete,
  applyWorkflowComplete,
  applyWorkflowFailed
} from "../src/protocol/workflow.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("WORKFLOW_INTENTS contains all four orchestration intents", () => {
  assert.equal(WORKFLOW_INTENTS.EXECUTE, "workflow.execute@v1");
  assert.equal(WORKFLOW_INTENTS.STEP_COMPLETE, "workflow.step_complete@v1");
  assert.equal(WORKFLOW_INTENTS.COMPLETE, "workflow.complete@v1");
  assert.equal(WORKFLOW_INTENTS.FAILED, "workflow.failed@v1");
});

test("WORKFLOW_STATES contains running, completed, failed", () => {
  assert.equal(WORKFLOW_STATES.RUNNING, "running");
  assert.equal(WORKFLOW_STATES.COMPLETED, "completed");
  assert.equal(WORKFLOW_STATES.FAILED, "failed");
});

// ─── Predicate ──────────────────────────────────────────────────────────────

test("isWorkflowOrchestrationIntent returns true for all 4 known intents", () => {
  assert.equal(isWorkflowOrchestrationIntent("workflow.execute@v1"), true);
  assert.equal(isWorkflowOrchestrationIntent("workflow.step_complete@v1"), true);
  assert.equal(isWorkflowOrchestrationIntent("workflow.complete@v1"), true);
  assert.equal(isWorkflowOrchestrationIntent("workflow.failed@v1"), true);
});

test("isWorkflowOrchestrationIntent returns false for MCP intents", () => {
  assert.equal(isWorkflowOrchestrationIntent("mcp.tool_request@v1"), false);
  assert.equal(isWorkflowOrchestrationIntent("mcp.tool_response@v1"), false);
});

test("isWorkflowOrchestrationIntent returns false for other workflow-prefixed intents", () => {
  assert.equal(isWorkflowOrchestrationIntent("workflow.custom@v1"), false);
  assert.equal(isWorkflowOrchestrationIntent("workflow.execute@v2"), false);
  assert.equal(isWorkflowOrchestrationIntent(""), false);
  assert.equal(isWorkflowOrchestrationIntent(null), false);
  assert.equal(isWorkflowOrchestrationIntent(undefined), false);
});

// ─── validateWorkflowExecuteParameters ──────────────────────────────────────

test("validateWorkflowExecuteParameters: valid parameters pass", () => {
  const errors = validateWorkflowExecuteParameters({
    workflow_id: "wf_123",
    definition: {
      steps: [{ step_id: "step_1" }, { step_id: "step_2" }]
    }
  });
  assert.equal(errors.length, 0);
});

test("validateWorkflowExecuteParameters: missing workflow_id", () => {
  const errors = validateWorkflowExecuteParameters({
    definition: { steps: [{ step_id: "s1" }] }
  });
  assert.ok(errors.some((e) => e.field === "workflow_id"));
});

test("validateWorkflowExecuteParameters: missing definition", () => {
  const errors = validateWorkflowExecuteParameters({ workflow_id: "wf_1" });
  assert.ok(errors.some((e) => e.field === "definition"));
});

test("validateWorkflowExecuteParameters: definition.steps not array", () => {
  const errors = validateWorkflowExecuteParameters({
    workflow_id: "wf_1",
    definition: { steps: "not-array" }
  });
  assert.ok(errors.some((e) => e.field === "definition.steps"));
});

test("validateWorkflowExecuteParameters: empty steps array", () => {
  const errors = validateWorkflowExecuteParameters({
    workflow_id: "wf_1",
    definition: { steps: [] }
  });
  assert.ok(errors.some((e) => e.field === "definition.steps" && e.reason.includes("at least one")));
});

test("validateWorkflowExecuteParameters: step without step_id", () => {
  const errors = validateWorkflowExecuteParameters({
    workflow_id: "wf_1",
    definition: { steps: [{ name: "test" }] }
  });
  assert.ok(errors.some((e) => e.field.includes("step_id")));
});

test("validateWorkflowExecuteParameters: null parameters", () => {
  const errors = validateWorkflowExecuteParameters(null);
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.field === "parameters"));
});

// ─── validateWorkflowStepCompleteParameters ─────────────────────────────────

test("validateWorkflowStepCompleteParameters: valid parameters pass", () => {
  const errors = validateWorkflowStepCompleteParameters({
    workflow_id: "wf_1",
    step_id: "step_1",
    result: { output: "done" }
  });
  assert.equal(errors.length, 0);
});

test("validateWorkflowStepCompleteParameters: missing step_id", () => {
  const errors = validateWorkflowStepCompleteParameters({
    workflow_id: "wf_1",
    result: "ok"
  });
  assert.ok(errors.some((e) => e.field === "step_id"));
});

test("validateWorkflowStepCompleteParameters: missing result", () => {
  const errors = validateWorkflowStepCompleteParameters({
    workflow_id: "wf_1",
    step_id: "s1"
  });
  assert.ok(errors.some((e) => e.field === "result"));
});

// ─── validateWorkflowCompleteParameters ─────────────────────────────────────

test("validateWorkflowCompleteParameters: valid with result", () => {
  const errors = validateWorkflowCompleteParameters({
    workflow_id: "wf_1",
    result: { summary: "all done" }
  });
  assert.equal(errors.length, 0);
});

test("validateWorkflowCompleteParameters: valid without result", () => {
  const errors = validateWorkflowCompleteParameters({
    workflow_id: "wf_1"
  });
  assert.equal(errors.length, 0);
});

test("validateWorkflowCompleteParameters: missing workflow_id", () => {
  const errors = validateWorkflowCompleteParameters({});
  assert.ok(errors.some((e) => e.field === "workflow_id"));
});

// ─── validateWorkflowFailedParameters ───────────────────────────────────────

test("validateWorkflowFailedParameters: valid parameters pass", () => {
  const errors = validateWorkflowFailedParameters({
    workflow_id: "wf_1",
    error: { message: "something went wrong" }
  });
  assert.equal(errors.length, 0);
});

test("validateWorkflowFailedParameters: missing error", () => {
  const errors = validateWorkflowFailedParameters({
    workflow_id: "wf_1"
  });
  assert.ok(errors.some((e) => e.field === "error"));
});

test("validateWorkflowFailedParameters: error without message", () => {
  const errors = validateWorkflowFailedParameters({
    workflow_id: "wf_1",
    error: { code: 500 }
  });
  assert.ok(errors.some((e) => e.field === "error.message"));
});

// ─── WORKFLOW_INTENT_VALIDATORS map ─────────────────────────────────────────

test("WORKFLOW_INTENT_VALIDATORS maps each intent to its validator", () => {
  assert.equal(WORKFLOW_INTENT_VALIDATORS[WORKFLOW_INTENTS.EXECUTE], validateWorkflowExecuteParameters);
  assert.equal(WORKFLOW_INTENT_VALIDATORS[WORKFLOW_INTENTS.STEP_COMPLETE], validateWorkflowStepCompleteParameters);
  assert.equal(WORKFLOW_INTENT_VALIDATORS[WORKFLOW_INTENTS.COMPLETE], validateWorkflowCompleteParameters);
  assert.equal(WORKFLOW_INTENT_VALIDATORS[WORKFLOW_INTENTS.FAILED], validateWorkflowFailedParameters);
});

// ─── State Builders ─────────────────────────────────────────────────────────

test("buildInitialWorkflowState creates running state", () => {
  const state = buildInitialWorkflowState({
    workflow_id: "wf_abc",
    definition: { steps: [{ step_id: "s1" }] }
  });
  assert.equal(state.workflow_id, "wf_abc");
  assert.equal(state.status, "running");
  assert.deepEqual(state.definition, { steps: [{ step_id: "s1" }] });
  assert.deepEqual(state.step_states, {});
  assert.ok(state.started_at);
  assert.equal(state.completed_at, null);
  assert.equal(state.failed_at, null);
  assert.equal(state.error, null);
});

test("applyStepComplete adds step state", () => {
  const initial = buildInitialWorkflowState({
    workflow_id: "wf_1",
    definition: { steps: [{ step_id: "s1" }, { step_id: "s2" }] }
  });
  const updated = applyStepComplete(initial, {
    step_id: "s1",
    result: { output: "done" }
  });
  assert.equal(updated.step_states.s1.status, "completed");
  assert.deepEqual(updated.step_states.s1.result, { output: "done" });
  assert.ok(updated.step_states.s1.completed_at);
  assert.equal(updated.status, "running");
});

test("applyStepComplete overwrites duplicate step_id", () => {
  const initial = buildInitialWorkflowState({
    workflow_id: "wf_1",
    definition: { steps: [{ step_id: "s1" }] }
  });
  const after1 = applyStepComplete(initial, { step_id: "s1", result: "first" });
  const after2 = applyStepComplete(after1, { step_id: "s1", result: "second" });
  assert.equal(after2.step_states.s1.result, "second");
});

test("applyWorkflowComplete sets completed status", () => {
  const initial = buildInitialWorkflowState({
    workflow_id: "wf_1",
    definition: { steps: [{ step_id: "s1" }] }
  });
  const completed = applyWorkflowComplete(initial, { result: "all good" });
  assert.equal(completed.status, "completed");
  assert.ok(completed.completed_at);
  assert.equal(completed.result, "all good");
  assert.equal(completed.failed_at, null);
});

test("applyWorkflowComplete without result", () => {
  const initial = buildInitialWorkflowState({
    workflow_id: "wf_1",
    definition: { steps: [{ step_id: "s1" }] }
  });
  const completed = applyWorkflowComplete(initial, {});
  assert.equal(completed.status, "completed");
  assert.ok(completed.completed_at);
  assert.equal(completed.result, undefined);
});

test("applyWorkflowFailed sets failed status with error", () => {
  const initial = buildInitialWorkflowState({
    workflow_id: "wf_1",
    definition: { steps: [{ step_id: "s1" }] }
  });
  const failed = applyWorkflowFailed(initial, {
    error: { message: "timeout", code: "TIMEOUT" }
  });
  assert.equal(failed.status, "failed");
  assert.ok(failed.failed_at);
  assert.deepEqual(failed.error, { message: "timeout", code: "TIMEOUT" });
  assert.equal(failed.completed_at, null);
});

// ─── State Transition Sequences ─────────────────────────────────────────────

test("full lifecycle: execute → step_complete → complete", () => {
  let state = buildInitialWorkflowState({
    workflow_id: "wf_lifecycle",
    definition: { steps: [{ step_id: "fetch" }, { step_id: "process" }] }
  });
  assert.equal(state.status, "running");

  state = applyStepComplete(state, { step_id: "fetch", result: { data: [1, 2, 3] } });
  assert.equal(state.status, "running");
  assert.ok(state.step_states.fetch);

  state = applyStepComplete(state, { step_id: "process", result: { count: 3 } });
  assert.equal(state.status, "running");
  assert.ok(state.step_states.process);

  state = applyWorkflowComplete(state, { result: "success" });
  assert.equal(state.status, "completed");
  assert.ok(state.completed_at);
});

test("lifecycle: execute → failed", () => {
  let state = buildInitialWorkflowState({
    workflow_id: "wf_fail",
    definition: { steps: [{ step_id: "s1" }] }
  });

  state = applyWorkflowFailed(state, { error: { message: "crash" } });
  assert.equal(state.status, "failed");
  assert.ok(state.failed_at);
});
