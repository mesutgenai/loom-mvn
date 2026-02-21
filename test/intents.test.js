import test from "node:test";
import assert from "node:assert/strict";

import {
  INTENT_REGISTRY,
  getIntentValidator,
  validateIntentParameters,
  validateMessageGeneralParameters,
  validateMessageQuestionParameters,
  validateTaskCreateParameters,
  validateTaskStateUpdateParameters,
  validateApprovalRequestParameters,
  validateApprovalResponseParameters,
  validateScheduleMeetingParameters,
  validateScheduleConfirmParameters,
  validateEventInviteParameters,
  validateEventRsvpParameters,
  validateHandoffTransferParameters,
  validateHandoffAcceptParameters,
  validateNotificationSystemParameters,
  validateNotificationAutoreplyParameters,
  validateReceiptDeliveredParameters,
  validateReceiptReadParameters,
  validateReceiptFailedParameters,
  validateAgentNegotiateParameters
} from "../src/protocol/intents.js";

// ─── Registry ────────────────────────────────────────────────────────────────

test("INTENT_REGISTRY contains all 18 intents", () => {
  assert.equal(Object.keys(INTENT_REGISTRY).length, 18);
});

test("getIntentValidator returns entry for known intent", () => {
  const entry = getIntentValidator("task.create@v1");
  assert.ok(entry);
  assert.equal(entry.type, "task");
  assert.equal(typeof entry.validator, "function");
});

test("getIntentValidator returns null for unknown intent", () => {
  assert.equal(getIntentValidator("unknown.intent@v1"), null);
});

test("validateIntentParameters returns [] for unknown intent (extensible)", () => {
  const errors = validateIntentParameters("custom.thing@v1", {});
  assert.equal(errors.length, 0);
});

// ─── message.general@v1 ─────────────────────────────────────────────────────

test("message.general: no required parameters", () => {
  assert.equal(validateMessageGeneralParameters({}).length, 0);
  assert.equal(validateMessageGeneralParameters(null).length, 0);
});

// ─── message.question@v1 ────────────────────────────────────────────────────

test("message.question: valid", () => {
  const errors = validateMessageQuestionParameters({
    question_text: "What is your name?",
    question_type: "open_ended"
  });
  assert.equal(errors.length, 0);
});

test("message.question: missing question_text", () => {
  const errors = validateMessageQuestionParameters({ question_type: "yes_no" });
  assert.ok(errors.some((e) => e.field === "question_text"));
});

test("message.question: invalid question_type", () => {
  const errors = validateMessageQuestionParameters({
    question_text: "test",
    question_type: "essay"
  });
  assert.ok(errors.some((e) => e.field === "question_type"));
});

test("message.question: multiple_choice needs options", () => {
  const errors = validateMessageQuestionParameters({
    question_text: "pick one",
    question_type: "multiple_choice",
    options: ["a"]
  });
  assert.ok(errors.some((e) => e.field === "options"));
});

test("message.question: null parameters", () => {
  const errors = validateMessageQuestionParameters(null);
  assert.ok(errors.length > 0);
});

// ─── task.create@v1 ─────────────────────────────────────────────────────────

test("task.create: valid", () => {
  const errors = validateTaskCreateParameters({ task_id: "t1" });
  assert.equal(errors.length, 0);
});

test("task.create: missing task_id", () => {
  const errors = validateTaskCreateParameters({});
  assert.ok(errors.some((e) => e.field === "task_id"));
});

test("task.create: invalid assignee URI", () => {
  const errors = validateTaskCreateParameters({ task_id: "t1", assignee: "not-a-uri" });
  assert.ok(errors.some((e) => e.field === "assignee"));
});

test("task.create: valid assignee", () => {
  const errors = validateTaskCreateParameters({ task_id: "t1", assignee: "loom://user@example.com" });
  assert.equal(errors.length, 0);
});

test("task.create: invalid due_date", () => {
  const errors = validateTaskCreateParameters({ task_id: "t1", due_date: "not-a-date" });
  assert.ok(errors.some((e) => e.field === "due_date"));
});

// ─── task.state_update@v1 ───────────────────────────────────────────────────

test("task.state_update: valid", () => {
  const errors = validateTaskStateUpdateParameters({ task_id: "t1", state: "completed" });
  assert.equal(errors.length, 0);
});

test("task.state_update: invalid state", () => {
  const errors = validateTaskStateUpdateParameters({ task_id: "t1", state: "unknown" });
  assert.ok(errors.some((e) => e.field === "state"));
});

// ─── approval.request@v1 ───────────────────────────────────────────────────

test("approval.request: valid", () => {
  const errors = validateApprovalRequestParameters({
    requester: "loom://alice",
    decision_options: ["approve", "reject"],
    deadline: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("approval.request: missing requester", () => {
  const errors = validateApprovalRequestParameters({
    decision_options: ["a", "b"],
    deadline: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "requester"));
});

test("approval.request: too few decision_options", () => {
  const errors = validateApprovalRequestParameters({
    requester: "alice",
    decision_options: ["only_one"],
    deadline: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "decision_options"));
});

// ─── approval.response@v1 ──────────────────────────────────────────────────

test("approval.response: valid", () => {
  const errors = validateApprovalResponseParameters({
    decision: "approve",
    decided_by: "alice",
    decision_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("approval.response: invalid decision", () => {
  const errors = validateApprovalResponseParameters({
    decision: "maybe",
    decided_by: "alice",
    decision_at: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "decision"));
});

// ─── schedule.meeting@v1 ───────────────────────────────────────────────────

test("schedule.meeting: valid", () => {
  const errors = validateScheduleMeetingParameters({
    start_time: "2025-06-01T10:00:00Z",
    end_time: "2025-06-01T11:00:00Z",
    attendees: ["alice", "bob"],
    location: "Conference Room A"
  });
  assert.equal(errors.length, 0);
});

test("schedule.meeting: end_time before start_time", () => {
  const errors = validateScheduleMeetingParameters({
    start_time: "2025-06-01T11:00:00Z",
    end_time: "2025-06-01T10:00:00Z",
    attendees: ["alice"],
    location: "Room"
  });
  assert.ok(errors.some((e) => e.field === "end_time"));
});

test("schedule.meeting: empty attendees", () => {
  const errors = validateScheduleMeetingParameters({
    start_time: "2025-06-01T10:00:00Z",
    end_time: "2025-06-01T11:00:00Z",
    attendees: [],
    location: "Room"
  });
  assert.ok(errors.some((e) => e.field === "attendees"));
});

// ─── schedule.confirm@v1 ───────────────────────────────────────────────────

test("schedule.confirm: valid", () => {
  const errors = validateScheduleConfirmParameters({
    meeting_id: "m1",
    confirmed_by: "alice",
    status: "confirmed",
    confirmed_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("schedule.confirm: invalid status", () => {
  const errors = validateScheduleConfirmParameters({
    meeting_id: "m1",
    confirmed_by: "alice",
    status: "maybe",
    confirmed_at: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "status"));
});

// ─── event.invite@v1 ────────────────────────────────────────────────────────

test("event.invite: valid", () => {
  const errors = validateEventInviteParameters({
    event_id: "e1",
    start_time: "2025-06-01T10:00:00Z",
    end_time: "2025-06-01T11:00:00Z",
    invitees: ["alice"],
    organizer: "bob"
  });
  assert.equal(errors.length, 0);
});

test("event.invite: missing organizer", () => {
  const errors = validateEventInviteParameters({
    event_id: "e1",
    start_time: "2025-06-01T10:00:00Z",
    end_time: "2025-06-01T11:00:00Z",
    invitees: ["alice"]
  });
  assert.ok(errors.some((e) => e.field === "organizer"));
});

// ─── event.rsvp@v1 ──────────────────────────────────────────────────────────

test("event.rsvp: valid", () => {
  const errors = validateEventRsvpParameters({
    event_id: "e1",
    response: "yes",
    respondent: "alice",
    responded_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("event.rsvp: invalid response", () => {
  const errors = validateEventRsvpParameters({
    event_id: "e1",
    response: "unsure",
    respondent: "alice",
    responded_at: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "response"));
});

// ─── handoff.transfer@v1 ───────────────────────────────────────────────────

test("handoff.transfer: valid", () => {
  const errors = validateHandoffTransferParameters({
    item_id: "i1",
    item_type: "task",
    transferring_from: "alice",
    transferring_to: "bob",
    transfer_reason: "vacation"
  });
  assert.equal(errors.length, 0);
});

test("handoff.transfer: invalid item_type", () => {
  const errors = validateHandoffTransferParameters({
    item_id: "i1",
    item_type: "widget",
    transferring_from: "alice",
    transferring_to: "bob",
    transfer_reason: "reason"
  });
  assert.ok(errors.some((e) => e.field === "item_type"));
});

// ─── handoff.accept@v1 ─────────────────────────────────────────────────────

test("handoff.accept: valid", () => {
  const errors = validateHandoffAcceptParameters({
    item_id: "i1",
    accepted_by: "bob",
    accepted_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("handoff.accept: missing accepted_by", () => {
  const errors = validateHandoffAcceptParameters({
    item_id: "i1",
    accepted_at: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "accepted_by"));
});

// ─── notification.system@v1 ─────────────────────────────────────────────────

test("notification.system: valid", () => {
  const errors = validateNotificationSystemParameters({
    severity: "info",
    system_code: "SYS_001"
  });
  assert.equal(errors.length, 0);
});

test("notification.system: invalid severity", () => {
  const errors = validateNotificationSystemParameters({
    severity: "fatal",
    system_code: "SYS_001"
  });
  assert.ok(errors.some((e) => e.field === "severity"));
});

// ─── notification.autoreply@v1 ──────────────────────────────────────────────

test("notification.autoreply: valid", () => {
  const errors = validateNotificationAutoreplyParameters({
    original_recipient: "loom://alice@example.com",
    triggered_by_envelope_id: "env_123"
  });
  assert.equal(errors.length, 0);
});

test("notification.autoreply: invalid frequency_limit", () => {
  const errors = validateNotificationAutoreplyParameters({
    original_recipient: "loom://alice",
    triggered_by_envelope_id: "env_123",
    frequency_limit: "twice"
  });
  assert.ok(errors.some((e) => e.field === "frequency_limit"));
});

// ─── receipt.delivered@v1 ───────────────────────────────────────────────────

test("receipt.delivered: valid", () => {
  const errors = validateReceiptDeliveredParameters({
    original_envelope_id: "env_1",
    timestamp: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("receipt.delivered: missing timestamp", () => {
  const errors = validateReceiptDeliveredParameters({
    original_envelope_id: "env_1"
  });
  assert.ok(errors.some((e) => e.field === "timestamp"));
});

// ─── receipt.read@v1 ────────────────────────────────────────────────────────

test("receipt.read: valid", () => {
  const errors = validateReceiptReadParameters({
    original_envelope_id: "env_1",
    read_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

// ─── receipt.failed@v1 ──────────────────────────────────────────────────────

test("receipt.failed: valid", () => {
  const errors = validateReceiptFailedParameters({
    original_envelope_id: "env_1",
    reason: "mailbox full",
    failed_at: "2025-01-01T00:00:00Z"
  });
  assert.equal(errors.length, 0);
});

test("receipt.failed: missing reason", () => {
  const errors = validateReceiptFailedParameters({
    original_envelope_id: "env_1",
    failed_at: "2025-01-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "reason"));
});

// ─── agent.negotiate@v1 ────────────────────────────────────────────────────

test("agent.negotiate: valid", () => {
  const errors = validateAgentNegotiateParameters({
    task_id: "t1",
    fitness_score: 0.95,
    current_load: 3,
    required_capabilities: ["code_review", "testing"]
  });
  assert.equal(errors.length, 0);
});

test("agent.negotiate: fitness_score out of range", () => {
  const errors = validateAgentNegotiateParameters({
    task_id: "t1",
    fitness_score: 1.5,
    current_load: 0,
    required_capabilities: ["a"]
  });
  assert.ok(errors.some((e) => e.field === "fitness_score"));
});

test("agent.negotiate: empty required_capabilities", () => {
  const errors = validateAgentNegotiateParameters({
    task_id: "t1",
    fitness_score: 0.5,
    current_load: 0,
    required_capabilities: []
  });
  assert.ok(errors.some((e) => e.field === "required_capabilities"));
});

test("agent.negotiate: negative current_load", () => {
  const errors = validateAgentNegotiateParameters({
    task_id: "t1",
    fitness_score: 0.5,
    current_load: -1,
    required_capabilities: ["a"]
  });
  assert.ok(errors.some((e) => e.field === "current_load"));
});

// ─── validateIntentParameters dispatcher ────────────────────────────────────

test("validateIntentParameters: dispatches to correct validator", () => {
  const errors = validateIntentParameters("task.create@v1", {});
  assert.ok(errors.some((e) => e.field === "task_id"));
});

test("validateIntentParameters: message.general passes with any params", () => {
  const errors = validateIntentParameters("message.general@v1", {});
  assert.equal(errors.length, 0);
});
