// ─── Intent Parameter Validators — Appendix B Complete Registry ─────────────
//
// Each validator returns {field, reason}[] error arrays.
// Thread operations and workflow intents are validated in their own modules;
// this module covers message, task, approval, schedule, event, handoff,
// notification, receipt, and agent negotiation intents.

// ─── Helpers ────────────────────────────────────────────────────────────────

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isIso8601(value) {
  if (typeof value !== "string") return false;
  const d = Date.parse(value);
  return Number.isFinite(d);
}

function isLoomUri(value) {
  return typeof value === "string" && (value.startsWith("loom://") || value.startsWith("bridge://"));
}

function isArrayOfStrings(value) {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

// ─── INTENT REGISTRY ────────────────────────────────────────────────────────

export const INTENT_REGISTRY = Object.freeze({
  // Messages
  "message.general@v1": { type: "message", validator: validateMessageGeneralParameters },
  "message.question@v1": { type: "message", validator: validateMessageQuestionParameters },

  // Tasks
  "task.create@v1": { type: "task", validator: validateTaskCreateParameters },
  "task.state_update@v1": { type: "task", validator: validateTaskStateUpdateParameters },

  // Approvals
  "approval.request@v1": { type: "approval", validator: validateApprovalRequestParameters },
  "approval.response@v1": { type: "approval", validator: validateApprovalResponseParameters },

  // Scheduling
  "schedule.meeting@v1": { type: "event", validator: validateScheduleMeetingParameters },
  "schedule.confirm@v1": { type: "event", validator: validateScheduleConfirmParameters },

  // Events
  "event.invite@v1": { type: "event", validator: validateEventInviteParameters },
  "event.rsvp@v1": { type: "event", validator: validateEventRsvpParameters },

  // Handoff
  "handoff.transfer@v1": { type: "handoff", validator: validateHandoffTransferParameters },
  "handoff.accept@v1": { type: "handoff", validator: validateHandoffAcceptParameters },

  // Notifications
  "notification.system@v1": { type: "notification", validator: validateNotificationSystemParameters },
  "notification.autoreply@v1": { type: "notification", validator: validateNotificationAutoreplyParameters },

  // Receipts
  "receipt.delivered@v1": { type: "receipt", validator: validateReceiptDeliveredParameters },
  "receipt.read@v1": { type: "receipt", validator: validateReceiptReadParameters },
  "receipt.failed@v1": { type: "receipt", validator: validateReceiptFailedParameters },

  // Agent
  "agent.negotiate@v1": { type: "message", validator: validateAgentNegotiateParameters }
});

export function getIntentValidator(intent) {
  return INTENT_REGISTRY[intent] || null;
}

export function validateIntentParameters(intent, parameters) {
  const entry = INTENT_REGISTRY[intent];
  if (!entry || !entry.validator) {
    return []; // Unknown intents pass through — extensible by design
  }
  return entry.validator(parameters);
}

// ─── message.general@v1 ────────────────────────────────────────────────────

export function validateMessageGeneralParameters(_parameters) {
  // No required structured parameters — content.human.text carries the message
  return [];
}

// ─── message.question@v1 ───────────────────────────────────────────────────

const VALID_QUESTION_TYPES = new Set(["open_ended", "yes_no", "multiple_choice", "text", "numeric"]);

export function validateMessageQuestionParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.question_text)) {
    errors.push({ field: "question_text", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.question_type)) {
    errors.push({ field: "question_type", reason: "required non-empty string" });
  } else if (!VALID_QUESTION_TYPES.has(parameters.question_type)) {
    errors.push({ field: "question_type", reason: `must be one of: ${[...VALID_QUESTION_TYPES].join(", ")}` });
  }

  if (parameters.question_type === "multiple_choice" && parameters.options !== undefined) {
    if (!Array.isArray(parameters.options) || parameters.options.length < 2) {
      errors.push({ field: "options", reason: "must be an array with at least 2 choices for multiple_choice" });
    }
  }

  return errors;
}

// ─── task.create@v1 ────────────────────────────────────────────────────────

export function validateTaskCreateParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.task_id)) {
    errors.push({ field: "task_id", reason: "required non-empty string" });
  }

  if (parameters.assignee !== undefined && !isLoomUri(parameters.assignee)) {
    errors.push({ field: "assignee", reason: "must be a valid LOOM URI if provided" });
  }

  if (parameters.due_date !== undefined && !isIso8601(parameters.due_date)) {
    errors.push({ field: "due_date", reason: "must be a valid ISO 8601 timestamp if provided" });
  }

  return errors;
}

// ─── task.state_update@v1 ──────────────────────────────────────────────────

const VALID_TASK_STATES = new Set(["open", "in_progress", "blocked", "completed", "cancelled"]);

export function validateTaskStateUpdateParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.task_id)) {
    errors.push({ field: "task_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.state)) {
    errors.push({ field: "state", reason: "required non-empty string" });
  } else if (!VALID_TASK_STATES.has(parameters.state)) {
    errors.push({ field: "state", reason: `must be one of: ${[...VALID_TASK_STATES].join(", ")}` });
  }

  return errors;
}

// ─── approval.request@v1 ───────────────────────────────────────────────────

export function validateApprovalRequestParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.requester)) {
    errors.push({ field: "requester", reason: "required non-empty string" });
  }

  if (!Array.isArray(parameters.decision_options) || parameters.decision_options.length < 2) {
    errors.push({ field: "decision_options", reason: "required array with at least 2 options" });
  } else if (!parameters.decision_options.every((o) => typeof o === "string")) {
    errors.push({ field: "decision_options", reason: "all options must be strings" });
  }

  if (!isIso8601(parameters.deadline)) {
    errors.push({ field: "deadline", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── approval.response@v1 ──────────────────────────────────────────────────

const VALID_DECISIONS = new Set(["approve", "reject", "request_changes", "defer"]);

export function validateApprovalResponseParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.decision)) {
    errors.push({ field: "decision", reason: "required non-empty string" });
  } else if (!VALID_DECISIONS.has(parameters.decision)) {
    errors.push({ field: "decision", reason: `must be one of: ${[...VALID_DECISIONS].join(", ")}` });
  }

  if (!isNonEmptyString(parameters.decided_by)) {
    errors.push({ field: "decided_by", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.decision_at)) {
    errors.push({ field: "decision_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── schedule.meeting@v1 ───────────────────────────────────────────────────

export function validateScheduleMeetingParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isIso8601(parameters.start_time)) {
    errors.push({ field: "start_time", reason: "required valid ISO 8601 timestamp" });
  }

  if (!isIso8601(parameters.end_time)) {
    errors.push({ field: "end_time", reason: "required valid ISO 8601 timestamp" });
  }

  if (parameters.start_time && parameters.end_time && isIso8601(parameters.start_time) && isIso8601(parameters.end_time)) {
    if (Date.parse(parameters.start_time) >= Date.parse(parameters.end_time)) {
      errors.push({ field: "end_time", reason: "must be after start_time" });
    }
  }

  if (!Array.isArray(parameters.attendees) || parameters.attendees.length === 0) {
    errors.push({ field: "attendees", reason: "required non-empty array" });
  }

  if (!isNonEmptyString(parameters.location)) {
    errors.push({ field: "location", reason: "required non-empty string" });
  }

  return errors;
}

// ─── schedule.confirm@v1 ───────────────────────────────────────────────────

const VALID_CONFIRM_STATUS = new Set(["confirmed", "tentative", "declined"]);

export function validateScheduleConfirmParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.meeting_id)) {
    errors.push({ field: "meeting_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.confirmed_by)) {
    errors.push({ field: "confirmed_by", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.status)) {
    errors.push({ field: "status", reason: "required non-empty string" });
  } else if (!VALID_CONFIRM_STATUS.has(parameters.status)) {
    errors.push({ field: "status", reason: `must be one of: ${[...VALID_CONFIRM_STATUS].join(", ")}` });
  }

  if (!isIso8601(parameters.confirmed_at)) {
    errors.push({ field: "confirmed_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── event.invite@v1 ───────────────────────────────────────────────────────

export function validateEventInviteParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.event_id)) {
    errors.push({ field: "event_id", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.start_time)) {
    errors.push({ field: "start_time", reason: "required valid ISO 8601 timestamp" });
  }

  if (!isIso8601(parameters.end_time)) {
    errors.push({ field: "end_time", reason: "required valid ISO 8601 timestamp" });
  }

  if (parameters.start_time && parameters.end_time && isIso8601(parameters.start_time) && isIso8601(parameters.end_time)) {
    if (Date.parse(parameters.start_time) >= Date.parse(parameters.end_time)) {
      errors.push({ field: "end_time", reason: "must be after start_time" });
    }
  }

  if (!Array.isArray(parameters.invitees) || parameters.invitees.length === 0) {
    errors.push({ field: "invitees", reason: "required non-empty array" });
  }

  if (!isNonEmptyString(parameters.organizer)) {
    errors.push({ field: "organizer", reason: "required non-empty string" });
  }

  return errors;
}

// ─── event.rsvp@v1 ─────────────────────────────────────────────────────────

const VALID_RSVP_RESPONSES = new Set(["yes", "no", "maybe"]);

export function validateEventRsvpParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.event_id)) {
    errors.push({ field: "event_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.response)) {
    errors.push({ field: "response", reason: "required non-empty string" });
  } else if (!VALID_RSVP_RESPONSES.has(parameters.response)) {
    errors.push({ field: "response", reason: `must be one of: ${[...VALID_RSVP_RESPONSES].join(", ")}` });
  }

  if (!isNonEmptyString(parameters.respondent)) {
    errors.push({ field: "respondent", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.responded_at)) {
    errors.push({ field: "responded_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── handoff.transfer@v1 ───────────────────────────────────────────────────

const VALID_ITEM_TYPES = new Set(["task", "thread", "project", "case"]);

export function validateHandoffTransferParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.item_id)) {
    errors.push({ field: "item_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.item_type)) {
    errors.push({ field: "item_type", reason: "required non-empty string" });
  } else if (!VALID_ITEM_TYPES.has(parameters.item_type)) {
    errors.push({ field: "item_type", reason: `must be one of: ${[...VALID_ITEM_TYPES].join(", ")}` });
  }

  if (!isNonEmptyString(parameters.transferring_from)) {
    errors.push({ field: "transferring_from", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.transferring_to)) {
    errors.push({ field: "transferring_to", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.transfer_reason)) {
    errors.push({ field: "transfer_reason", reason: "required non-empty string" });
  }

  return errors;
}

// ─── handoff.accept@v1 ─────────────────────────────────────────────────────

export function validateHandoffAcceptParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.item_id)) {
    errors.push({ field: "item_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.accepted_by)) {
    errors.push({ field: "accepted_by", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.accepted_at)) {
    errors.push({ field: "accepted_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── notification.system@v1 ────────────────────────────────────────────────

const VALID_SEVERITIES = new Set(["info", "warning", "error", "critical"]);

export function validateNotificationSystemParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.severity)) {
    errors.push({ field: "severity", reason: "required non-empty string" });
  } else if (!VALID_SEVERITIES.has(parameters.severity)) {
    errors.push({ field: "severity", reason: `must be one of: ${[...VALID_SEVERITIES].join(", ")}` });
  }

  if (!isNonEmptyString(parameters.system_code)) {
    errors.push({ field: "system_code", reason: "required non-empty string" });
  }

  return errors;
}

// ─── notification.autoreply@v1 ──────────────────────────────────────────────

const VALID_FREQUENCY_LIMITS = new Set(["once_per_sender", "once_per_day", "unlimited"]);

export function validateNotificationAutoreplyParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.original_recipient)) {
    errors.push({ field: "original_recipient", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.triggered_by_envelope_id)) {
    errors.push({ field: "triggered_by_envelope_id", reason: "required non-empty string" });
  }

  if (parameters.frequency_limit !== undefined && !VALID_FREQUENCY_LIMITS.has(parameters.frequency_limit)) {
    errors.push({ field: "frequency_limit", reason: `must be one of: ${[...VALID_FREQUENCY_LIMITS].join(", ")}` });
  }

  if (parameters.schedule_start !== undefined && !isIso8601(parameters.schedule_start)) {
    errors.push({ field: "schedule_start", reason: "must be a valid ISO 8601 timestamp if provided" });
  }

  if (parameters.schedule_end !== undefined && !isIso8601(parameters.schedule_end)) {
    errors.push({ field: "schedule_end", reason: "must be a valid ISO 8601 timestamp if provided" });
  }

  return errors;
}

// ─── receipt.delivered@v1 ───────────────────────────────────────────────────

export function validateReceiptDeliveredParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.original_envelope_id)) {
    errors.push({ field: "original_envelope_id", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.timestamp)) {
    errors.push({ field: "timestamp", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── receipt.read@v1 ────────────────────────────────────────────────────────

export function validateReceiptReadParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.original_envelope_id)) {
    errors.push({ field: "original_envelope_id", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.read_at)) {
    errors.push({ field: "read_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── receipt.failed@v1 ──────────────────────────────────────────────────────

export function validateReceiptFailedParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.original_envelope_id)) {
    errors.push({ field: "original_envelope_id", reason: "required non-empty string" });
  }

  if (!isNonEmptyString(parameters.reason)) {
    errors.push({ field: "reason", reason: "required non-empty string" });
  }

  if (!isIso8601(parameters.failed_at)) {
    errors.push({ field: "failed_at", reason: "required valid ISO 8601 timestamp" });
  }

  return errors;
}

// ─── agent.negotiate@v1 ────────────────────────────────────────────────────

export function validateAgentNegotiateParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    errors.push({ field: "parameters", reason: "must be an object" });
    return errors;
  }

  if (!isNonEmptyString(parameters.task_id)) {
    errors.push({ field: "task_id", reason: "required non-empty string" });
  }

  if (typeof parameters.fitness_score !== "number" || parameters.fitness_score < 0 || parameters.fitness_score > 1) {
    errors.push({ field: "fitness_score", reason: "required number between 0.0 and 1.0" });
  }

  if (!Number.isInteger(parameters.current_load) || parameters.current_load < 0) {
    errors.push({ field: "current_load", reason: "required non-negative integer" });
  }

  if (!isArrayOfStrings(parameters.required_capabilities) || parameters.required_capabilities.length === 0) {
    errors.push({ field: "required_capabilities", reason: "required non-empty array of strings" });
  }

  return errors;
}
