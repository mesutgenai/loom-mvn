// ─── Channel Filtering & Rules Engine — Section 20.4 ────────────────────────
//
// Rule-based envelope routing. Rules MUST NOT modify signed content;
// only labels, routing, and metadata.

export const RULE_ACTIONS = Object.freeze({
  LABEL: "label",
  ROUTE: "route",
  DELEGATE: "delegate",
  ESCALATE: "escalate",
  QUARANTINE: "quarantine"
});

export function validateChannelRule(rule) {
  const errors = [];
  if (!rule || typeof rule !== "object") {
    errors.push({ field: "rule", reason: "must be an object" });
    return errors;
  }

  if (!rule.condition || typeof rule.condition !== "object") {
    errors.push({ field: "condition", reason: "required object" });
  }

  if (!rule.action || typeof rule.action !== "object") {
    errors.push({ field: "action", reason: "required object" });
  } else {
    if (!rule.action.type || typeof rule.action.type !== "string") {
      errors.push({ field: "action.type", reason: "required non-empty string" });
    }
  }

  if (rule.priority !== undefined && (typeof rule.priority !== "number" || !Number.isInteger(rule.priority))) {
    errors.push({ field: "priority", reason: "must be an integer if provided" });
  }

  return errors;
}

export function normalizeChannelRules(rules) {
  if (!Array.isArray(rules)) return [];
  return rules
    .filter((r) => r && typeof r === "object" && r.condition && r.action)
    .map((r) => ({
      id: r.id || null,
      condition: r.condition,
      action: r.action,
      priority: Number.isInteger(r.priority) ? r.priority : 0,
      enabled: r.enabled !== false
    }))
    .sort((a, b) => b.priority - a.priority); // Higher priority first
}

export function matchesCondition(envelope, condition) {
  // Intent matching
  if (condition.intent) {
    const intent = envelope.content?.structured?.intent || "";
    if (typeof condition.intent === "string") {
      if (condition.intent.endsWith("*")) {
        if (!intent.startsWith(condition.intent.slice(0, -1))) return false;
      } else if (intent !== condition.intent) {
        return false;
      }
    }
  }

  // Sender matching
  if (condition.sender) {
    const sender = envelope.from?.identity || "";
    if (typeof condition.sender === "string" && sender !== condition.sender) return false;
  }

  // Label matching (thread labels)
  if (Array.isArray(condition.labels) && condition.labels.length > 0) {
    const threadLabels = condition._thread_labels || [];
    const hasMatch = condition.labels.some((l) => threadLabels.includes(l));
    if (!hasMatch) return false;
  }

  // Priority matching
  if (condition.priority) {
    if (envelope.priority !== condition.priority) return false;
  }

  // Attachment type matching
  if (Array.isArray(condition.attachment_types) && condition.attachment_types.length > 0) {
    const attachments = Array.isArray(envelope.attachments) ? envelope.attachments : [];
    const mimeTypes = attachments.map((a) => a.mime_type || "");
    const hasMatch = condition.attachment_types.some((t) => mimeTypes.includes(t));
    if (!hasMatch) return false;
  }

  return true;
}

export function evaluateRules(envelope, rules, threadLabels = []) {
  const results = [];
  const activeRules = rules.filter((r) => r.enabled !== false);

  for (const rule of activeRules) {
    const conditionWithLabels = { ...rule.condition, _thread_labels: threadLabels };
    if (matchesCondition(envelope, conditionWithLabels)) {
      results.push(rule.action);
    }
  }

  return results;
}

export function applyRuleActions(actions) {
  const result = {
    labels_to_add: [],
    labels_to_remove: [],
    route_to: null,
    delegate_to: null,
    escalate: false,
    quarantine: false
  };

  for (const action of actions) {
    switch (action.type) {
      case RULE_ACTIONS.LABEL:
        if (action.add) result.labels_to_add.push(...(Array.isArray(action.add) ? action.add : [action.add]));
        if (action.remove) result.labels_to_remove.push(...(Array.isArray(action.remove) ? action.remove : [action.remove]));
        break;
      case RULE_ACTIONS.ROUTE:
        if (action.target) result.route_to = action.target;
        break;
      case RULE_ACTIONS.DELEGATE:
        if (action.target) result.delegate_to = action.target;
        break;
      case RULE_ACTIONS.ESCALATE:
        result.escalate = true;
        break;
      case RULE_ACTIONS.QUARANTINE:
        result.quarantine = true;
        result.labels_to_add.push("sys.quarantine");
        break;
    }
  }

  return result;
}
