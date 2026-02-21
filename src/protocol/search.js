// ─── Search Helpers — Section 16.6 ──────────────────────────────────────────
//
// Filtering functions for thread/envelope search. E2EE threads are
// metadata-only searchable (labels, participants, subject — not content).

export function validateSearchQuery(query) {
  const errors = [];
  if (!query || typeof query !== "object") {
    errors.push({ field: "query", reason: "must be an object" });
    return errors;
  }

  if (query.q !== undefined && typeof query.q !== "string") {
    errors.push({ field: "q", reason: "must be a string if provided" });
  }

  if (query.intent !== undefined && typeof query.intent !== "string") {
    errors.push({ field: "intent", reason: "must be a string if provided" });
  }

  if (query.sender !== undefined && typeof query.sender !== "string") {
    errors.push({ field: "sender", reason: "must be a string if provided" });
  }

  if (query.labels !== undefined && !Array.isArray(query.labels)) {
    errors.push({ field: "labels", reason: "must be an array if provided" });
  }

  if (query.participant !== undefined && typeof query.participant !== "string") {
    errors.push({ field: "participant", reason: "must be a string if provided" });
  }

  if (query.after !== undefined && typeof query.after === "string" && !Number.isFinite(Date.parse(query.after))) {
    errors.push({ field: "after", reason: "must be a valid ISO 8601 timestamp" });
  }

  if (query.before !== undefined && typeof query.before === "string" && !Number.isFinite(Date.parse(query.before))) {
    errors.push({ field: "before", reason: "must be a valid ISO 8601 timestamp" });
  }

  if (query.limit !== undefined && (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 1000)) {
    errors.push({ field: "limit", reason: "must be an integer between 1 and 1000" });
  }

  return errors;
}

export function matchesEnvelopeQuery(envelope, query, threadContext = {}) {
  // Full-text search on cleartext human content
  if (query.q && typeof query.q === "string") {
    const text = envelope.content?.human?.text || "";
    const isEncrypted = envelope.content?.encrypted === true;
    // E2EE envelopes cannot be content-searched
    if (isEncrypted) return false;
    if (!text.toLowerCase().includes(query.q.toLowerCase())) return false;
  }

  // Intent matching (exact or prefix)
  if (query.intent) {
    const intent = envelope.content?.structured?.intent || "";
    if (query.intent.endsWith("*")) {
      if (!intent.startsWith(query.intent.slice(0, -1))) return false;
    } else if (intent !== query.intent) {
      return false;
    }
  }

  // Sender matching
  if (query.sender) {
    if (envelope.from?.identity !== query.sender) return false;
  }

  // Date range
  if (query.after) {
    const after = Date.parse(query.after);
    const created = Date.parse(envelope.created_at);
    if (Number.isFinite(after) && Number.isFinite(created) && created < after) return false;
  }

  if (query.before) {
    const before = Date.parse(query.before);
    const created = Date.parse(envelope.created_at);
    if (Number.isFinite(before) && Number.isFinite(created) && created >= before) return false;
  }

  return true;
}

export function matchesThreadQuery(thread, query) {
  // Label matching
  if (Array.isArray(query.labels) && query.labels.length > 0) {
    const threadLabels = thread.labels || [];
    const allMatch = query.labels.every((l) => threadLabels.includes(l));
    if (!allMatch) return false;
  }

  // Participant matching
  if (query.participant) {
    const participants = (thread.participants || []).map((p) => p.identity);
    if (!participants.includes(query.participant)) return false;
  }

  // Subject matching
  if (query.subject) {
    const subject = thread.subject || "";
    if (!subject.toLowerCase().includes(query.subject.toLowerCase())) return false;
  }

  return true;
}

export function searchEnvelopes(envelopes, threads, query) {
  const limit = query.limit || 50;
  const results = [];

  for (const envelope of envelopes) {
    if (results.length >= limit) break;

    const thread = threads.get(envelope.thread_id);
    const threadContext = thread || {};

    if (!matchesThreadQuery(threadContext, query)) continue;
    if (!matchesEnvelopeQuery(envelope, query, threadContext)) continue;

    results.push(envelope);
  }

  return results;
}
