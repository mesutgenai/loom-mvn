// ─── WebSocket Real-Time Protocol — Section 17 ─────────────────────────────
//
// Resume/cursor semantics, event types, subscription management.

export const WS_EVENT_TYPES = Object.freeze({
  ENVELOPE_NEW: "envelope.new",
  ENVELOPE_RETRACTED: "envelope.retracted",
  THREAD_UPDATED: "thread.updated",
  THREAD_FORK: "thread.fork",
  THREAD_MERGED: "thread.merged",
  PARTICIPANT_JOINED: "participant.joined",
  PARTICIPANT_LEFT: "participant.left",
  PRESENCE_UPDATE: "presence.update",
  CAPABILITY_REVOKED: "capability.revoked",
  DELEGATION_REVOKED: "delegation.revoked",
  RECEIPT_DELIVERED: "receipt.delivered",
  RECEIPT_READ: "receipt.read",
  RECEIPT_FAILED: "receipt.failed",
  TYPING_START: "typing.start",
  TYPING_STOP: "typing.stop"
});

export const WS_CHANNEL_TYPES = Object.freeze({
  ALL_THREADS: "all_threads",
  THREAD: "thread",
  TYPING: "typing"
});

export function validateSubscribeMessage(message) {
  const errors = [];
  if (!message || typeof message !== "object") {
    errors.push({ field: "message", reason: "must be an object" });
    return errors;
  }

  if (message.action !== "subscribe") {
    errors.push({ field: "action", reason: 'must be "subscribe"' });
  }

  if (!Array.isArray(message.channels) || message.channels.length === 0) {
    errors.push({ field: "channels", reason: "required non-empty array" });
  } else {
    for (let i = 0; i < message.channels.length; i++) {
      const ch = message.channels[i];
      if (!ch || typeof ch !== "object") {
        errors.push({ field: `channels[${i}]`, reason: "must be an object" });
        continue;
      }
      if (!ch.type) {
        errors.push({ field: `channels[${i}].type`, reason: "required" });
      }
      if (ch.type === "thread" && !ch.thread_id) {
        errors.push({ field: `channels[${i}].thread_id`, reason: "required for thread channel" });
      }
    }
  }

  if (message.since !== undefined && typeof message.since !== "string") {
    errors.push({ field: "since", reason: "must be a string event_id if provided" });
  }

  return errors;
}

export function validateAckMessage(message) {
  const errors = [];
  if (!message || typeof message !== "object") {
    errors.push({ field: "message", reason: "must be an object" });
    return errors;
  }

  if (message.action !== "ack") {
    errors.push({ field: "action", reason: 'must be "ack"' });
  }

  if (!message.cursor || typeof message.cursor !== "string") {
    errors.push({ field: "cursor", reason: "required string" });
  }

  return errors;
}

export function createEventLog(maxRetentionMs = 7 * 24 * 60 * 60 * 1000) {
  return {
    events: [],
    max_retention_ms: maxRetentionMs
  };
}

export function appendEvent(eventLog, { type, payload }) {
  const event = {
    event_id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    cursor: null,
    type,
    timestamp: new Date().toISOString(),
    payload
  };
  event.cursor = event.event_id;
  eventLog.events.push(event);
  return event;
}

export function getEventsSince(eventLog, sinceEventId) {
  if (!sinceEventId) return eventLog.events.slice();

  const idx = eventLog.events.findIndex((e) => e.event_id === sinceEventId);
  if (idx < 0) return eventLog.events.slice(); // cursor not found — return all
  return eventLog.events.slice(idx + 1);
}

export function pruneEventLog(eventLog, now = Date.now()) {
  const cutoff = now - eventLog.max_retention_ms;
  eventLog.events = eventLog.events.filter((e) => {
    const ts = Date.parse(e.timestamp);
    return Number.isFinite(ts) && ts > cutoff;
  });
}

export function deduplicateEvents(events) {
  const seen = new Set();
  return events.filter((e) => {
    if (seen.has(e.event_id)) return false;
    seen.add(e.event_id);
    return true;
  });
}
