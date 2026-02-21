import test from "node:test";
import assert from "node:assert/strict";

import {
  WS_EVENT_TYPES,
  WS_CHANNEL_TYPES,
  validateSubscribeMessage,
  validateAckMessage,
  createEventLog,
  appendEvent,
  getEventsSince,
  pruneEventLog,
  deduplicateEvents
} from "../src/protocol/websocket.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("WS_EVENT_TYPES contains all 15 event types", () => {
  assert.equal(Object.keys(WS_EVENT_TYPES).length, 15);
  assert.equal(WS_EVENT_TYPES.ENVELOPE_NEW, "envelope.new");
  assert.equal(WS_EVENT_TYPES.TYPING_START, "typing.start");
  assert.equal(WS_EVENT_TYPES.TYPING_STOP, "typing.stop");
  assert.equal(WS_EVENT_TYPES.RECEIPT_DELIVERED, "receipt.delivered");
});

test("WS_CHANNEL_TYPES has all channel types", () => {
  assert.equal(WS_CHANNEL_TYPES.ALL_THREADS, "all_threads");
  assert.equal(WS_CHANNEL_TYPES.THREAD, "thread");
  assert.equal(WS_CHANNEL_TYPES.TYPING, "typing");
});

// ─── validateSubscribeMessage ──────────────────────────────────────────────

test("validateSubscribeMessage: valid message", () => {
  const errors = validateSubscribeMessage({
    action: "subscribe",
    channels: [{ type: "all_threads" }]
  });
  assert.equal(errors.length, 0);
});

test("validateSubscribeMessage: wrong action", () => {
  const errors = validateSubscribeMessage({
    action: "unsubscribe",
    channels: [{ type: "all_threads" }]
  });
  assert.ok(errors.some((e) => e.field === "action"));
});

test("validateSubscribeMessage: empty channels", () => {
  const errors = validateSubscribeMessage({
    action: "subscribe",
    channels: []
  });
  assert.ok(errors.some((e) => e.field === "channels"));
});

test("validateSubscribeMessage: thread channel requires thread_id", () => {
  const errors = validateSubscribeMessage({
    action: "subscribe",
    channels: [{ type: "thread" }]
  });
  assert.ok(errors.some((e) => e.field.includes("thread_id")));
});

test("validateSubscribeMessage: thread channel with thread_id passes", () => {
  const errors = validateSubscribeMessage({
    action: "subscribe",
    channels: [{ type: "thread", thread_id: "thr_1" }]
  });
  assert.equal(errors.length, 0);
});

test("validateSubscribeMessage: since must be string", () => {
  const errors = validateSubscribeMessage({
    action: "subscribe",
    channels: [{ type: "all_threads" }],
    since: 12345
  });
  assert.ok(errors.some((e) => e.field === "since"));
});

test("validateSubscribeMessage: null input", () => {
  const errors = validateSubscribeMessage(null);
  assert.ok(errors.length > 0);
});

// ─── validateAckMessage ────────────────────────────────────────────────────

test("validateAckMessage: valid", () => {
  const errors = validateAckMessage({ action: "ack", cursor: "evt_123" });
  assert.equal(errors.length, 0);
});

test("validateAckMessage: wrong action", () => {
  const errors = validateAckMessage({ action: "nack", cursor: "x" });
  assert.ok(errors.some((e) => e.field === "action"));
});

test("validateAckMessage: missing cursor", () => {
  const errors = validateAckMessage({ action: "ack" });
  assert.ok(errors.some((e) => e.field === "cursor"));
});

// ─── Event Log ─────────────────────────────────────────────────────────────

test("createEventLog: creates empty log", () => {
  const log = createEventLog();
  assert.deepEqual(log.events, []);
  assert.equal(log.max_retention_ms, 7 * 24 * 60 * 60 * 1000);
});

test("createEventLog: custom retention", () => {
  const log = createEventLog(3600000);
  assert.equal(log.max_retention_ms, 3600000);
});

test("appendEvent: adds event with cursor", () => {
  const log = createEventLog();
  const event = appendEvent(log, {
    type: WS_EVENT_TYPES.ENVELOPE_NEW,
    payload: { envelope_id: "env_1", thread_id: "thr_1" }
  });
  assert.ok(event.event_id);
  assert.equal(event.cursor, event.event_id);
  assert.equal(event.type, "envelope.new");
  assert.ok(event.timestamp);
  assert.equal(event.payload.envelope_id, "env_1");
  assert.equal(log.events.length, 1);
});

test("getEventsSince: returns all events when no cursor", () => {
  const log = createEventLog();
  appendEvent(log, { type: "x", payload: {} });
  appendEvent(log, { type: "y", payload: {} });
  const events = getEventsSince(log, null);
  assert.equal(events.length, 2);
});

test("getEventsSince: returns events after cursor", () => {
  const log = createEventLog();
  const e1 = appendEvent(log, { type: "a", payload: {} });
  appendEvent(log, { type: "b", payload: {} });
  appendEvent(log, { type: "c", payload: {} });

  const events = getEventsSince(log, e1.event_id);
  assert.equal(events.length, 2);
  assert.equal(events[0].type, "b");
});

test("getEventsSince: returns all if cursor not found", () => {
  const log = createEventLog();
  appendEvent(log, { type: "a", payload: {} });
  const events = getEventsSince(log, "nonexistent");
  assert.equal(events.length, 1);
});

test("pruneEventLog: removes old events", () => {
  const log = createEventLog(1000); // 1 second retention
  const event = appendEvent(log, { type: "old", payload: {} });
  // Backdate the timestamp
  event.timestamp = new Date(Date.now() - 5000).toISOString();

  pruneEventLog(log);
  assert.equal(log.events.length, 0);
});

test("pruneEventLog: keeps recent events", () => {
  const log = createEventLog(60000);
  appendEvent(log, { type: "recent", payload: {} });
  pruneEventLog(log);
  assert.equal(log.events.length, 1);
});

test("deduplicateEvents: removes duplicates", () => {
  const events = [
    { event_id: "a", type: "x" },
    { event_id: "b", type: "y" },
    { event_id: "a", type: "x" } // duplicate
  ];
  const deduped = deduplicateEvents(events);
  assert.equal(deduped.length, 2);
});

test("deduplicateEvents: preserves order", () => {
  const events = [
    { event_id: "c", type: "z" },
    { event_id: "a", type: "x" },
    { event_id: "b", type: "y" }
  ];
  const deduped = deduplicateEvents(events);
  assert.equal(deduped[0].event_id, "c");
  assert.equal(deduped[1].event_id, "a");
  assert.equal(deduped[2].event_id, "b");
});
