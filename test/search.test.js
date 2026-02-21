import test from "node:test";
import assert from "node:assert/strict";

import {
  validateSearchQuery,
  matchesEnvelopeQuery,
  matchesThreadQuery,
  searchEnvelopes
} from "../src/protocol/search.js";

// ─── validateSearchQuery ───────────────────────────────────────────────────

test("validateSearchQuery: valid query", () => {
  const errors = validateSearchQuery({
    q: "hello",
    intent: "message.general@v1",
    sender: "loom://alice",
    labels: ["inbox"],
    limit: 50
  });
  assert.equal(errors.length, 0);
});

test("validateSearchQuery: invalid q type", () => {
  const errors = validateSearchQuery({ q: 123 });
  assert.ok(errors.some((e) => e.field === "q"));
});

test("validateSearchQuery: invalid labels type", () => {
  const errors = validateSearchQuery({ labels: "not-array" });
  assert.ok(errors.some((e) => e.field === "labels"));
});

test("validateSearchQuery: limit out of range", () => {
  assert.ok(validateSearchQuery({ limit: 0 }).some((e) => e.field === "limit"));
  assert.ok(validateSearchQuery({ limit: 1001 }).some((e) => e.field === "limit"));
});

test("validateSearchQuery: invalid date", () => {
  const errors = validateSearchQuery({ after: "not-a-date" });
  assert.ok(errors.some((e) => e.field === "after"));
});

test("validateSearchQuery: null input", () => {
  const errors = validateSearchQuery(null);
  assert.ok(errors.length > 0);
});

// ─── matchesEnvelopeQuery ──────────────────────────────────────────────────

test("matchesEnvelopeQuery: full-text match", () => {
  const envelope = { content: { human: { text: "Hello World" }, encrypted: false } };
  assert.equal(matchesEnvelopeQuery(envelope, { q: "hello" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { q: "missing" }), false);
});

test("matchesEnvelopeQuery: E2EE envelopes cannot be content-searched", () => {
  const envelope = { content: { human: { text: "secret" }, encrypted: true } };
  assert.equal(matchesEnvelopeQuery(envelope, { q: "secret" }), false);
});

test("matchesEnvelopeQuery: intent exact match", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  assert.equal(matchesEnvelopeQuery(envelope, { intent: "task.create@v1" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { intent: "message.general@v1" }), false);
});

test("matchesEnvelopeQuery: intent prefix match", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  assert.equal(matchesEnvelopeQuery(envelope, { intent: "task.*" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { intent: "msg.*" }), false);
});

test("matchesEnvelopeQuery: sender match", () => {
  const envelope = { from: { identity: "loom://alice" } };
  assert.equal(matchesEnvelopeQuery(envelope, { sender: "loom://alice" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { sender: "loom://bob" }), false);
});

test("matchesEnvelopeQuery: date range filtering", () => {
  const envelope = { created_at: "2025-06-15T12:00:00Z" };
  assert.equal(matchesEnvelopeQuery(envelope, { after: "2025-06-01T00:00:00Z" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { after: "2025-07-01T00:00:00Z" }), false);
  assert.equal(matchesEnvelopeQuery(envelope, { before: "2025-07-01T00:00:00Z" }), true);
  assert.equal(matchesEnvelopeQuery(envelope, { before: "2025-06-01T00:00:00Z" }), false);
});

test("matchesEnvelopeQuery: empty query matches all", () => {
  assert.equal(matchesEnvelopeQuery({}, {}), true);
});

// ─── matchesThreadQuery ────────────────────────────────────────────────────

test("matchesThreadQuery: label match (all required)", () => {
  const thread = { labels: ["inbox", "urgent"] };
  assert.equal(matchesThreadQuery(thread, { labels: ["inbox"] }), true);
  assert.equal(matchesThreadQuery(thread, { labels: ["inbox", "urgent"] }), true);
  assert.equal(matchesThreadQuery(thread, { labels: ["inbox", "missing"] }), false);
});

test("matchesThreadQuery: participant match", () => {
  const thread = { participants: [{ identity: "loom://alice" }, { identity: "loom://bob" }] };
  assert.equal(matchesThreadQuery(thread, { participant: "loom://alice" }), true);
  assert.equal(matchesThreadQuery(thread, { participant: "loom://carol" }), false);
});

test("matchesThreadQuery: subject match (case insensitive)", () => {
  const thread = { subject: "Project Update Q3" };
  assert.equal(matchesThreadQuery(thread, { subject: "project" }), true);
  assert.equal(matchesThreadQuery(thread, { subject: "unrelated" }), false);
});

test("matchesThreadQuery: empty query matches all", () => {
  assert.equal(matchesThreadQuery({}, {}), true);
});

// ─── searchEnvelopes ───────────────────────────────────────────────────────

test("searchEnvelopes: combines thread and envelope filtering", () => {
  const threads = new Map([
    ["thr_1", { labels: ["inbox"], participants: [{ identity: "loom://alice" }] }],
    ["thr_2", { labels: ["spam"], participants: [{ identity: "loom://bob" }] }]
  ]);
  const envelopes = [
    { id: "e1", thread_id: "thr_1", from: { identity: "loom://alice" }, content: { human: { text: "hello" } } },
    { id: "e2", thread_id: "thr_2", from: { identity: "loom://bob" }, content: { human: { text: "hello" } } }
  ];

  const results = searchEnvelopes(envelopes, threads, { labels: ["inbox"], q: "hello" });
  assert.equal(results.length, 1);
  assert.equal(results[0].id, "e1");
});

test("searchEnvelopes: respects limit", () => {
  const threads = new Map([["thr_1", { labels: [] }]]);
  const envelopes = Array.from({ length: 100 }, (_, i) => ({
    id: `e${i}`,
    thread_id: "thr_1",
    content: { human: { text: "test" } }
  }));

  const results = searchEnvelopes(envelopes, threads, { limit: 5 });
  assert.equal(results.length, 5);
});

test("searchEnvelopes: default limit is 50", () => {
  const threads = new Map([["thr_1", { labels: [] }]]);
  const envelopes = Array.from({ length: 100 }, (_, i) => ({
    id: `e${i}`,
    thread_id: "thr_1",
    content: {}
  }));

  const results = searchEnvelopes(envelopes, threads, {});
  assert.equal(results.length, 50);
});
