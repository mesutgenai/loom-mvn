import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_INDEX_OPTIONS,
  createSearchIndex,
  tokenizeText,
  indexEnvelope,
  removeEnvelope,
  rebuildIndex,
  clearIndex,
  queryIndex,
  getIndexStats
} from "../src/protocol/search_index.js";

function makeEnvelope(overrides = {}) {
  return {
    id: overrides.id || `env_${Math.random().toString(36).slice(2)}`,
    thread_id: overrides.thread_id || "thr_001",
    type: overrides.type || "message",
    from: { identity: overrides.sender || "loom://alice@example.com", type: "human" },
    content: overrides.content || { human: { text: overrides.text || "Hello world from Alice" } },
    created_at: overrides.created_at || "2025-03-15T10:00:00Z",
    ...(overrides.extra || {})
  };
}

// ─── createSearchIndex ──────────────────────────────────────────────────────

test("createSearchIndex returns empty index with defaults", () => {
  const idx = createSearchIndex();
  assert.equal(idx.entryCount, 0);
  assert.equal(idx.options.max_entries, 100000);
});

test("createSearchIndex accepts custom options", () => {
  const idx = createSearchIndex({ max_entries: 50 });
  assert.equal(idx.options.max_entries, 50);
});

test("createSearchIndex empty stats", () => {
  const idx = createSearchIndex();
  const stats = getIndexStats(idx);
  assert.equal(stats.entry_count, 0);
  assert.equal(stats.term_count, 0);
  assert.equal(stats.utilization_pct, 0);
});

test("DEFAULT_INDEX_OPTIONS is frozen", () => {
  assert.ok(Object.isFrozen(DEFAULT_INDEX_OPTIONS));
  assert.ok(Object.isFrozen(DEFAULT_INDEX_OPTIONS.stop_words));
});

// ─── tokenizeText ───────────────────────────────────────────────────────────

test("tokenizeText splits on whitespace", () => {
  const tokens = tokenizeText("hello world test");
  assert.ok(tokens.includes("hello"));
  assert.ok(tokens.includes("world"));
  assert.ok(tokens.includes("test"));
});

test("tokenizeText lowercases tokens", () => {
  const tokens = tokenizeText("Hello WORLD");
  assert.ok(tokens.includes("hello"));
  assert.ok(tokens.includes("world"));
});

test("tokenizeText removes stop words", () => {
  const tokens = tokenizeText("the quick brown fox is running");
  assert.ok(!tokens.includes("the"));
  assert.ok(!tokens.includes("is"));
  assert.ok(tokens.includes("quick"));
  assert.ok(tokens.includes("brown"));
  assert.ok(tokens.includes("fox"));
});

test("tokenizeText filters by min length", () => {
  const tokens = tokenizeText("I am here now");
  assert.ok(!tokens.includes("i"));
  assert.ok(tokens.includes("am"));
  assert.ok(tokens.includes("here"));
  assert.ok(tokens.includes("now"));
});

test("tokenizeText handles punctuation", () => {
  const tokens = tokenizeText("hello, world! how are you?");
  assert.ok(tokens.includes("hello"));
  assert.ok(tokens.includes("world"));
  assert.ok(tokens.includes("how"));
  assert.ok(tokens.includes("you"));
});

test("tokenizeText returns empty for null", () => {
  assert.deepEqual(tokenizeText(null), []);
  assert.deepEqual(tokenizeText(""), []);
  assert.deepEqual(tokenizeText(undefined), []);
});

test("tokenizeText deduplicates", () => {
  const tokens = tokenizeText("hello hello hello world");
  assert.equal(tokens.filter((t) => t === "hello").length, 1);
});

test("tokenizeText handles numbers", () => {
  const tokens = tokenizeText("version 123 release");
  assert.ok(tokens.includes("123"));
  assert.ok(tokens.includes("version"));
});

test("tokenizeText handles mixed content", () => {
  const tokens = tokenizeText("Error: file_not_found at line 42");
  assert.ok(tokens.includes("error"));
  assert.ok(tokens.includes("file_not_found"));
  assert.ok(tokens.includes("line"));
  assert.ok(tokens.includes("42"));
});

test("tokenizeText filters long tokens", () => {
  const longWord = "a".repeat(81);
  const tokens = tokenizeText(`hello ${longWord} world`);
  assert.ok(!tokens.includes(longWord));
  assert.ok(tokens.includes("hello"));
});

// ─── indexEnvelope ──────────────────────────────────────────────────────────

test("indexEnvelope indexes into all maps", () => {
  const idx = createSearchIndex();
  const env = makeEnvelope({
    id: "env_001",
    sender: "loom://alice@test.com",
    thread_id: "thr_100",
    type: "message",
    text: "important meeting tomorrow"
  });
  const result = indexEnvelope(idx, env);
  assert.equal(result.indexed, true);
  assert.equal(result.evicted, null);
  assert.equal(idx.entryCount, 1);
  assert.ok(idx.bySender.get("loom://alice@test.com").has("env_001"));
  assert.ok(idx.byThreadId.get("thr_100").has("env_001"));
  assert.ok(idx.byType.get("message").has("env_001"));
  assert.ok(idx.byTerm.get("important").has("env_001"));
  assert.ok(idx.byTerm.get("meeting").has("env_001"));
  assert.ok(idx.byTerm.get("tomorrow").has("env_001"));
});

test("indexEnvelope is idempotent", () => {
  const idx = createSearchIndex();
  const env = makeEnvelope({ id: "env_001" });
  indexEnvelope(idx, env);
  const result = indexEnvelope(idx, env);
  assert.equal(result.indexed, false);
  assert.equal(idx.entryCount, 1);
});

test("indexEnvelope skips encrypted content", () => {
  const idx = createSearchIndex();
  const env = makeEnvelope({
    id: "env_enc",
    content: { encrypted: { ciphertext: "abc" } }
  });
  indexEnvelope(idx, env);
  assert.equal(idx.byTerm.size, 0);
  assert.equal(idx.reverseTerms.get("env_enc").size, 0);
});

test("indexEnvelope handles missing fields gracefully", () => {
  const idx = createSearchIndex();
  const env = { id: "env_minimal" };
  const result = indexEnvelope(idx, env);
  assert.equal(result.indexed, true);
  assert.equal(idx.entryCount, 1);
});

test("indexEnvelope handles null envelope", () => {
  const idx = createSearchIndex();
  const result = indexEnvelope(idx, null);
  assert.equal(result.indexed, false);
});

test("indexEnvelope handles envelope without id", () => {
  const idx = createSearchIndex();
  const result = indexEnvelope(idx, { type: "message" });
  assert.equal(result.indexed, false);
});

test("indexEnvelope populates date bucket", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_d1", created_at: "2025-03-15T10:00:00Z" }));
  assert.ok(idx.byDateBucket.get("2025-03-15").has("env_d1"));
});

test("indexEnvelope indexes intent", () => {
  const idx = createSearchIndex();
  const env = makeEnvelope({
    id: "env_intent",
    content: { structured: { intent: "task.assign" }, human: { text: "please do this" } }
  });
  indexEnvelope(idx, env);
  assert.ok(idx.byIntent.get("task.assign").has("env_intent"));
});

test("indexEnvelope indexes multiple envelopes same sender", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_a1", sender: "loom://bob@test.com" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_a2", sender: "loom://bob@test.com" }));
  assert.equal(idx.bySender.get("loom://bob@test.com").size, 2);
});

test("indexEnvelope increments entry count", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_c1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_c2" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_c3" }));
  assert.equal(idx.entryCount, 3);
});

test("indexEnvelope stores reverse terms", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_rt", text: "unique keyword here" }));
  const terms = idx.reverseTerms.get("env_rt");
  assert.ok(terms.has("unique"));
  assert.ok(terms.has("keyword"));
  assert.ok(terms.has("here"));
});

// ─── removeEnvelope ─────────────────────────────────────────────────────────

test("removeEnvelope removes from all maps", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_rm", sender: "loom://x@y.com", text: "special word" }));
  assert.equal(idx.entryCount, 1);

  const result = removeEnvelope(idx, "env_rm");
  assert.equal(result.removed, true);
  assert.equal(idx.entryCount, 0);
  assert.equal(idx.bySender.has("loom://x@y.com"), false);
  assert.equal(idx.byTerm.has("special"), false);
  assert.equal(idx.reverseTerms.has("env_rm"), false);
  assert.equal(idx.envelopeMeta.has("env_rm"), false);
});

test("removeEnvelope returns false for non-existent", () => {
  const idx = createSearchIndex();
  const result = removeEnvelope(idx, "env_nonexistent");
  assert.equal(result.removed, false);
});

test("removeEnvelope decrements entry count", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_d1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_d2" }));
  removeEnvelope(idx, "env_d1");
  assert.equal(idx.entryCount, 1);
});

test("removeEnvelope cleans entryOrder", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_o1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_o2" }));
  removeEnvelope(idx, "env_o1");
  assert.ok(!idx.entryOrder.includes("env_o1"));
  assert.ok(idx.entryOrder.includes("env_o2"));
});

test("removeEnvelope preserves other entries in shared maps", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_s1", sender: "loom://shared@x.com" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_s2", sender: "loom://shared@x.com" }));
  removeEnvelope(idx, "env_s1");
  assert.ok(idx.bySender.get("loom://shared@x.com").has("env_s2"));
  assert.ok(!idx.bySender.get("loom://shared@x.com").has("env_s1"));
});

test("removeEnvelope handles null id", () => {
  const idx = createSearchIndex();
  const result = removeEnvelope(idx, null);
  assert.equal(result.removed, false);
});

test("removeEnvelope removes date bucket entry", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_db", created_at: "2025-01-01T00:00:00Z" }));
  removeEnvelope(idx, "env_db");
  assert.equal(idx.byDateBucket.has("2025-01-01"), false);
});

// ─── LRU eviction ───────────────────────────────────────────────────────────

test("LRU evicts oldest when at capacity", () => {
  const idx = createSearchIndex({ max_entries: 3 });
  indexEnvelope(idx, makeEnvelope({ id: "env_e1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_e2" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_e3" }));
  const result = indexEnvelope(idx, makeEnvelope({ id: "env_e4" }));
  assert.equal(result.evicted, "env_e1");
  assert.equal(idx.entryCount, 3);
  assert.ok(!idx.envelopeMeta.has("env_e1"));
  assert.ok(idx.envelopeMeta.has("env_e4"));
});

test("LRU evicted entry removed from all maps", () => {
  const idx = createSearchIndex({ max_entries: 2 });
  indexEnvelope(idx, makeEnvelope({ id: "env_lru1", sender: "loom://unique@test.com", text: "rarterm" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_lru2" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_lru3" }));
  assert.equal(idx.bySender.has("loom://unique@test.com"), false);
  assert.equal(idx.byTerm.has("rarterm"), false);
});

test("LRU eviction preserves newer entries", () => {
  const idx = createSearchIndex({ max_entries: 2 });
  indexEnvelope(idx, makeEnvelope({ id: "env_p1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_p2" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_p3" }));
  assert.ok(!idx.envelopeMeta.has("env_p1"));
  assert.ok(idx.envelopeMeta.has("env_p2"));
  assert.ok(idx.envelopeMeta.has("env_p3"));
});

test("LRU no eviction at exactly max_entries", () => {
  const idx = createSearchIndex({ max_entries: 3 });
  indexEnvelope(idx, makeEnvelope({ id: "env_b1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_b2" }));
  const result = indexEnvelope(idx, makeEnvelope({ id: "env_b3" }));
  assert.equal(result.evicted, null);
  assert.equal(idx.entryCount, 3);
});

test("LRU multiple evictions in sequence", () => {
  const idx = createSearchIndex({ max_entries: 1 });
  indexEnvelope(idx, makeEnvelope({ id: "env_seq1" }));
  const r2 = indexEnvelope(idx, makeEnvelope({ id: "env_seq2" }));
  assert.equal(r2.evicted, "env_seq1");
  const r3 = indexEnvelope(idx, makeEnvelope({ id: "env_seq3" }));
  assert.equal(r3.evicted, "env_seq2");
  assert.equal(idx.entryCount, 1);
});

test("LRU with max_entries=1 keeps only latest", () => {
  const idx = createSearchIndex({ max_entries: 1 });
  indexEnvelope(idx, makeEnvelope({ id: "env_one1" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_one2" }));
  assert.equal(idx.entryCount, 1);
  assert.ok(idx.envelopeMeta.has("env_one2"));
});

// ─── rebuildIndex ───────────────────────────────────────────────────────────

test("rebuildIndex clears and reindexes", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_old" }));
  const envelopes = [makeEnvelope({ id: "env_r1" }), makeEnvelope({ id: "env_r2" })];
  const result = rebuildIndex(idx, envelopes);
  assert.equal(result.indexed_count, 2);
  assert.equal(idx.entryCount, 2);
  assert.ok(!idx.envelopeMeta.has("env_old"));
});

test("rebuildIndex respects max_entries", () => {
  const idx = createSearchIndex({ max_entries: 2 });
  const envelopes = [
    makeEnvelope({ id: "env_rb1" }),
    makeEnvelope({ id: "env_rb2" }),
    makeEnvelope({ id: "env_rb3" })
  ];
  const result = rebuildIndex(idx, envelopes);
  assert.equal(idx.entryCount, 2);
  assert.ok(result.evicted_count > 0);
});

test("rebuildIndex handles empty list", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_pre" }));
  rebuildIndex(idx, []);
  assert.equal(idx.entryCount, 0);
});

test("rebuildIndex handles null input", () => {
  const idx = createSearchIndex();
  rebuildIndex(idx, null);
  assert.equal(idx.entryCount, 0);
});

// ─── clearIndex ─────────────────────────────────────────────────────────────

test("clearIndex empties all maps", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_cl1", text: "some content" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_cl2", text: "more content" }));
  clearIndex(idx);
  assert.equal(idx.entryCount, 0);
  assert.equal(idx.byTerm.size, 0);
  assert.equal(idx.bySender.size, 0);
  assert.equal(idx.entryOrder.length, 0);
});

test("clearIndex stats reflect empty state", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_cs1" }));
  clearIndex(idx);
  const stats = getIndexStats(idx);
  assert.equal(stats.entry_count, 0);
  assert.equal(stats.utilization_pct, 0);
});

// ─── queryIndex ─────────────────────────────────────────────────────────────

test("queryIndex by sender", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_q1", sender: "loom://alice@x.com" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_q2", sender: "loom://bob@x.com" }));
  const result = queryIndex(idx, { sender: "loom://alice@x.com" });
  assert.deepEqual(result.candidate_ids, ["env_q1"]);
  assert.ok(result.strategy.includes("sender"));
});

test("queryIndex by intent", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({
    id: "env_qi1",
    content: { structured: { intent: "task.create" }, human: { text: "create task" } }
  }));
  indexEnvelope(idx, makeEnvelope({ id: "env_qi2" }));
  const result = queryIndex(idx, { intent: "task.create" });
  assert.deepEqual(result.candidate_ids, ["env_qi1"]);
});

test("queryIndex by type", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_qt1", type: "notification" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_qt2", type: "message" }));
  const result = queryIndex(idx, { type: "notification" });
  assert.deepEqual(result.candidate_ids, ["env_qt1"]);
});

test("queryIndex by thread_id", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_qth1", thread_id: "thr_AAA" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_qth2", thread_id: "thr_BBB" }));
  const result = queryIndex(idx, { thread_id: "thr_AAA" });
  assert.deepEqual(result.candidate_ids, ["env_qth1"]);
});

test("queryIndex by date range", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_qd1", created_at: "2025-01-10T10:00:00Z" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_qd2", created_at: "2025-01-20T10:00:00Z" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_qd3", created_at: "2025-01-30T10:00:00Z" }));
  const result = queryIndex(idx, { after: "2025-01-15T00:00:00Z", before: "2025-01-25T00:00:00Z" });
  assert.deepEqual(result.candidate_ids, ["env_qd2"]);
});

test("queryIndex by text term", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_txt1", text: "important deadline approaching" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_txt2", text: "casual conversation" }));
  const result = queryIndex(idx, { q: "deadline" });
  assert.deepEqual(result.candidate_ids, ["env_txt1"]);
});

test("queryIndex combined sender+type", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_c1", sender: "loom://a@x.com", type: "task" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_c2", sender: "loom://a@x.com", type: "message" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_c3", sender: "loom://b@x.com", type: "task" }));
  const result = queryIndex(idx, { sender: "loom://a@x.com", type: "task" });
  assert.deepEqual(result.candidate_ids, ["env_c1"]);
});

test("queryIndex empty filters returns empty", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_ef1" }));
  const result = queryIndex(idx, {});
  assert.deepEqual(result.candidate_ids, []);
  assert.equal(result.strategy, "none");
});

test("queryIndex non-matching returns empty", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_nm1", sender: "loom://alice@x.com" }));
  const result = queryIndex(idx, { sender: "loom://nobody@x.com" });
  assert.deepEqual(result.candidate_ids, []);
});

test("queryIndex respects limit", () => {
  const idx = createSearchIndex();
  for (let i = 0; i < 10; i++) {
    indexEnvelope(idx, makeEnvelope({ id: `env_lim${i}`, type: "message" }));
  }
  const result = queryIndex(idx, { type: "message", limit: 3 });
  assert.equal(result.candidate_ids.length, 3);
});

test("queryIndex multiple text terms use AND", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_and1", text: "project deadline budget review" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_and2", text: "project status update" }));
  const result = queryIndex(idx, { q: "project deadline" });
  assert.deepEqual(result.candidate_ids, ["env_and1"]);
});

// ─── getIndexStats ──────────────────────────────────────────────────────────

test("getIndexStats accurate after indexing", () => {
  const idx = createSearchIndex({ max_entries: 1000 });
  indexEnvelope(idx, makeEnvelope({ id: "env_st1", sender: "loom://a@x.com", type: "message" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_st2", sender: "loom://b@x.com", type: "task" }));
  const stats = getIndexStats(idx);
  assert.equal(stats.entry_count, 2);
  assert.equal(stats.sender_count, 2);
  assert.equal(stats.type_count, 2);
  assert.equal(stats.max_entries, 1000);
  assert.equal(stats.utilization_pct, 0.2);
});

test("getIndexStats zero after clear", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_szc" }));
  clearIndex(idx);
  const stats = getIndexStats(idx);
  assert.equal(stats.entry_count, 0);
  assert.equal(stats.term_count, 0);
});

test("getIndexStats term count reflects unique terms", () => {
  const idx = createSearchIndex();
  indexEnvelope(idx, makeEnvelope({ id: "env_tc1", text: "alpha beta gamma" }));
  indexEnvelope(idx, makeEnvelope({ id: "env_tc2", text: "alpha delta epsilon" }));
  const stats = getIndexStats(idx);
  assert.equal(stats.term_count, 5); // alpha, beta, gamma, delta, epsilon
});
