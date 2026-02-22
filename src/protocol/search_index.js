// ─── Search Index ── Section 16.7 ────────────────────────────────────────────
//
// Term-based in-memory inverted index for efficient envelope lookups.
// Bounded memory via max entries with LRU eviction. Pure-function module.

// ─── Constants ──────────────────────────────────────────────────────────────

const _STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been",
  "being", "have", "has", "had", "do", "does", "did", "will",
  "would", "could", "should", "may", "might", "shall", "can",
  "to", "of", "in", "for", "on", "with", "at", "by", "from",
  "it", "this", "that", "and", "or", "but", "not", "if", "as"
]);

export const DEFAULT_INDEX_OPTIONS = Object.freeze({
  max_entries: 100000,
  text_min_length: 2,
  text_max_length: 80,
  stop_words: Object.freeze(_STOP_WORDS)
});

// ─── Index Creation ─────────────────────────────────────────────────────────

export function createSearchIndex(options = {}) {
  return {
    options: { ...DEFAULT_INDEX_OPTIONS, ...options },
    byTerm: new Map(),
    bySender: new Map(),
    byIntent: new Map(),
    byType: new Map(),
    byThreadId: new Map(),
    byDateBucket: new Map(),
    reverseTerms: new Map(),
    envelopeMeta: new Map(),
    entryOrder: [],
    entryCount: 0
  };
}

// ─── Tokenization ───────────────────────────────────────────────────────────

export function tokenizeText(text, options = DEFAULT_INDEX_OPTIONS) {
  if (!text || typeof text !== "string") return [];

  const minLen = options.text_min_length || 2;
  const maxLen = options.text_max_length || 80;
  const stopWords = options.stop_words || _STOP_WORDS;

  const tokens = text
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= minLen && t.length <= maxLen && !stopWords.has(t));

  return [...new Set(tokens)];
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

function addToMapSet(map, key, value) {
  if (!key) return;
  let set = map.get(key);
  if (!set) {
    set = new Set();
    map.set(key, set);
  }
  set.add(value);
}

function removeFromMapSet(map, key, value) {
  if (!key) return;
  const set = map.get(key);
  if (set) {
    set.delete(value);
    if (set.size === 0) map.delete(key);
  }
}

function extractDateBucket(isoString) {
  if (!isoString || typeof isoString !== "string") return null;
  return isoString.slice(0, 10); // "YYYY-MM-DD"
}

function evictOldest(index) {
  if (index.entryOrder.length === 0) return null;
  const evictedId = index.entryOrder.shift();
  _removeFromAllMaps(index, evictedId);
  return evictedId;
}

function _removeFromAllMaps(index, envelopeId) {
  // Remove from structured maps using stored metadata
  const meta = index.envelopeMeta.get(envelopeId);
  if (meta) {
    removeFromMapSet(index.bySender, meta.sender, envelopeId);
    removeFromMapSet(index.byIntent, meta.intent, envelopeId);
    removeFromMapSet(index.byType, meta.type, envelopeId);
    removeFromMapSet(index.byThreadId, meta.thread_id, envelopeId);
    removeFromMapSet(index.byDateBucket, meta.date_bucket, envelopeId);
    index.envelopeMeta.delete(envelopeId);
  }

  // Remove from term maps using reverse index
  const terms = index.reverseTerms.get(envelopeId);
  if (terms) {
    for (const term of terms) {
      removeFromMapSet(index.byTerm, term, envelopeId);
    }
    index.reverseTerms.delete(envelopeId);
  }

  index.entryCount = Math.max(0, index.entryCount - 1);
}

// ─── Index Maintenance ──────────────────────────────────────────────────────

export function indexEnvelope(index, envelope) {
  if (!envelope || !envelope.id) return { indexed: false, evicted: null };

  const envelopeId = envelope.id;

  // Idempotent: skip if already indexed
  if (index.envelopeMeta.has(envelopeId)) {
    return { indexed: false, evicted: null };
  }

  // LRU eviction if at capacity
  let evicted = null;
  if (index.entryCount >= index.options.max_entries) {
    evicted = evictOldest(index);
  }

  // Extract metadata
  const sender = envelope.from?.identity || null;
  const intent = envelope.content?.structured?.intent || null;
  const type = envelope.type || null;
  const threadId = envelope.thread_id || null;
  const dateBucket = extractDateBucket(envelope.created_at);

  // Store metadata for efficient removal
  index.envelopeMeta.set(envelopeId, {
    sender, intent, type, thread_id: threadId, date_bucket: dateBucket
  });

  // Index structured fields
  addToMapSet(index.bySender, sender, envelopeId);
  addToMapSet(index.byIntent, intent, envelopeId);
  addToMapSet(index.byType, type, envelopeId);
  addToMapSet(index.byThreadId, threadId, envelopeId);
  addToMapSet(index.byDateBucket, dateBucket, envelopeId);

  // Index text content (skip encrypted envelopes)
  const text = envelope.content?.encrypted ? null : (envelope.content?.human?.text || null);
  if (text) {
    const tokens = tokenizeText(text, index.options);
    index.reverseTerms.set(envelopeId, new Set(tokens));
    for (const token of tokens) {
      addToMapSet(index.byTerm, token, envelopeId);
    }
  } else {
    index.reverseTerms.set(envelopeId, new Set());
  }

  index.entryOrder.push(envelopeId);
  index.entryCount += 1;

  return { indexed: true, evicted };
}

export function removeEnvelope(index, envelopeId) {
  if (!envelopeId || !index.envelopeMeta.has(envelopeId)) {
    return { removed: false };
  }

  _removeFromAllMaps(index, envelopeId);

  // Remove from entryOrder
  const orderIdx = index.entryOrder.indexOf(envelopeId);
  if (orderIdx !== -1) {
    index.entryOrder.splice(orderIdx, 1);
  }

  return { removed: true };
}

export function rebuildIndex(index, envelopes) {
  clearIndex(index);
  const arr = Array.isArray(envelopes) ? envelopes : [];
  let indexedCount = 0;
  let evictedCount = 0;

  for (const envelope of arr) {
    const result = indexEnvelope(index, envelope);
    if (result.indexed) indexedCount++;
    if (result.evicted) evictedCount++;
  }

  return { indexed_count: indexedCount, evicted_count: evictedCount };
}

export function clearIndex(index) {
  index.byTerm.clear();
  index.bySender.clear();
  index.byIntent.clear();
  index.byType.clear();
  index.byThreadId.clear();
  index.byDateBucket.clear();
  index.reverseTerms.clear();
  index.envelopeMeta.clear();
  index.entryOrder.length = 0;
  index.entryCount = 0;
}

// ─── Query Execution ────────────────────────────────────────────────────────

export function queryIndex(index, filters = {}) {
  const candidateSets = [];
  const strategies = [];

  // Structured field lookups
  if (filters.sender) {
    const set = index.bySender.get(filters.sender);
    candidateSets.push(set || new Set());
    strategies.push("sender");
  }

  if (filters.intent) {
    const set = index.byIntent.get(filters.intent);
    candidateSets.push(set || new Set());
    strategies.push("intent");
  }

  if (filters.type) {
    const set = index.byType.get(filters.type);
    candidateSets.push(set || new Set());
    strategies.push("type");
  }

  if (filters.thread_id) {
    const set = index.byThreadId.get(filters.thread_id);
    candidateSets.push(set || new Set());
    strategies.push("thread_id");
  }

  // Date range via bucket union
  if (filters.after || filters.before) {
    const afterMs = filters.after ? Date.parse(filters.after) : null;
    const beforeMs = filters.before ? Date.parse(filters.before) : null;
    const dateCandidates = new Set();

    for (const [bucket, ids] of index.byDateBucket.entries()) {
      const bucketMs = Date.parse(bucket + "T00:00:00Z");
      const bucketEndMs = bucketMs + 86400000; // end of day
      if (afterMs != null && bucketEndMs <= afterMs) continue;
      if (beforeMs != null && bucketMs > beforeMs) continue;
      for (const id of ids) dateCandidates.add(id);
    }

    candidateSets.push(dateCandidates);
    strategies.push("date_range");
  }

  // Text term lookup
  if (filters.q && typeof filters.q === "string" && filters.q.trim().length > 0) {
    const queryTokens = tokenizeText(filters.q, index.options);
    if (queryTokens.length > 0) {
      // Intersect all term sets
      let termCandidates = null;
      for (const token of queryTokens) {
        const set = index.byTerm.get(token);
        if (!set || set.size === 0) {
          termCandidates = new Set();
          break;
        }
        if (termCandidates === null) {
          termCandidates = new Set(set);
        } else {
          for (const id of termCandidates) {
            if (!set.has(id)) termCandidates.delete(id);
          }
        }
      }
      candidateSets.push(termCandidates || new Set());
      strategies.push("text");
    }
  }

  if (candidateSets.length === 0) {
    return { candidate_ids: [], strategy: "none" };
  }

  // Intersect all candidate sets — start with smallest
  candidateSets.sort((a, b) => a.size - b.size);
  let result = new Set(candidateSets[0]);
  for (let i = 1; i < candidateSets.length; i++) {
    const next = candidateSets[i];
    for (const id of result) {
      if (!next.has(id)) result.delete(id);
    }
  }

  // Apply limit
  const limit = filters.limit ? Math.max(1, Math.min(Number(filters.limit), 10000)) : 10000;
  const ids = [];
  for (const id of result) {
    if (ids.length >= limit) break;
    ids.push(id);
  }

  return {
    candidate_ids: ids,
    strategy: strategies.join("+")
  };
}

// ─── Stats ──────────────────────────────────────────────────────────────────

export function getIndexStats(index) {
  return {
    entry_count: index.entryCount,
    max_entries: index.options.max_entries,
    term_count: index.byTerm.size,
    sender_count: index.bySender.size,
    intent_count: index.byIntent.size,
    type_count: index.byType.size,
    thread_count: index.byThreadId.size,
    date_bucket_count: index.byDateBucket.size,
    utilization_pct: index.options.max_entries > 0
      ? Math.round((index.entryCount / index.options.max_entries) * 100 * 10) / 10
      : 0
  };
}
