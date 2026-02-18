import { LoomError } from "./errors.js";

function compareEnvelopeOrder(a, b) {
  const timeA = Date.parse(a.created_at);
  const timeB = Date.parse(b.created_at);

  if (Number.isFinite(timeA) && Number.isFinite(timeB) && timeA !== timeB) {
    return timeA - timeB;
  }

  return a.id.localeCompare(b.id);
}

function compareQueueIds(idA, idB, byId, orphanSet) {
  const aOrphan = orphanSet.has(idA);
  const bOrphan = orphanSet.has(idB);
  if (aOrphan !== bOrphan) {
    return aOrphan ? 1 : -1;
  }
  return compareEnvelopeOrder(byId.get(idA), byId.get(idB));
}

/**
 * Insert `id` into a sorted array using binary search so that the array
 * stays sorted according to the provided comparator without re-sorting the
 * entire array on every insertion (O(log n) search + O(n) splice instead
 * of O(n log n) full sort).
 */
function sortedInsert(arr, id, cmp) {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (cmp(id, arr[mid]) < 0) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }
  arr.splice(lo, 0, id);
}

export function analyzeThreadGraph(envelopes) {
  const byId = new Map();
  for (const envelope of envelopes) {
    byId.set(envelope.id, envelope);
  }

  const childrenByParent = new Map();
  const indegree = new Map();

  for (const envelope of envelopes) {
    indegree.set(envelope.id, 0);
    childrenByParent.set(envelope.id, []);
  }

  const orphanIds = [];

  for (const envelope of envelopes) {
    const parentId = envelope.parent_id;
    if (!parentId) {
      continue;
    }

    if (!byId.has(parentId)) {
      orphanIds.push(envelope.id);
      continue;
    }

    childrenByParent.get(parentId).push(envelope.id);
    indegree.set(envelope.id, indegree.get(envelope.id) + 1);
  }

  for (const childIds of childrenByParent.values()) {
    childIds.sort((idA, idB) => compareEnvelopeOrder(byId.get(idA), byId.get(idB)));
  }

  orphanIds.sort((idA, idB) => compareEnvelopeOrder(byId.get(idA), byId.get(idB)));

  return { byId, childrenByParent, indegree, orphanIds };
}

export function validateThreadDag(envelopes) {
  const { byId, childrenByParent, indegree, orphanIds } = analyzeThreadGraph(envelopes);
  const orphanSet = new Set(orphanIds);
  const cmp = (idA, idB) => compareQueueIds(idA, idB, byId, orphanSet);

  const queue = [];
  for (const [id, degree] of indegree.entries()) {
    if (degree === 0) {
      sortedInsert(queue, id, cmp);
    }
  }

  let seen = 0;
  while (queue.length > 0) {
    const id = queue.shift();
    seen += 1;

    for (const childId of childrenByParent.get(id)) {
      const nextDegree = indegree.get(childId) - 1;
      indegree.set(childId, nextDegree);
      if (nextDegree === 0) {
        sortedInsert(queue, childId, cmp);
      }
    }
  }

  const hasCycle = seen !== envelopes.length;

  return {
    valid: !hasCycle,
    hasCycle,
    orphanIds
  };
}

export function assertThreadDagOrThrow(envelopes) {
  const result = validateThreadDag(envelopes);
  if (result.hasCycle) {
    throw new LoomError("ENVELOPE_INVALID", "Thread DAG contains a cycle", 400, {
      reason: "cycle",
      thread_size: envelopes.length
    });
  }
  return result;
}

export function canonicalThreadOrder(envelopes) {
  const { byId, childrenByParent, indegree, orphanIds } = analyzeThreadGraph(envelopes);
  const orphanSet = new Set(orphanIds);
  const cmp = (idA, idB) => compareQueueIds(idA, idB, byId, orphanSet);

  const queue = [];
  for (const [id, degree] of indegree.entries()) {
    if (degree === 0) {
      sortedInsert(queue, id, cmp);
    }
  }

  const ordered = [];

  while (queue.length > 0) {
    const id = queue.shift();
    ordered.push(byId.get(id));

    for (const childId of childrenByParent.get(id)) {
      const nextDegree = indegree.get(childId) - 1;
      indegree.set(childId, nextDegree);
      if (nextDegree === 0) {
        sortedInsert(queue, childId, cmp);
      }
    }
  }

  if (ordered.length !== envelopes.length) {
    throw new LoomError("ENVELOPE_INVALID", "Thread DAG contains a cycle", 400, {
      reason: "cycle",
      thread_size: envelopes.length
    });
  }

  return ordered;
}
