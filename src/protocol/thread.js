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

  const queue = [];
  for (const [id, degree] of indegree.entries()) {
    if (degree === 0) {
      queue.push(id);
    }
  }

  queue.sort((idA, idB) => compareQueueIds(idA, idB, byId, orphanSet));

  let seen = 0;
  while (queue.length > 0) {
    const id = queue.shift();
    seen += 1;

    for (const childId of childrenByParent.get(id)) {
      const nextDegree = indegree.get(childId) - 1;
      indegree.set(childId, nextDegree);
      if (nextDegree === 0) {
        queue.push(childId);
      }
    }

    queue.sort((idA, idB) => compareQueueIds(idA, idB, byId, orphanSet));
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

  const queue = [];
  for (const [id, degree] of indegree.entries()) {
    if (degree === 0) {
      queue.push(id);
    }
  }

  queue.sort((idA, idB) => compareQueueIds(idA, idB, byId, orphanSet));

  const ordered = [];

  while (queue.length > 0) {
    const id = queue.shift();
    ordered.push(byId.get(id));

    for (const childId of childrenByParent.get(id)) {
      const nextDegree = indegree.get(childId) - 1;
      indegree.set(childId, nextDegree);
      if (nextDegree === 0) {
        queue.push(childId);
      }
    }

    queue.sort((idA, idB) => compareQueueIds(idA, idB, byId, orphanSet));
  }

  if (ordered.length !== envelopes.length) {
    throw new LoomError("ENVELOPE_INVALID", "Thread DAG contains a cycle", 400, {
      reason: "cycle",
      thread_size: envelopes.length
    });
  }

  return ordered;
}
