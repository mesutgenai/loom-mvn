import { LoomError } from "./errors.js";

export const DEFAULT_THREAD_LIMITS = {
  max_envelopes_per_thread: 10000,
  max_pending_parents: 500
};

export function assertThreadLimitsOrThrow(envelopeCount, limits = {}, pendingParentCount = 0) {
  const maxEnvelopes = limits.max_envelopes_per_thread ?? DEFAULT_THREAD_LIMITS.max_envelopes_per_thread;

  if (maxEnvelopes > 0 && envelopeCount >= maxEnvelopes) {
    throw new LoomError("ENVELOPE_INVALID", "Thread has reached maximum envelope count", 400, {
      envelope_count: envelopeCount,
      max_envelopes_per_thread: maxEnvelopes
    });
  }

  const maxPending = limits.max_pending_parents ?? DEFAULT_THREAD_LIMITS.max_pending_parents;
  if (maxPending > 0 && pendingParentCount >= maxPending) {
    throw new LoomError("ENVELOPE_INVALID", "Thread has too many pending (unresolved) parent references", 400, {
      pending_parent_count: pendingParentCount,
      max_pending_parents: maxPending
    });
  }
}
