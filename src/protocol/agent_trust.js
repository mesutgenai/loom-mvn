// ─── Agent Trust Scoring Protocol Module ─────────────────────────────────────
//
// Pure-function protocol module. No store or server dependencies.
// Provides per-agent behavioral trust scoring with event weights,
// decay windows, threshold classification, and assertion enforcement.

import { LoomError } from "./errors.js";

// ─── Trust Event Types ───────────────────────────────────────────────────────

export const AGENT_TRUST_EVENT_TYPES = Object.freeze({
  successful_operation:   -1,
  injection_detected:     +5,
  sandbox_violation:      +3,
  rate_limit_hit:         +2,
  loop_escalation:        +4,
  content_filter_flag:    +3,
  delegation_violation:   +5,
  authentication_failure: +2
});

// ─── Trust Levels ────────────────────────────────────────────────────────────

export const AGENT_TRUST_LEVELS = Object.freeze({
  TRUSTED:      "trusted",
  WARNING:      "warning",
  QUARANTINED:  "quarantined",
  BLOCKED:      "blocked"
});

// ─── Default Trust Policy ────────────────────────────────────────────────────

export const DEFAULT_AGENT_TRUST_POLICY = Object.freeze({
  decay_window_ms:         86_400_000,   // 24 hours
  warning_threshold:              10,
  quarantine_threshold:           25,
  block_threshold:                50,
  max_events_per_agent:          200,
  good_behavior_decay:          true
});

// ─── Policy Validation ───────────────────────────────────────────────────────

export function validateAgentTrustPolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    return [{ field: "policy", reason: "must be an object" }];
  }

  if (policy.decay_window_ms != null) {
    if (typeof policy.decay_window_ms !== "number" || policy.decay_window_ms < 60000) {
      errors.push({ field: "decay_window_ms", reason: "must be a number >= 60000" });
    }
  }
  if (policy.warning_threshold != null) {
    if (typeof policy.warning_threshold !== "number" || policy.warning_threshold < 1) {
      errors.push({ field: "warning_threshold", reason: "must be a positive number" });
    }
  }
  if (policy.quarantine_threshold != null) {
    if (typeof policy.quarantine_threshold !== "number" || policy.quarantine_threshold < 2) {
      errors.push({ field: "quarantine_threshold", reason: "must be a number >= 2" });
    }
  }
  if (policy.block_threshold != null) {
    if (typeof policy.block_threshold !== "number" || policy.block_threshold < 3) {
      errors.push({ field: "block_threshold", reason: "must be a number >= 3" });
    }
  }
  if (policy.max_events_per_agent != null) {
    if (typeof policy.max_events_per_agent !== "number" || policy.max_events_per_agent < 10) {
      errors.push({ field: "max_events_per_agent", reason: "must be a number >= 10" });
    }
  }

  // Threshold ordering check
  const wt = policy.warning_threshold ?? DEFAULT_AGENT_TRUST_POLICY.warning_threshold;
  const qt = policy.quarantine_threshold ?? DEFAULT_AGENT_TRUST_POLICY.quarantine_threshold;
  const bt = policy.block_threshold ?? DEFAULT_AGENT_TRUST_POLICY.block_threshold;
  if (typeof wt === "number" && typeof qt === "number" && typeof bt === "number") {
    if (wt >= qt) {
      errors.push({ field: "warning_threshold", reason: "must be less than quarantine_threshold" });
    }
    if (qt >= bt) {
      errors.push({ field: "quarantine_threshold", reason: "must be less than block_threshold" });
    }
  }

  return errors;
}

// ─── Score Computation ───────────────────────────────────────────────────────

export function computeAgentTrustScore(events, policy, now) {
  const effectivePolicy = {
    ...DEFAULT_AGENT_TRUST_POLICY,
    ...(policy || {})
  };

  if (!Array.isArray(events) || events.length === 0) {
    return {
      score: 0,
      event_count: 0,
      active_event_count: 0,
      decayed_count: 0,
      oldest_event: null,
      newest_event: null
    };
  }

  const cutoff = now - effectivePolicy.decay_window_ms;
  let score = 0;
  let activeCount = 0;
  let decayedCount = 0;
  let oldestActive = null;
  let newestActive = null;

  for (const event of events) {
    const eventTime = event.timestamp || 0;

    if (eventTime < cutoff) {
      decayedCount++;
      continue;
    }

    const eventType = event.type;
    const weight = AGENT_TRUST_EVENT_TYPES[eventType];

    if (weight === undefined) {
      continue;
    }

    // Skip good-behavior events if disabled
    if (!effectivePolicy.good_behavior_decay && weight < 0) {
      continue;
    }

    score += weight;
    activeCount++;

    if (oldestActive === null || eventTime < oldestActive) {
      oldestActive = eventTime;
    }
    if (newestActive === null || eventTime > newestActive) {
      newestActive = eventTime;
    }
  }

  // Score cannot go below 0
  if (score < 0) {
    score = 0;
  }

  return {
    score,
    event_count: events.length,
    active_event_count: activeCount,
    decayed_count: decayedCount,
    oldest_event: oldestActive,
    newest_event: newestActive
  };
}

// ─── Trust Classification ────────────────────────────────────────────────────

export function classifyAgentTrust(score, policy) {
  const effectivePolicy = {
    ...DEFAULT_AGENT_TRUST_POLICY,
    ...(policy || {})
  };

  if (score >= effectivePolicy.block_threshold) {
    return AGENT_TRUST_LEVELS.BLOCKED;
  }
  if (score >= effectivePolicy.quarantine_threshold) {
    return AGENT_TRUST_LEVELS.QUARANTINED;
  }
  if (score >= effectivePolicy.warning_threshold) {
    return AGENT_TRUST_LEVELS.WARNING;
  }
  return AGENT_TRUST_LEVELS.TRUSTED;
}

// ─── Trust Assertion ─────────────────────────────────────────────────────────

export function assertAgentTrustOrThrow(score, policy) {
  const level = classifyAgentTrust(score, policy);

  if (level === AGENT_TRUST_LEVELS.BLOCKED) {
    throw new LoomError("AGENT_BLOCKED",
      `Agent is blocked due to trust score: ${score}`,
      403, {
        trust_score: score,
        trust_level: level
      });
  }

  if (level === AGENT_TRUST_LEVELS.QUARANTINED) {
    throw new LoomError("AGENT_QUARANTINED",
      `Agent is quarantined due to trust score: ${score}`,
      403, {
        trust_score: score,
        trust_level: level
      });
  }

  return { score, level };
}

// ─── Trust Summary Builder ───────────────────────────────────────────────────

export function buildAgentTrustSummary(events, policy, now) {
  const scoreResult = computeAgentTrustScore(events, policy, now);
  const level = classifyAgentTrust(scoreResult.score, policy);

  // Build event breakdown by type
  const effectivePolicy = {
    ...DEFAULT_AGENT_TRUST_POLICY,
    ...(policy || {})
  };
  const cutoff = now - effectivePolicy.decay_window_ms;
  const breakdown = {};

  if (Array.isArray(events)) {
    for (const event of events) {
      if ((event.timestamp || 0) < cutoff) {
        continue;
      }
      const type = event.type;
      if (!breakdown[type]) {
        breakdown[type] = { count: 0, total_weight: 0 };
      }
      breakdown[type].count++;
      const weight = AGENT_TRUST_EVENT_TYPES[type] || 0;
      breakdown[type].total_weight += weight;
    }
  }

  return {
    score: scoreResult.score,
    level,
    event_count: scoreResult.event_count,
    active_event_count: scoreResult.active_event_count,
    decayed_count: scoreResult.decayed_count,
    oldest_event: scoreResult.oldest_event,
    newest_event: scoreResult.newest_event,
    breakdown
  };
}
