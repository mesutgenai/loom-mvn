import { createHash } from "node:crypto";
import { LoomError } from "./errors.js";

// ─── Default Limits ──────────────────────────────────────────────────────────

export const DEFAULT_LOOP_LIMITS = {
  max_hop_count: 20,
  max_agent_envelopes_per_thread_window: 50,
  agent_window_ms: 60_000
};

export const MAX_HOP_COUNT_ABSOLUTE = 255;
const PING_PONG_MIN_ENVELOPES = 4;

// ─── Hop Count Validation ────────────────────────────────────────────────────

export function validateHopCount(hopCount) {
  const errors = [];
  if (hopCount === undefined || hopCount === null) {
    return errors;
  }
  if (typeof hopCount !== "number" || !Number.isInteger(hopCount)) {
    errors.push({ field: "hop_count", reason: "must be an integer when present" });
    return errors;
  }
  if (hopCount < 0) {
    errors.push({ field: "hop_count", reason: "must be non-negative" });
  }
  if (hopCount > MAX_HOP_COUNT_ABSOLUTE) {
    errors.push({ field: "hop_count", reason: `must not exceed ${MAX_HOP_COUNT_ABSOLUTE}` });
  }
  return errors;
}

// ─── Conversation Hash ───────────────────────────────────────────────────────

export function computeConversationHash(senderIdentity, recipientIdentities, intent) {
  const sender = String(senderIdentity || "").trim();
  const recipients = Array.isArray(recipientIdentities)
    ? recipientIdentities
        .map((r) => String(r || "").trim())
        .filter(Boolean)
    : [];
  // Symmetric: combine sender + recipients into a sorted participant set
  const participants = [sender, ...recipients].filter(Boolean).sort();
  const intentStr = String(intent || "").trim();

  const payload = JSON.stringify({ participants, intent: intentStr });
  return createHash("sha256").update(payload).digest("hex");
}

// ─── Ping-Pong Pattern Detection ─────────────────────────────────────────────

export function detectPingPongPattern(threadEnvelopeIds, envelopesById, currentSender, currentRecipients, currentIntent) {
  if (!Array.isArray(threadEnvelopeIds) || threadEnvelopeIds.length < PING_PONG_MIN_ENVELOPES) {
    return { detected: false };
  }

  const currentHash = computeConversationHash(currentSender, currentRecipients, currentIntent);

  // Collect recent envelopes, filtering to agent senders only
  const recentCount = Math.min(threadEnvelopeIds.length, 12);
  const recentIds = threadEnvelopeIds.slice(-recentCount);
  const agentEnvelopes = [];
  for (const id of recentIds) {
    const env = envelopesById.get(id);
    if (env && env.from?.type === "agent") {
      agentEnvelopes.push(env);
    }
  }

  if (agentEnvelopes.length < PING_PONG_MIN_ENVELOPES) {
    return { detected: false };
  }

  const senders = new Set();
  let alternatingCount = 0;
  let matchingHashCount = 0;

  for (let i = agentEnvelopes.length - 1; i >= 0; i--) {
    const env = agentEnvelopes[i];
    const envSender = String(env.from?.identity || "").trim();
    const envRecipients = Array.isArray(env.to) ? env.to.map((r) => String(r.identity || "").trim()) : [];
    const envIntent = String(env.content?.structured?.intent || "").trim();
    const envHash = computeConversationHash(envSender, envRecipients, envIntent);

    senders.add(envSender);

    if (envHash === currentHash) {
      matchingHashCount++;
    }

    if (i < agentEnvelopes.length - 1) {
      const nextEnv = agentEnvelopes[i + 1];
      const nextSender = String(nextEnv.from?.identity || "").trim();
      if (envSender !== nextSender) {
        alternatingCount++;
      }
    }
  }

  senders.add(currentSender);

  const isTwoPartyAlternation = senders.size === 2 && alternatingCount >= PING_PONG_MIN_ENVELOPES - 2;
  const hasMatchingHashes = matchingHashCount >= PING_PONG_MIN_ENVELOPES - 1;

  if (isTwoPartyAlternation && hasMatchingHashes) {
    return { detected: true, senders: Array.from(senders), conversation_hash: currentHash };
  }

  return { detected: false };
}

// ─── Agent Per-Thread Rate Limiting ──────────────────────────────────────────

export function assertAgentThreadRateOrThrow(threadEnvelopeIds, envelopesById, senderIdentity, now, limits = {}) {
  const maxPerWindow = limits.max_agent_envelopes_per_thread_window ?? DEFAULT_LOOP_LIMITS.max_agent_envelopes_per_thread_window;
  const windowMs = limits.agent_window_ms ?? DEFAULT_LOOP_LIMITS.agent_window_ms;

  if (maxPerWindow <= 0 || windowMs <= 0) {
    return;
  }

  if (!Array.isArray(threadEnvelopeIds) || threadEnvelopeIds.length === 0) {
    return;
  }

  const cutoff = now - windowMs;
  let count = 0;

  for (let i = threadEnvelopeIds.length - 1; i >= 0; i--) {
    const env = envelopesById.get(threadEnvelopeIds[i]);
    if (!env) {
      continue;
    }

    const receivedAt = env.meta?.received_at || env.created_at;
    const receivedMs = new Date(receivedAt).getTime();
    if (receivedMs < cutoff) {
      break;
    }

    if (String(env.from?.identity || "").trim() === senderIdentity && env.from?.type === "agent") {
      count++;
    }
  }

  if (count >= maxPerWindow) {
    throw new LoomError("LOOP_DETECTED", "Agent sender exceeded per-thread rate limit", 429, {
      sender: senderIdentity,
      count,
      max_per_window: maxPerWindow,
      window_ms: windowMs
    });
  }
}
