import { canonicalizeJson } from "./canonical.js";
import { LoomError } from "./errors.js";
import { isIdentity, isIsoDateTime } from "./ids.js";
import { verifyUtf8MessageSignature } from "./crypto.js";

const ENVELOPE_TYPE_ACTIONS = {
  message: "message.send@v1",
  task: "task.send@v1",
  approval: "approval.send@v1",
  event: "event.send@v1",
  notification: "notification.send@v1",
  handoff: "handoff.send@v1",
  data: "data.send@v1",
  receipt: "receipt.send@v1",
  workflow: "workflow.send@v1",
  thread_op: "thread.op.execute@v1"
};

function parseIsoTime(value) {
  if (!isIsoDateTime(value)) {
    return null;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeStringArray(value, field) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new LoomError("DELEGATION_INVALID", `${field} must be a non-empty array`, 403, {
      field
    });
  }

  const normalized = value
    .map((item) => String(item || "").trim())
    .filter((item) => item.length > 0);

  if (normalized.length === 0) {
    throw new LoomError("DELEGATION_INVALID", `${field} must contain at least one scope`, 403, {
      field
    });
  }

  return normalized;
}

export function canonicalizeDelegationLink(link) {
  const canonical = {};
  for (const [key, value] of Object.entries(link || {})) {
    if (key !== "signature") {
      canonical[key] = value;
    }
  }

  return canonicalizeJson(canonical);
}

function scopePatternAllowsAction(pattern, action) {
  if (pattern === "*") {
    return true;
  }

  if (pattern.endsWith("*")) {
    return action.startsWith(pattern.slice(0, -1));
  }

  return pattern === action;
}

function normalizeAction(action) {
  if (typeof action !== "string") {
    return [];
  }

  const normalized = action.trim();
  if (normalized.length === 0) {
    return [];
  }

  const noVersion = normalized.replace(/@v\d+$/i, "");
  return Array.from(new Set([normalized, noVersion]));
}

function normalizeActionList(actions) {
  if (actions == null) {
    return [];
  }

  const list = Array.isArray(actions) ? actions : [actions];
  const normalized = [];
  for (const entry of list) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }
    normalized.push(trimmed);
  }
  return Array.from(new Set(normalized));
}

function scopePatternSubset(child, parent) {
  if (parent === "*") {
    return true;
  }

  if (!parent.endsWith("*")) {
    return child === parent;
  }

  const prefix = parent.slice(0, -1);
  if (child === parent) {
    return true;
  }

  return child.startsWith(prefix);
}

export function isScopeSubset(childScopes, parentScopes) {
  const child = normalizeStringArray(childScopes, "child_scope");
  const parent = normalizeStringArray(parentScopes, "parent_scope");

  return child.every((childPattern) => parent.some((parentPattern) => scopePatternSubset(childPattern, parentPattern)));
}

export function scopeAllowsAction(scopeList, action) {
  const scopes = normalizeStringArray(scopeList, "scope");
  const actionCandidates = normalizeAction(action);

  if (actionCandidates.length === 0) {
    return false;
  }

  return scopes.some((pattern) => actionCandidates.some((candidate) => scopePatternAllowsAction(pattern, candidate)));
}

function resolveEnvelopeActions(envelope, options = {}) {
  const explicit = normalizeActionList(options.requiredActions || options.requiredAction);
  if (explicit.length > 0) {
    return explicit;
  }

  const envelopeType = String(envelope?.type || "").trim();
  const mapped = ENVELOPE_TYPE_ACTIONS[envelopeType];
  if (mapped) {
    return [mapped];
  }

  if (envelopeType.length > 0) {
    return [`${envelopeType}.send@v1`];
  }

  return [];
}

export function resolveEnvelopeAction(envelope, options = {}) {
  const actions = resolveEnvelopeActions(envelope, options);
  return actions.length > 0 ? actions[0] : null;
}

function resolveDelegatorSigningKey(link, resolveIdentity, resolvePublicKey) {
  const identity = resolveIdentity(link.delegator);
  if (!identity) {
    throw new LoomError("DELEGATION_INVALID", `Delegator identity not found: ${link.delegator}`, 403, {
      delegator: link.delegator
    });
  }

  const explicitKeyId = link.key_id || link.signature_key_id || null;
  if (explicitKeyId) {
    const fromIdentity = identity.signing_keys?.find((key) => key.key_id === explicitKeyId);
    const publicKeyPem = fromIdentity?.public_key_pem || resolvePublicKey(explicitKeyId);
    if (!publicKeyPem) {
      throw new LoomError("DELEGATION_INVALID", `Delegation signing key not found: ${explicitKeyId}`, 403, {
        key_id: explicitKeyId
      });
    }

    return { keyId: explicitKeyId, publicKeyPem };
  }

  const available = Array.isArray(identity.signing_keys) ? identity.signing_keys : [];
  if (available.length !== 1) {
    throw new LoomError(
      "DELEGATION_INVALID",
      "Delegation must include key_id when delegator has multiple signing keys",
      403,
      { delegator: link.delegator }
    );
  }

  return {
    keyId: available[0].key_id,
    publicKeyPem: available[0].public_key_pem
  };
}

export function verifyDelegationLinkOrThrow(link, options = {}) {
  const resolveIdentity = options.resolveIdentity;
  const resolvePublicKey = options.resolvePublicKey || (() => null);

  if (!link || typeof link !== "object") {
    throw new LoomError("DELEGATION_INVALID", "Delegation link must be an object", 403, {
      field: "delegation_link"
    });
  }

  if (!isIdentity(link.delegator)) {
    throw new LoomError("DELEGATION_INVALID", "Delegation link has invalid delegator identity", 403, {
      field: "delegator"
    });
  }

  if (!isIdentity(link.delegate)) {
    throw new LoomError("DELEGATION_INVALID", "Delegation link has invalid delegate identity", 403, {
      field: "delegate"
    });
  }

  if (!link.signature || typeof link.signature !== "string") {
    throw new LoomError("DELEGATION_INVALID", "Delegation link signature is required", 403, {
      field: "signature"
    });
  }

  normalizeStringArray(link.scope, "scope");

  if (link.expires_at != null) {
    const expires = parseIsoTime(link.expires_at);
    if (expires == null) {
      throw new LoomError("DELEGATION_INVALID", "Delegation expires_at must be ISO-8601", 403, {
        field: "expires_at"
      });
    }
  }

  const { publicKeyPem } = resolveDelegatorSigningKey(link, resolveIdentity, resolvePublicKey);
  const canonical = canonicalizeDelegationLink(link);
  const valid = verifyUtf8MessageSignature(publicKeyPem, canonical, link.signature);

  if (!valid) {
    throw new LoomError("DELEGATION_INVALID", "Delegation signature verification failed", 403, {
      delegator: link.delegator,
      delegate: link.delegate
    });
  }

  return true;
}

export function verifyDelegationChainOrThrow(envelope, options = {}) {
  const chain = envelope?.from?.delegation_chain;
  const now = options.now || Date.now();
  const resolveIdentity = options.resolveIdentity;
  const resolvePublicKey = options.resolvePublicKey || (() => null);
  const isDelegationRevoked = options.isDelegationRevoked || (() => false);

  if (!Array.isArray(chain) || chain.length === 0) {
    throw new LoomError("DELEGATION_INVALID", "Agent envelope requires non-empty delegation_chain", 403, {
      field: "from.delegation_chain"
    });
  }

  for (let index = 0; index < chain.length; index += 1) {
    const link = chain[index];
    verifyDelegationLinkOrThrow(link, { resolveIdentity, resolvePublicKey });

    const expiresAt = link.expires_at ? parseIsoTime(link.expires_at) : null;
    if (expiresAt != null && expiresAt <= now) {
      throw new LoomError("DELEGATION_INVALID", "Delegation link expired", 403, {
        index,
        delegate: link.delegate
      });
    }

    if (isDelegationRevoked(link)) {
      throw new LoomError("DELEGATION_INVALID", "Delegation link has been revoked", 403, {
        index,
        delegation_id: link.id || null,
        delegate: link.delegate
      });
    }

    const remainingDepth = chain.length - (index + 1);
    const maxSubDelegationDepth = Number(link.max_sub_delegation_depth);
    if (remainingDepth > 0 && Number.isFinite(maxSubDelegationDepth) && maxSubDelegationDepth >= 0) {
      if (remainingDepth > maxSubDelegationDepth) {
        throw new LoomError("DELEGATION_INVALID", "Delegation chain exceeds max_sub_delegation_depth", 403, {
          index,
          max_sub_delegation_depth: maxSubDelegationDepth,
          remaining_depth: remainingDepth
        });
      }
    }

    if (index > 0) {
      const previous = chain[index - 1];
      if (previous.delegate !== link.delegator) {
        throw new LoomError("DELEGATION_INVALID", "Delegation chain continuity violation", 403, {
          index,
          expected_delegator: previous.delegate,
          actual_delegator: link.delegator
        });
      }

      if (!isScopeSubset(link.scope, previous.scope)) {
        throw new LoomError("DELEGATION_INVALID", "Delegation scope escalation detected", 403, {
          index,
          delegator: link.delegator,
          delegate: link.delegate
        });
      }

      if (previous.allow_sub_delegation === false) {
        throw new LoomError("DELEGATION_INVALID", "Sub-delegation forbidden by parent delegation", 403, {
          index,
          delegator: previous.delegator,
          delegate: previous.delegate
        });
      }
    }
  }

  const leaf = chain[chain.length - 1];
  if (leaf.delegate !== envelope.from.identity) {
    throw new LoomError("DELEGATION_INVALID", "Delegation chain leaf must match envelope sender identity", 403, {
      leaf_delegate: leaf.delegate,
      sender: envelope.from.identity
    });
  }

  const requiredActions = resolveEnvelopeActions(envelope, options);
  if (requiredActions.length === 0) {
    throw new LoomError("DELEGATION_INVALID", "Delegation verification requires at least one server-derived action", 403, {
      sender: envelope?.from?.identity || null
    });
  }

  const allowed = requiredActions.some((action) => scopeAllowsAction(leaf.scope, action));
  if (!allowed) {
    throw new LoomError("DELEGATION_INVALID", "Delegation scope does not permit envelope action", 403, {
      sender: envelope.from.identity,
      required_actions: requiredActions
    });
  }

  return true;
}
