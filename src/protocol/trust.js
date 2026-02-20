import { normalizeLoomIdentity } from "./ids.js";

function normalizeAuthorityLike(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) {
    return null;
  }

  const withoutScheme = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const hostPort = withoutScheme.split("/")[0];
  if (!hostPort) {
    return null;
  }

  if (hostPort.startsWith("[") && hostPort.includes("]")) {
    return hostPort.slice(1, hostPort.indexOf("]")) || null;
  }

  const colonIndex = hostPort.indexOf(":");
  if (colonIndex >= 0) {
    return hostPort.slice(0, colonIndex) || null;
  }

  return hostPort.replace(/\.+$/, "") || null;
}

function normalizeTrustAnchorCandidates(value) {
  const normalized = new Set();
  for (const candidate of Array.isArray(value) ? value : [value]) {
    const authority = normalizeAuthorityLike(candidate);
    if (authority) {
      normalized.add(authority);
    }
  }
  return normalized;
}

function parseRawBindingEntries(value) {
  if (value == null) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.map((entry) => String(entry || "").trim()).filter(Boolean);
  }

  return String(value)
    .split(/[,\n;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function normalizeNodeAuthority(nodeId) {
  return normalizeAuthorityLike(nodeId);
}

export function parseLoomIdentityAuthority(identityUri) {
  const normalizedIdentity = normalizeLoomIdentity(identityUri);
  if (!normalizedIdentity) {
    return null;
  }

  const raw = normalizedIdentity.slice("loom://".length);
  const atIndex = raw.indexOf("@");
  if (atIndex <= 0 || atIndex >= raw.length - 1) {
    return null;
  }

  return normalizeAuthorityLike(raw.slice(atIndex + 1));
}

export function parseTrustAnchorBindings(value) {
  const bindings = new Map();
  if (value == null) {
    return bindings;
  }

  if (value instanceof Map) {
    for (const [identityAuthority, nodeAuthorities] of value.entries()) {
      const normalizedIdentityAuthority = normalizeAuthorityLike(identityAuthority);
      if (!normalizedIdentityAuthority) {
        continue;
      }
      const normalizedNodeAuthorities = normalizeTrustAnchorCandidates(nodeAuthorities);
      if (normalizedNodeAuthorities.size > 0) {
        bindings.set(normalizedIdentityAuthority, normalizedNodeAuthorities);
      }
    }
    return bindings;
  }

  if (typeof value === "object" && !Array.isArray(value)) {
    for (const [identityAuthority, nodeAuthorities] of Object.entries(value)) {
      const normalizedIdentityAuthority = normalizeAuthorityLike(identityAuthority);
      if (!normalizedIdentityAuthority) {
        continue;
      }
      const normalizedNodeAuthorities = normalizeTrustAnchorCandidates(nodeAuthorities);
      if (normalizedNodeAuthorities.size > 0) {
        bindings.set(normalizedIdentityAuthority, normalizedNodeAuthorities);
      }
    }
    return bindings;
  }

  for (const entry of parseRawBindingEntries(value)) {
    const splitIndex = entry.indexOf("=");
    if (splitIndex <= 0 || splitIndex >= entry.length - 1) {
      continue;
    }

    const identityAuthority = normalizeAuthorityLike(entry.slice(0, splitIndex));
    const nodeAuthorities = entry
      .slice(splitIndex + 1)
      .split("|")
      .map((candidate) => candidate.trim())
      .filter(Boolean);

    if (!identityAuthority) {
      continue;
    }

    const normalizedNodeAuthorities = normalizeTrustAnchorCandidates(nodeAuthorities);
    if (normalizedNodeAuthorities.size > 0) {
      bindings.set(identityAuthority, normalizedNodeAuthorities);
    }
  }

  return bindings;
}

export function isNodeAuthorizedForIdentity({
  identityUri,
  senderNodeId,
  trustAnchorBindings = new Map()
} = {}) {
  const identityAuthority = parseLoomIdentityAuthority(identityUri);
  const senderNodeAuthority = normalizeNodeAuthority(senderNodeId);
  const trustedNodeAuthorities = trustAnchorBindings.get(identityAuthority) || null;

  if (!identityAuthority || !senderNodeAuthority) {
    return {
      valid: false,
      identityAuthority,
      senderNodeAuthority,
      trustedNodeAuthorities: trustedNodeAuthorities ? Array.from(trustedNodeAuthorities) : []
    };
  }

  if (!trustedNodeAuthorities || trustedNodeAuthorities.size === 0) {
    return {
      valid: identityAuthority === senderNodeAuthority,
      identityAuthority,
      senderNodeAuthority,
      trustedNodeAuthorities: []
    };
  }

  return {
    valid: trustedNodeAuthorities.has(senderNodeAuthority),
    identityAuthority,
    senderNodeAuthority,
    trustedNodeAuthorities: Array.from(trustedNodeAuthorities).sort()
  };
}
