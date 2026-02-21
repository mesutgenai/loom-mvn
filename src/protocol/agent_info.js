// ─── Inference Provider Abstraction — agent_info Validation & Normalization ──

const VALID_AGENT_INFO_FIELDS = new Set(["provider", "model", "version", "capabilities"]);

export function validateAgentInfo(agentInfo) {
  const errors = [];
  if (!agentInfo || typeof agentInfo !== "object" || Array.isArray(agentInfo)) {
    errors.push({ field: "agent_info", reason: "must be a non-null object" });
    return errors;
  }

  if (!agentInfo.provider || typeof agentInfo.provider !== "string") {
    errors.push({ field: "agent_info.provider", reason: "required non-empty string" });
  }

  if (!agentInfo.model || typeof agentInfo.model !== "string") {
    errors.push({ field: "agent_info.model", reason: "required non-empty string" });
  }

  if (agentInfo.version !== undefined && agentInfo.version !== null && typeof agentInfo.version !== "string") {
    errors.push({ field: "agent_info.version", reason: "must be a string if provided" });
  }

  if (agentInfo.capabilities !== undefined && agentInfo.capabilities !== null) {
    if (!Array.isArray(agentInfo.capabilities)) {
      errors.push({ field: "agent_info.capabilities", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < agentInfo.capabilities.length; i++) {
        if (typeof agentInfo.capabilities[i] !== "string") {
          errors.push({ field: `agent_info.capabilities[${i}]`, reason: "must be a string" });
          break;
        }
      }
    }
  }

  return errors;
}

export function normalizeAgentInfo(agentInfo) {
  if (!agentInfo || typeof agentInfo !== "object" || Array.isArray(agentInfo)) {
    return null;
  }

  if (!agentInfo.provider || typeof agentInfo.provider !== "string") {
    return null;
  }

  if (!agentInfo.model || typeof agentInfo.model !== "string") {
    return null;
  }

  return {
    provider: agentInfo.provider,
    model: agentInfo.model,
    version: typeof agentInfo.version === "string" ? agentInfo.version : null,
    capabilities: Array.isArray(agentInfo.capabilities)
      ? agentInfo.capabilities.filter((c) => typeof c === "string")
      : []
  };
}
