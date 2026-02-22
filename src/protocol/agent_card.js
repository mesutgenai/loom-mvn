// ─── A2A Agent Card Protocol Module ──────────────────────────────────────────
//
// Pure-function protocol module. No store or server dependencies.
// Extends agent_info.js with A2A-compatible Agent Card fields:
// skills, supported_intents, authentication, I/O modes, URLs.

import { validateAgentInfo, normalizeAgentInfo } from "./agent_info.js";

// ─── Constants ───────────────────────────────────────────────────────────────

export const AGENT_CARD_SCHEMA_VERSION = "1.0";

export const VALID_AUTHENTICATION_SCHEMES = Object.freeze([
  "bearer",
  "oauth2",
  "api_key",
  "loom_capability",
  "none"
]);

export const VALID_INPUT_MODES = Object.freeze([
  "text",
  "structured",
  "file",
  "multimodal"
]);

export const VALID_OUTPUT_MODES = Object.freeze([
  "text",
  "structured",
  "file",
  "multimodal"
]);

// ─── Skill Definition Validation ─────────────────────────────────────────────

export function isValidSkillDefinition(skill) {
  if (!skill || typeof skill !== "object" || Array.isArray(skill)) {
    return false;
  }
  if (!skill.id || typeof skill.id !== "string") {
    return false;
  }
  if (!skill.name || typeof skill.name !== "string") {
    return false;
  }
  if (skill.description !== undefined && skill.description !== null && typeof skill.description !== "string") {
    return false;
  }
  if (skill.supported_intents !== undefined && skill.supported_intents !== null) {
    if (!Array.isArray(skill.supported_intents)) {
      return false;
    }
    for (const intent of skill.supported_intents) {
      if (typeof intent !== "string") {
        return false;
      }
    }
  }
  return true;
}

// ─── Agent Card Validation ───────────────────────────────────────────────────

export function validateAgentCard(card) {
  const errors = [];

  if (!card || typeof card !== "object" || Array.isArray(card)) {
    errors.push({ field: "agent_card", reason: "must be a non-null object" });
    return errors;
  }

  // Delegate base field validation to agent_info
  const baseErrors = validateAgentInfo(card);
  errors.push(...baseErrors);

  // ── skills ─────────────────────────────────────────────────────────────
  if (card.skills !== undefined && card.skills !== null) {
    if (!Array.isArray(card.skills)) {
      errors.push({ field: "agent_card.skills", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < card.skills.length; i++) {
        if (!isValidSkillDefinition(card.skills[i])) {
          errors.push({ field: `agent_card.skills[${i}]`, reason: "must have string id and name" });
        }
      }
    }
  }

  // ── supported_intents ──────────────────────────────────────────────────
  if (card.supported_intents !== undefined && card.supported_intents !== null) {
    if (!Array.isArray(card.supported_intents)) {
      errors.push({ field: "agent_card.supported_intents", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < card.supported_intents.length; i++) {
        if (typeof card.supported_intents[i] !== "string") {
          errors.push({ field: `agent_card.supported_intents[${i}]`, reason: "must be a string" });
          break;
        }
      }
    }
  }

  // ── authentication ─────────────────────────────────────────────────────
  if (card.authentication !== undefined && card.authentication !== null) {
    if (!Array.isArray(card.authentication)) {
      errors.push({ field: "agent_card.authentication", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < card.authentication.length; i++) {
        const auth = card.authentication[i];
        if (!auth || typeof auth !== "object" || Array.isArray(auth)) {
          errors.push({ field: `agent_card.authentication[${i}]`, reason: "must be an object" });
          continue;
        }
        if (!auth.scheme || typeof auth.scheme !== "string") {
          errors.push({ field: `agent_card.authentication[${i}].scheme`, reason: "required string" });
        } else if (!VALID_AUTHENTICATION_SCHEMES.includes(auth.scheme)) {
          errors.push({ field: `agent_card.authentication[${i}].scheme`, reason: `must be one of: ${VALID_AUTHENTICATION_SCHEMES.join(", ")}` });
        }
      }
    }
  }

  // ── default_input_modes ────────────────────────────────────────────────
  if (card.default_input_modes !== undefined && card.default_input_modes !== null) {
    if (!Array.isArray(card.default_input_modes)) {
      errors.push({ field: "agent_card.default_input_modes", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < card.default_input_modes.length; i++) {
        if (!VALID_INPUT_MODES.includes(card.default_input_modes[i])) {
          errors.push({ field: `agent_card.default_input_modes[${i}]`, reason: `must be one of: ${VALID_INPUT_MODES.join(", ")}` });
          break;
        }
      }
    }
  }

  // ── default_output_modes ───────────────────────────────────────────────
  if (card.default_output_modes !== undefined && card.default_output_modes !== null) {
    if (!Array.isArray(card.default_output_modes)) {
      errors.push({ field: "agent_card.default_output_modes", reason: "must be an array if provided" });
    } else {
      for (let i = 0; i < card.default_output_modes.length; i++) {
        if (!VALID_OUTPUT_MODES.includes(card.default_output_modes[i])) {
          errors.push({ field: `agent_card.default_output_modes[${i}]`, reason: `must be one of: ${VALID_OUTPUT_MODES.join(", ")}` });
          break;
        }
      }
    }
  }

  // ── url / documentation_url ────────────────────────────────────────────
  if (card.url !== undefined && card.url !== null && typeof card.url !== "string") {
    errors.push({ field: "agent_card.url", reason: "must be a string if provided" });
  }
  if (card.documentation_url !== undefined && card.documentation_url !== null && typeof card.documentation_url !== "string") {
    errors.push({ field: "agent_card.documentation_url", reason: "must be a string if provided" });
  }

  return errors;
}

// ─── Agent Card Normalization ────────────────────────────────────────────────

export function normalizeAgentCard(card) {
  if (!card || typeof card !== "object" || Array.isArray(card)) {
    return null;
  }

  // Normalize base agent_info fields
  const base = normalizeAgentInfo(card);
  if (!base) {
    return null;
  }

  // Normalize skills
  let skills = [];
  if (Array.isArray(card.skills)) {
    skills = card.skills
      .filter((s) => isValidSkillDefinition(s))
      .map((s) => ({
        id: s.id,
        name: s.name,
        description: typeof s.description === "string" ? s.description : null,
        supported_intents: Array.isArray(s.supported_intents)
          ? s.supported_intents.filter((i) => typeof i === "string")
          : []
      }));
  }

  // Normalize supported_intents
  const supportedIntents = Array.isArray(card.supported_intents)
    ? card.supported_intents.filter((i) => typeof i === "string")
    : [];

  // Normalize authentication
  let authentication = [];
  if (Array.isArray(card.authentication)) {
    authentication = card.authentication
      .filter((a) => a && typeof a === "object" && !Array.isArray(a) && VALID_AUTHENTICATION_SCHEMES.includes(a.scheme))
      .map((a) => ({
        scheme: a.scheme,
        ...(typeof a.description === "string" ? { description: a.description } : {})
      }));
  }

  // Normalize input/output modes
  const defaultInputModes = Array.isArray(card.default_input_modes)
    ? card.default_input_modes.filter((m) => VALID_INPUT_MODES.includes(m))
    : [];
  const defaultOutputModes = Array.isArray(card.default_output_modes)
    ? card.default_output_modes.filter((m) => VALID_OUTPUT_MODES.includes(m))
    : [];

  return {
    ...base,
    skills,
    supported_intents: supportedIntents,
    authentication,
    default_input_modes: defaultInputModes,
    default_output_modes: defaultOutputModes,
    url: typeof card.url === "string" ? card.url : null,
    documentation_url: typeof card.documentation_url === "string" ? card.documentation_url : null,
    card_version: AGENT_CARD_SCHEMA_VERSION
  };
}

// ─── Build Agent Card from agent_info ────────────────────────────────────────

export function buildAgentCardFromInfo(agentInfo, extensions = {}) {
  const base = normalizeAgentInfo(agentInfo);
  if (!base) {
    return null;
  }

  const merged = { ...base, ...(extensions || {}) };
  return normalizeAgentCard(merged);
}
