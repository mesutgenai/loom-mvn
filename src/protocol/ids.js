import { ID_PREFIX } from "./constants.js";

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const LOOM_LOCAL_PART_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DOMAIN_LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const BRIDGE_URI_RE = /^bridge:\/\/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const STRICT_ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function splitLoomIdentity(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith("loom://")) {
    return null;
  }

  const raw = trimmed.slice("loom://".length);
  const atIndex = raw.indexOf("@");
  if (atIndex <= 0 || atIndex >= raw.length - 1) {
    return null;
  }

  const localPart = raw.slice(0, atIndex);
  const domain = raw.slice(atIndex + 1);
  return {
    localPart,
    domain
  };
}

function isValidDomain(domain) {
  if (typeof domain !== "string") {
    return false;
  }

  if (domain.length < 1 || domain.length > 253) {
    return false;
  }

  const labels = domain.split(".");
  if (labels.some((label) => label.length === 0)) {
    return false;
  }

  return labels.every((label) => DOMAIN_LABEL_RE.test(label));
}

export function normalizeLoomIdentity(value) {
  const parts = splitLoomIdentity(value);
  if (!parts) {
    return null;
  }

  const localPart = parts.localPart.toLowerCase();
  const domain = parts.domain.toLowerCase();
  if (!LOOM_LOCAL_PART_RE.test(localPart)) {
    return null;
  }

  if (!isValidDomain(domain)) {
    return null;
  }

  return `loom://${localPart}@${domain}`;
}

export function isUlid(value) {
  return typeof value === "string" && ULID_RE.test(value);
}

export function hasTypedUlid(value, prefix) {
  if (typeof value !== "string" || typeof prefix !== "string") {
    return false;
  }
  if (!value.startsWith(prefix)) {
    return false;
  }
  return isUlid(value.slice(prefix.length));
}

export function isEnvelopeId(value) {
  return hasTypedUlid(value, ID_PREFIX.envelope);
}

export function isThreadId(value) {
  return hasTypedUlid(value, ID_PREFIX.thread);
}

export function isCapabilityId(value) {
  return hasTypedUlid(value, ID_PREFIX.capability);
}

export function isEventId(value) {
  return hasTypedUlid(value, ID_PREFIX.event);
}

export function isLoomIdentity(value) {
  if (typeof value !== "string") {
    return false;
  }
  const normalized = normalizeLoomIdentity(value);
  return normalized != null && normalized === value;
}

export function isBridgeIdentity(value) {
  return typeof value === "string" && BRIDGE_URI_RE.test(value);
}

export function isIdentity(value) {
  return isLoomIdentity(value) || isBridgeIdentity(value);
}

export function isIsoDateTime(value) {
  if (typeof value !== "string") {
    return false;
  }

  if (!STRICT_ISO_UTC_RE.test(value)) {
    return false;
  }

  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    return false;
  }

  const iso = new Date(parsed).toISOString();
  if (value.endsWith("Z") && value.includes(".")) {
    return iso === value;
  }

  return iso === `${value.slice(0, -1)}.000Z`;
}
