import { ID_PREFIX } from "./constants.js";

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const LOOM_URI_RE = /^loom:\/\/[a-z0-9._-]+@[a-z0-9.-]+$/i;
const BRIDGE_URI_RE = /^bridge:\/\/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;

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
  return typeof value === "string" && LOOM_URI_RE.test(value);
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
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}
