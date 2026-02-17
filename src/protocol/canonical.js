function compareMemberNames(left, right) {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

function assertSupportedPrimitive(value, path) {
  const valueType = typeof value;
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Canonical JSON only supports finite numbers (${path})`);
    }
    return;
  }

  if (valueType === "string" || valueType === "boolean") {
    return;
  }

  if (valueType === "bigint" || valueType === "function" || valueType === "symbol" || valueType === "undefined") {
    throw new TypeError(`Canonical JSON value is not supported (${path})`);
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function serializeCanonicalJson(value, path = "$") {
  if (value == null) {
    return "null";
  }

  if (Array.isArray(value)) {
    const parts = value.map((item, index) => serializeCanonicalJson(item, `${path}[${index}]`));
    return `[${parts.join(",")}]`;
  }

  const valueType = typeof value;
  if (valueType !== "object") {
    assertSupportedPrimitive(value, path);
    return JSON.stringify(value);
  }

  if (!isPlainObject(value)) {
    throw new TypeError(`Canonical JSON requires plain objects (${path})`);
  }

  const keys = Object.keys(value).sort(compareMemberNames);
  const members = keys.map((key) => {
    const memberValue = value[key];
    const memberPath = `${path}.${key}`;
    if (memberValue === undefined) {
      throw new TypeError(`Canonical JSON does not allow undefined values (${memberPath})`);
    }
    return `${JSON.stringify(key)}:${serializeCanonicalJson(memberValue, memberPath)}`;
  });
  return `{${members.join(",")}}`;
}

export function canonicalizeJson(value) {
  return serializeCanonicalJson(value);
}

export function canonicalizeEnvelope(envelope, options = {}) {
  const { topLevelExcludes = ["signature", "meta"] } = options;

  const canonicalCandidate = {};
  for (const [key, value] of Object.entries(envelope || {})) {
    if (!topLevelExcludes.includes(key)) {
      canonicalCandidate[key] = value;
    }
  }

  return canonicalizeJson(canonicalCandidate);
}
