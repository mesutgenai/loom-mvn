function compareMemberNames(left, right) {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

function assertValidUnicodeString(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const nextCodeUnit = value.charCodeAt(index + 1);
      if (!(nextCodeUnit >= 0xdc00 && nextCodeUnit <= 0xdfff)) {
        throw new TypeError(`Canonical JSON does not allow unpaired surrogate code points (${path})`);
      }
      index += 1;
      continue;
    }

    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`Canonical JSON does not allow unpaired surrogate code points (${path})`);
    }
  }
}

/**
 * Serialize a finite IEEE 754 double according to RFC 8785 (JCS) Section 3.2.2.3.
 *
 * Key rules:
 *   - Negative zero serializes as "0"
 *   - Integers serialize without a decimal point
 *   - Non-integer values use the shortest representation (ES2024 Number::toString already does this)
 *   - Exponent notation uses lowercase 'e' (ES engines already produce lowercase)
 *
 * V8/Node already conforms to RFC 8785 number serialization because both follow
 * the ECMAScript specification for Number::toString, which RFC 8785 explicitly references.
 * This function makes that contract explicit and guards against engine deviations.
 */
function serializeNumberJCS(value, path) {
  if (!Number.isFinite(value)) {
    throw new TypeError(`Canonical JSON only supports finite numbers (${path})`);
  }
  if (Object.is(value, -0)) {
    return "0";
  }
  const str = String(value);
  return str;
}

function assertSupportedPrimitive(value, path) {
  const valueType = typeof value;
  if (valueType === "number") {
    serializeNumberJCS(value, path);
    return;
  }

  if (valueType === "string") {
    assertValidUnicodeString(value, path);
    return;
  }

  if (valueType === "boolean") {
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
    if (valueType === "number") {
      return serializeNumberJCS(value, path);
    }
    return JSON.stringify(value);
  }

  if (!isPlainObject(value)) {
    throw new TypeError(`Canonical JSON requires plain objects (${path})`);
  }

  const keys = Object.keys(value).sort(compareMemberNames);
  const members = keys.map((key) => {
    const memberValue = value[key];
    const memberPath = `${path}.${key}`;
    assertValidUnicodeString(key, `${path}.<key>`);
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
