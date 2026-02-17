function compareUtf8Lexicographically(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf-8");
  const rightBuffer = Buffer.from(String(right), "utf-8");
  const length = Math.min(leftBuffer.length, rightBuffer.length);

  for (let index = 0; index < length; index += 1) {
    if (leftBuffer[index] !== rightBuffer[index]) {
      return leftBuffer[index] - rightBuffer[index];
    }
  }

  return leftBuffer.length - rightBuffer.length;
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sortValue(item));
  }
  if (value && typeof value === "object") {
    const sorted = {};
    const keys = Object.keys(value).sort(compareUtf8Lexicographically);
    for (const key of keys) {
      sorted[key] = sortValue(value[key]);
    }
    return sorted;
  }
  return value;
}

export function canonicalizeJson(value) {
  const sorted = sortValue(value);
  return JSON.stringify(sorted);
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
