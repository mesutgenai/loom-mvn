function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sortValue(item));
  }
  if (value && typeof value === "object") {
    const sorted = {};
    const keys = Object.keys(value).sort((a, b) => a.localeCompare(b));
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
