/**
 * Shared environment / configuration parsing helpers.
 *
 * Every module in src/node/ previously carried its own copy of these
 * functions. They are consolidated here to avoid drift.
 */

export function parseBoolean(value, fallback = false) {
  if (value == null) {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}

export function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function parsePositiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function parseHostAllowlist(value) {
  if (value == null) {
    return [];
  }

  const list = Array.isArray(value) ? value : String(value).split(",");
  return Array.from(
    new Set(
      list
        .map((entry) =>
          String(entry || "")
            .trim()
            .toLowerCase()
            .replace(/\.+$/, "")
        )
        .filter(Boolean)
    )
  );
}
