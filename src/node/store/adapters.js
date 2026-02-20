function containsHeaderUnsafeChars(value) {
  return /[\r\n\0]/.test(String(value || ""));
}

export function normalizeEmailAddressAdapter(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (containsHeaderUnsafeChars(trimmed)) {
    return null;
  }

  const angleMatch = trimmed.match(/<([^>]+)>/);
  const candidate = angleMatch ? angleMatch[1].trim() : trimmed.replace(/^<|>$/g, "").trim();

  if (!candidate.includes("@")) {
    return null;
  }
  if (containsHeaderUnsafeChars(candidate)) {
    return null;
  }

  return candidate.toLowerCase();
}

export function splitAddressListAdapter(value) {
  if (Array.isArray(value)) {
    const flattened = [];
    for (const entry of value) {
      flattened.push(...splitAddressListAdapter(String(entry || "")));
    }
    return flattened;
  }

  if (typeof value !== "string") {
    return [];
  }

  const input = value.trim();
  if (!input) {
    return [];
  }

  const items = [];
  let current = "";
  let inQuote = false;
  let angleDepth = 0;
  let escapeNext = false;

  for (const char of input) {
    if (escapeNext) {
      current += char;
      escapeNext = false;
      continue;
    }

    if (char === "\\" && inQuote) {
      current += char;
      escapeNext = true;
      continue;
    }

    if (char === '"') {
      inQuote = !inQuote;
      current += char;
      continue;
    }

    if (!inQuote) {
      if (char === "<") {
        angleDepth += 1;
      } else if (char === ">" && angleDepth > 0) {
        angleDepth -= 1;
      }

      if ((char === "," || char === ";") && angleDepth === 0) {
        if (current.trim()) {
          items.push(current.trim());
        }
        current = "";
        continue;
      }
    }

    current += char;
  }

  if (current.trim()) {
    items.push(current.trim());
  }

  return items;
}

export function normalizeEmailAddressListAdapter(value) {
  return splitAddressListAdapter(value)
    .map((entry) => normalizeEmailAddressAdapter(String(entry || "")))
    .filter(Boolean);
}

export function resolveHeaderValueAdapter(headers, headerName) {
  if (!headers || typeof headers !== "object") {
    return null;
  }

  const target = String(headerName || "").trim().toLowerCase();
  if (!target) {
    return null;
  }

  for (const [key, value] of Object.entries(headers)) {
    if (String(key || "").trim().toLowerCase() === target) {
      return value;
    }
  }

  return null;
}

export function parseMessageIdAdapter(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  const bracketMatch = trimmed.match(/<([^>]+)>/);
  if (bracketMatch?.[1]) {
    return bracketMatch[1].trim();
  }

  const token = trimmed.split(/[\s,]+/).find(Boolean);
  if (!token) {
    return null;
  }

  return token.replace(/^<|>$/g, "").trim() || null;
}

export function parseMessageIdListAdapter(value) {
  if (Array.isArray(value)) {
    const combined = [];
    for (const entry of value) {
      combined.push(...parseMessageIdListAdapter(entry));
    }
    return Array.from(new Set(combined));
  }

  if (typeof value !== "string") {
    return [];
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return [];
  }

  const bracketMatches = trimmed.match(/<[^>]+>/g);
  const tokens = bracketMatches?.length ? bracketMatches : trimmed.split(/[\s,]+/);

  return Array.from(
    new Set(
      tokens
        .map((token) => parseMessageIdAdapter(token))
        .filter(Boolean)
    )
  );
}

export function parseReferencesAdapter(value) {
  return parseMessageIdListAdapter(value);
}

export function inferIdentityFromAddressAdapter(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed.startsWith("loom://") || trimmed.startsWith("bridge://")) {
    return trimmed;
  }

  const email = normalizeEmailAddressAdapter(trimmed);
  if (!email) {
    return null;
  }

  return `loom://${email}`;
}

export function resolveIdentitiesFromAddressInputAdapter(value) {
  return splitAddressListAdapter(value)
    .map((address) => inferIdentityFromAddressAdapter(String(address || "")))
    .filter(Boolean);
}

export function buildRecipientListAdapter({ primary = [], cc = [], bcc = [] } = {}) {
  const recipients = [];
  const byIdentity = new Map();
  const precedence = {
    primary: 3,
    cc: 2,
    bcc: 1
  };

  const addRecipient = (identity, role) => {
    if (!identity) {
      return;
    }

    const existingIndex = byIdentity.get(identity);
    if (existingIndex == null) {
      byIdentity.set(identity, recipients.length);
      recipients.push({
        identity,
        role
      });
      return;
    }

    const existing = recipients[existingIndex];
    if (precedence[role] > precedence[existing.role]) {
      existing.role = role;
    }
  };

  for (const identity of primary) {
    addRecipient(identity, "primary");
  }
  for (const identity of cc) {
    addRecipient(identity, "cc");
  }
  for (const identity of bcc) {
    addRecipient(identity, "bcc");
  }

  if (!recipients.some((recipient) => recipient.role === "primary") && recipients.length > 0) {
    recipients[0].role = "primary";
  }

  return recipients;
}

export function inferEmailFromIdentityAdapter(identity) {
  if (typeof identity !== "string") {
    return null;
  }

  if (identity.startsWith("bridge://")) {
    return identity.slice("bridge://".length);
  }

  if (identity.startsWith("loom://")) {
    return identity.slice("loom://".length);
  }

  return null;
}

export function htmlToTextAdapter(html) {
  if (typeof html !== "string") {
    return "";
  }

  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();
}
