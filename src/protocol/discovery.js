// ─── DNS Discovery — Section 15.1 ───────────────────────────────────────────
//
// SRV/TXT record parsing for LOOM node discovery.

export function parseLoomSrvRecord(srvRecord) {
  // SRV: { priority, weight, port, name }
  if (!srvRecord || typeof srvRecord !== "object") return null;

  return {
    priority: Number(srvRecord.priority) || 0,
    weight: Number(srvRecord.weight) || 0,
    port: Number(srvRecord.port) || 443,
    target: String(srvRecord.name || srvRecord.target || "").replace(/\.$/, "")
  };
}

export function parseLoomTxtRecord(txtRecordParts) {
  // TXT record arrives as array of strings (or array of arrays)
  const text = Array.isArray(txtRecordParts)
    ? txtRecordParts.flat().join("")
    : String(txtRecordParts || "");

  const result = {
    version: null,
    api: null,
    ws: null,
    wellknown: null
  };

  const pairs = text.split(";").map((s) => s.trim()).filter(Boolean);
  for (const pair of pairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx < 0) continue;
    const key = pair.slice(0, eqIdx).trim().toLowerCase();
    const value = pair.slice(eqIdx + 1).trim();

    switch (key) {
      case "v":
        result.version = value;
        break;
      case "api":
        result.api = value;
        break;
      case "ws":
        result.ws = value;
        break;
      case "wellknown":
        result.wellknown = value;
        break;
    }
  }

  return result;
}

export function validateDiscoveryResult(parsed) {
  const errors = [];

  if (!parsed.version) {
    errors.push({ field: "v", reason: "missing LOOM version" });
  } else if (!parsed.version.startsWith("LOOM")) {
    errors.push({ field: "v", reason: "version must start with LOOM" });
  }

  if (!parsed.api) {
    errors.push({ field: "api", reason: "missing API base URL" });
  } else if (!parsed.api.startsWith("https://")) {
    errors.push({ field: "api", reason: "API URL must use HTTPS" });
  }

  if (parsed.ws && !parsed.ws.startsWith("wss://")) {
    errors.push({ field: "ws", reason: "WebSocket URL must use WSS" });
  }

  if (parsed.wellknown && !parsed.wellknown.startsWith("https://")) {
    errors.push({ field: "wellknown", reason: "well-known URL must use HTTPS" });
  }

  return errors;
}

export function buildSrvQueryName(domain) {
  return `_loom._tcp.${domain}`;
}

export function buildTxtQueryName(domain) {
  return `_loom.${domain}`;
}

export function buildWellKnownUrl(domain) {
  return `https://${domain}/.well-known/loom.json`;
}
