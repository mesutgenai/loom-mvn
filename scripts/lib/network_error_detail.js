function cleanMessage(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function buildTargetLabel(method, url) {
  const normalizedMethod = String(method || "GET")
    .trim()
    .toUpperCase();
  const normalizedUrl = cleanMessage(url);
  if (!normalizedUrl) {
    return normalizedMethod;
  }
  return `${normalizedMethod} ${normalizedUrl}`;
}

export function describeNetworkRequestError({ error, method = "GET", url = "", timeoutMs = 0 } = {}) {
  const target = buildTargetLabel(method, url);
  const name = String(error?.name || "").trim();

  if (name === "AbortError") {
    const timeoutLabel = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? `${Number(timeoutMs)}ms` : "timeout";
    return `Request timed out after ${timeoutLabel} (${target}).`;
  }

  const baseMessage = cleanMessage(error?.message || String(error) || "request failed");
  const cause = error?.cause && typeof error.cause === "object" ? error.cause : null;
  const details = [];

  if (cause) {
    const causeCode = cleanMessage(cause.code);
    const causeSyscall = cleanMessage(cause.syscall);
    const causeAddress = cleanMessage(cause.address || cause.hostname);
    const causePort = cause.port;
    const causeMessage = cleanMessage(cause.message);

    if (causeCode) {
      details.push(`code=${causeCode}`);
    }
    if (causeSyscall) {
      details.push(`syscall=${causeSyscall}`);
    }
    if (causeAddress) {
      details.push(`address=${causeAddress}`);
    }
    if (causePort != null && causePort !== "") {
      details.push(`port=${String(causePort)}`);
    }
    if (causeMessage && causeMessage !== baseMessage) {
      details.push(`cause=${causeMessage}`);
    }
  }

  const tlsProbe = [baseMessage, cleanMessage(cause?.message), cleanMessage(cause?.code)].join(" ").toLowerCase();
  if (/self signed|unable to verify|certificate|cert_/.test(tlsProbe)) {
    details.push("tls=certificate-validation-failed");
  }

  if (details.length === 0) {
    return `Request failed (${target}): ${baseMessage}.`;
  }
  return `Request failed (${target}): ${baseMessage} [${details.join(", ")}].`;
}
