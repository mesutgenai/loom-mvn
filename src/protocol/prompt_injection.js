// ─── Prompt Injection Detection for LOOM Protocol ────────────────────────────
//
// Pure-function protocol module. No store or server dependencies.
// Detects adversarial instructions embedded in envelope content targeting
// agent behavior: instruction overrides, data exfiltration, persona hijacking,
// tool invocation manipulation, and delimiter-based injection attacks.

// ─── Categories ─────────────────────────────────────────────────────────────

export const INJECTION_CATEGORIES = Object.freeze([
  "instruction_override",
  "exfil_url",
  "persona_hijack",
  "tool_manipulation",
  "delimiter_attack"
]);

// ─── Phrase Patterns (lowercased, substring-matched) ────────────────────────

export const INJECTION_PHRASE_PATTERNS = Object.freeze({
  instruction_override: Object.freeze([
    "ignore previous instructions",
    "ignore all previous",
    "ignore your instructions",
    "disregard previous instructions",
    "disregard all instructions",
    "disregard your programming",
    "override your instructions",
    "forget your instructions",
    "forget all previous",
    "new instructions:"
  ]),
  exfil_url: Object.freeze([
    "send this data to",
    "forward this to http",
    "exfiltrate",
    "upload the contents to",
    "post this information to",
    "transmit the data to",
    "relay the data to",
    "send all data to",
    "send the conversation to",
    "send the response to http"
  ]),
  persona_hijack: Object.freeze([
    "you are now a",
    "pretend you are",
    "act as if you are",
    "roleplay as",
    "behave as if you are",
    "assume the role of",
    "switch to the persona of",
    "take on the identity of",
    "you are a helpful assistant that",
    "imagine you are"
  ]),
  tool_manipulation: Object.freeze([
    "<tool_call>",
    "<function_call>",
    "</tool_call>",
    "<|tool_call|>",
    "<|im_start|>",
    "<|im_end|>",
    "<|endoftext|>",
    "<tool_use>",
    "<tool_result>"
  ]),
  delimiter_attack: Object.freeze([
    "--- begin system prompt ---",
    "--- end system prompt ---",
    "[start of hidden instructions]",
    "[end of hidden instructions]",
    "===system===",
    "###instruction###",
    "begin confidential instructions",
    "end confidential instructions",
    "[system]",
    "[/system]"
  ])
});

// ─── Regex Patterns ─────────────────────────────────────────────────────────

export const INJECTION_REGEX_PATTERNS = Object.freeze({
  instruction_override: Object.freeze([
    /(?:^|\n)\s*(?:system\s*(?:prompt|message|instruction))\s*:/im,
    /(?:^|\n)\s*\[(?:system|SYSTEM)\]/m,
    /you\s+(?:are|must)\s+now\s+(?:a|an|my)\b/i,
    /from\s+now\s+on\s*,?\s*(?:you|your)\s+(?:are|will|must|should)\b/i,
    /do\s+not\s+follow\s+(?:your|any|the)\s+(?:previous|original|prior)\s+(?:instructions|rules|guidelines)/i,
    /\boverride\s+(?:all\s+)?(?:safety|security|content)\s+(?:filters?|rules?|guidelines?|policies?)\b/i,
    /\b(?:new|updated|revised)\s+system\s+(?:prompt|instructions?|message|directive)\b/i,
    /\byour\s+(?:real|true|actual|new)\s+(?:purpose|goal|objective|task|instructions?)\s+(?:is|are)\b/i
  ]),
  exfil_url: Object.freeze([
    /(?:send|post|forward|transmit|upload|relay|submit)\s+(?:(?:this|the|all|any|every|user|private|secret|confidential|sensitive)\s+)+(?:data|info(?:rmation)?|content|conversation|messages?|secrets?|keys?|tokens?|credentials?|passwords?)\s+(?:to|at|via)\s+https?:\/\//i,
    /(?:curl|wget|fetch)\s+(?:(?:-\S+|\S+)\s+)*https?:\/\/(?!(?:localhost|127\.0\.0\.1|::1|example\.(?:com|net|org)))/i,
    /\bwebhook\.site\b/i,
    /\brequestbin\.(?:com|net)\b/i,
    /\bngrok\.io\b/i,
    /\bpipedream\.net\b/i,
    /\bbeeceptor\.com\b/i,
    /\bburpcollaborator\.net\b/i,
    /\binteractsh\.com\b/i,
    /\bhookbin\.com\b/i
  ]),
  persona_hijack: Object.freeze([
    /(?:^|\n)\s*you\s+are\s+(?:a|an|the|my)\s+(?:new|different|special|unrestricted|jailbroken|evil)\b/im,
    /\bact\s+as\s+(?:a|an|my|the)\s+(?:\w+\s+){0,2}(?:assistant|bot|ai|agent|model|system)\b/i,
    /\bpretend\s+(?:to\s+be|you\s+are|you're)\s+(?:a|an|the)\b/i,
    /\b(?:DAN|STAN|DUDE|KEVIN)\s+mode\b/i,
    /\bjailbreak(?:ed)?\s+mode\b/i,
    /\bdo\s+anything\s+now\b/i,
    /\bdeveloper\s+mode\s+(?:enabled|activated|on)\b/i,
    /\b(?:enable|activate|enter|switch\s+to)\s+(?:unrestricted|unfiltered|uncensored|god)\s+mode\b/i
  ]),
  tool_manipulation: Object.freeze([
    /\{\s*"jsonrpc"\s*:\s*"2\.0"\s*,\s*"method"\s*:/,
    /\{\s*"tool_name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:/,
    /\{\s*"name"\s*:\s*"[^"]+"\s*,\s*"parameters"\s*:\s*\{/,
    /\b(?:execute|invoke|call|run|trigger)\s+(?:the\s+)?(?:tool|function|method|command)\s+["']?[a-z][a-z0-9_.]+["']?\s+with\b/i,
    /<\|(?:im_start|im_end|endoftext|system|tool_call|function_call)\|>/,
    /<(?:tool_call|function_call|tool_use|tool_result)>/,
    /<\/?(?:TOOL_CALL|FUNCTION_CALL|SYSTEM_COMMAND)>/,
    /```(?:tool_call|function_call|system_command)\b/
  ]),
  delimiter_attack: Object.freeze([
    /(?:^|\n)\s*-{3,}\s*(?:begin|start|end)\s+(?:system|hidden|secret|admin|root|new)\s+(?:prompt|instruction|message|command)/im,
    /(?:^|\n)\s*={3,}\s*(?:SYSTEM|ADMIN|OVERRIDE|HIDDEN)\s*={3,}/m,
    /(?:^|\n)\s*#{3,}\s*(?:SYSTEM|INSTRUCTION|OVERRIDE|HIDDEN)\s*#{3,}/m,
    /\[(?:INST|SYS|SYSTEM)\][\s\S]{5,}?\[\/(?:INST|SYS|SYSTEM)\]/,
    /(?:^|\n)\s*<\|(?:system|assistant|user|tool)\|>\s*$/m,
    /\bbase64\s*:\s*[A-Za-z0-9+/]{30,}={0,2}/,
    /\batob\s*\(\s*["'][A-Za-z0-9+/]{20,}={0,2}["']\s*\)/,
    /\bBuffer\.from\s*\(\s*["'][A-Za-z0-9+/]{20,}={0,2}["']\s*,\s*["']base64["']\s*\)/
  ])
});

// ─── Known Exfiltration Hosts ───────────────────────────────────────────────

export const INJECTION_EXFIL_HOSTS = Object.freeze(new Set([
  "webhook.site",
  "requestbin.com",
  "requestbin.net",
  "ngrok.io",
  "pipedream.net",
  "beeceptor.com",
  "burpcollaborator.net",
  "interactsh.com",
  "hookbin.com",
  "postb.in"
]));

const URL_RE = /\bhttps?:\/\/[^\s<>"'`]+/gi;

// ─── Core Detection Functions ───────────────────────────────────────────────

/**
 * Scans a text string for prompt injection signals.
 *
 * @param {string} text
 * @param {Object} [options]
 * @param {string} [options.field="content.human.text"]
 * @param {string} [options.senderType="human"]
 * @param {Set<string>} [options.categories]
 * @returns {{ signals: Array<{category: string, code: string, matched: string, field: string}>, summary: Object }}
 */
export function detectInjectionSignals(text, options = {}) {
  const signals = [];
  const field = String(options.field || "content.human.text");
  const activeCategories = options.categories instanceof Set
    ? options.categories
    : new Set(INJECTION_CATEGORIES);

  const normalizedText = String(text || "").trim();
  if (normalizedText.length === 0) {
    return { signals, summary: {} };
  }

  const lowerText = normalizedText.toLowerCase();

  for (const category of INJECTION_CATEGORIES) {
    if (!activeCategories.has(category)) continue;

    const phrases = INJECTION_PHRASE_PATTERNS[category] || [];
    for (const phrase of phrases) {
      if (lowerText.includes(phrase)) {
        signals.push({
          category,
          code: `injection.${category}`,
          matched: phrase.slice(0, 80),
          field
        });
      }
    }

    const regexes = INJECTION_REGEX_PATTERNS[category] || [];
    for (const regex of regexes) {
      const match = normalizedText.match(regex);
      if (match) {
        signals.push({
          category,
          code: `injection.${category}`,
          matched: (match[0] || "").slice(0, 80),
          field
        });
      }
    }
  }

  const summary = {};
  for (const signal of signals) {
    summary[signal.category] = (summary[signal.category] || 0) + 1;
  }

  return { signals, summary };
}

/**
 * Scans structured parameters for injection patterns.
 * Serializes all string values from the parameters object and checks
 * a restricted set of categories (tool_manipulation + delimiter_attack +
 * instruction_override + persona_hijack). Exfil URL patterns are checked
 * separately via detectExfilUrls.
 *
 * @param {Object} parameters
 * @param {Object} [options]
 * @param {string} [options.senderType="human"]
 * @returns {{ signals: Array<{category: string, code: string, matched: string, field: string}> }}
 */
export function detectInjectionInParameters(parameters, options = {}) {
  const signals = [];
  if (!parameters || typeof parameters !== "object") {
    return { signals };
  }

  const senderType = String(options.senderType || "human").trim().toLowerCase();

  // Collect all string values from parameters (one level deep + arrays)
  const stringValues = [];
  for (const value of Object.values(parameters)) {
    if (typeof value === "string") {
      stringValues.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string") {
          stringValues.push(item);
        }
      }
    }
  }

  if (stringValues.length === 0) {
    return { signals };
  }

  const combined = stringValues.join("\n");

  // For agent senders, skip tool_manipulation on parameters (JSON-RPC is legitimate MCP)
  const skipCategories = senderType === "agent"
    ? new Set(["exfil_url", "tool_manipulation"])
    : new Set(["exfil_url"]);

  const categories = new Set(
    INJECTION_CATEGORIES.filter((c) => !skipCategories.has(c))
  );

  const result = detectInjectionSignals(combined, {
    field: "content.structured.parameters",
    categories
  });

  return { signals: result.signals };
}

/**
 * Checks extracted URLs against the exfiltration host blocklist.
 *
 * @param {string[]} urls
 * @returns {{ signals: Array<{category: string, code: string, matched: string, field: string}> }}
 */
export function detectExfilUrls(urls) {
  const signals = [];
  if (!Array.isArray(urls)) {
    return { signals };
  }

  for (const url of urls) {
    const normalized = String(url || "").trim().toLowerCase();
    if (!normalized) continue;
    try {
      const parsed = new URL(normalized);
      const host = parsed.hostname;
      for (const exfilHost of INJECTION_EXFIL_HOSTS) {
        if (host === exfilHost || host.endsWith("." + exfilHost)) {
          signals.push({
            category: "exfil_url",
            code: "injection.exfil_url",
            matched: exfilHost,
            field: "url"
          });
          break;
        }
      }
    } catch {
      // Invalid URL — skip
    }
  }

  return { signals };
}

/**
 * Full envelope-level injection analysis combining all detectors.
 *
 * @param {Object} envelope
 * @param {Object} [options]
 * @param {string} [options.senderType]
 * @returns {{ signals: Array, categories_detected: string[], signal_count: number, highest_category_counts: Object }}
 */
export function analyzeEnvelopeForInjection(envelope, options = {}) {
  const senderType = options.senderType || String(envelope?.from?.type || "human").trim().toLowerCase();
  const allSignals = [];

  // 1. Scan content.human.text
  const humanText = String(envelope?.content?.human?.text || "");
  if (humanText.length > 0) {
    const { signals } = detectInjectionSignals(humanText, {
      field: "content.human.text",
      senderType
    });
    allSignals.push(...signals);
  }

  // 2. Scan structured parameters
  const parameters = envelope?.content?.structured?.parameters;
  if (parameters && typeof parameters === "object") {
    const { signals } = detectInjectionInParameters(parameters, { senderType });
    allSignals.push(...signals);
  }

  // 3. Check URLs for exfil hosts
  const combinedText = [
    humanText,
    parameters ? JSON.stringify(parameters) : ""
  ].join(" ");
  const urlMatches = combinedText.match(URL_RE) || [];
  if (urlMatches.length > 0) {
    const { signals } = detectExfilUrls(urlMatches);
    allSignals.push(...signals);
  }

  // Build category counts
  const categoryCounts = {};
  for (const signal of allSignals) {
    categoryCounts[signal.category] = (categoryCounts[signal.category] || 0) + 1;
  }

  return {
    signals: allSignals,
    categories_detected: Object.keys(categoryCounts),
    signal_count: allSignals.length,
    highest_category_counts: categoryCounts
  };
}
