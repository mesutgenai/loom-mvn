#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

import { generateSigningKeyPair, signEnvelope, signUtf8Message, verifyUtf8MessageSignature } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { describeNetworkRequestError } from "./lib/network_error_detail.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";
const DEFAULT_OUTPUT_DIR = "scripts/output/federation-interop-drills";
const DEFAULT_TIMEOUT_MS = 15000;

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function nowStamp() {
  const date = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "T",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
    "Z"
  ].join("");
}

function randomSuffix() {
  return Math.random().toString(36).slice(2, 10);
}

function parseArgs(argv) {
  const args = {
    baseUrl: process.env.LOOM_BASE_URL || DEFAULT_BASE_URL,
    adminToken: process.env.LOOM_ADMIN_TOKEN || "",
    remoteNodeId: process.env.LOOM_INTEROP_REMOTE_NODE_ID || "interop-remote.test",
    remoteNodeKeyId: process.env.LOOM_INTEROP_REMOTE_NODE_KEY_ID || "k_node_sign_interop_remote_1",
    timeoutMs: parsePositiveInt(process.env.LOOM_INTEROP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    outputDir: process.env.LOOM_INTEROP_OUTPUT_DIR || DEFAULT_OUTPUT_DIR,
    drillId: `interop-${nowStamp()}`,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--base-url" && i + 1 < argv.length) {
      args.baseUrl = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--remote-node-id" && i + 1 < argv.length) {
      args.remoteNodeId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--remote-node-key-id" && i + 1 < argv.length) {
      args.remoteNodeKeyId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], DEFAULT_TIMEOUT_MS);
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      args.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--drill-id" && i + 1 < argv.length) {
      args.drillId = argv[i + 1];
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_federation_interop_drill.js [options]

Options:
  --base-url <url>           Target LOOM base URL (default: ${DEFAULT_BASE_URL})
  --admin-token <token>      Admin token (or LOOM_ADMIN_TOKEN env)
  --remote-node-id <id>      Remote node ID to emulate (default: interop-remote.test)
  --remote-node-key-id <id>  Remote node signing key id
  --timeout-ms <int>         Request timeout in ms (default: ${DEFAULT_TIMEOUT_MS})
  --output-dir <path>        Output directory (default: ${DEFAULT_OUTPUT_DIR})
  --drill-id <id>            Override drill ID
  -h, --help                 Show help

Example:
  npm run drill:federation-interop -- --base-url https://loom.example.com --admin-token <token>
`);
}

function normalizeBaseUrl(raw) {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("base URL must use http or https");
    }
    if (!url.pathname.endsWith("/")) {
      url.pathname = `${url.pathname}/`;
    }
    return url.toString();
  } catch (error) {
    throw new Error(`Invalid --base-url: ${raw} (${error.message})`);
  }
}

async function requestJson(baseUrl, path, options = {}) {
  const url = new URL(path, baseUrl).toString();
  const method = options.method || "GET";
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    try {
      const response = await fetch(url, {
        method,
        headers: options.headers || {},
        body: options.body,
        signal: controller.signal
      });
      const text = await response.text();
      let json = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = null;
      }
      return { url, response, status: response.status, text, json };
    } catch (error) {
      const message = describeNetworkRequestError({ error, method, url, timeoutMs });
      throw new Error(message, { cause: error });
    }
  } finally {
    clearTimeout(timer);
  }
}

function canonicalizeFederationReceipt(receipt) {
  const acceptedIds = Array.isArray(receipt?.accepted_envelope_ids)
    ? receipt.accepted_envelope_ids.map((id) => String(id || "").trim()).filter(Boolean)
    : [];
  return [
    String(receipt?.loom || ""),
    String(receipt?.type || ""),
    String(receipt?.delivery_id || ""),
    String(receipt?.sender_node || ""),
    String(receipt?.recipient_node || ""),
    String(receipt?.status || ""),
    String(receipt?.accepted_count ?? ""),
    acceptedIds.join(","),
    String(receipt?.timestamp || "")
  ].join("\n");
}

function buildSignedFederationHeaders({ nodeId, keyId, nonce, path, rawBody, privateKeyPem }) {
  const timestamp = new Date().toISOString();
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
  return {
    "x-loom-node": nodeId,
    "x-loom-timestamp": timestamp,
    "x-loom-nonce": nonce,
    "x-loom-key-id": keyId,
    "x-loom-signature": signUtf8Message(privateKeyPem, canonical)
  };
}

function assertStatus(result, expectedStatus, label) {
  if (result.status !== expectedStatus) {
    throw new Error(`${label} failed (expected HTTP ${expectedStatus}, got ${result.status})`);
  }
}

function buildSummary(report, reportPath) {
  const lines = [];
  lines.push("# Federation Interop Drill Report");
  lines.push("");
  lines.push(`- Drill ID: \`${report.drill_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Base URL: \`${report.base_url}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push("");
  lines.push("## Verified Flow");
  lines.push("");
  lines.push("- Federation challenge token issue");
  lines.push("- Signed federation delivery");
  lines.push("- Signed delivery receipt verification");
  lines.push("- Nonce replay guard rejection");
  lines.push("");
  lines.push(`- Report JSON: \`${reportPath}\``);
  if (report.failure) {
    lines.push(`- Failure: \`${report.failure}\``);
  }
  return lines.join("\n") + "\n";
}

async function runDrill(args) {
  if (!String(args.adminToken || "").trim()) {
    throw new Error("Admin token is required for interop drill setup (--admin-token or LOOM_ADMIN_TOKEN).");
  }

  const baseUrl = normalizeBaseUrl(args.baseUrl);
  const suffix = randomSuffix();
  const localAdminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  const report = {
    drill_id: args.drillId,
    started_at: new Date().toISOString(),
    base_url: baseUrl,
    remote_node_id: args.remoteNodeId,
    success: false,
    steps: []
  };

  function pushStep(name, result) {
    report.steps.push({
      name,
      status: result.status,
      ok: result.response ? result.response.ok : false,
      url: result.url,
      response_body: result.json || result.text || null
    });
  }

  try {
    const nodeDocument = await requestJson(baseUrl, "/.well-known/loom.json", {
      timeoutMs: args.timeoutMs
    });
    pushStep("fetch_node_document", nodeDocument);
    assertStatus(nodeDocument, 200, "Fetch node document");
    const targetNodeId = String(nodeDocument.json?.node_id || "").trim();
    if (!targetNodeId) {
      throw new Error("Target node document is missing node_id.");
    }

    const localAdminIdentity = `loom://interop-admin-${suffix}@${targetNodeId}`;
    const localAdminKeyId = `k_sign_interop_admin_${suffix}`;
    const remoteSenderIdentity = `loom://interop-sender-${suffix}@${args.remoteNodeId}`;
    const remoteSenderKeyId = `k_sign_interop_sender_${suffix}`;

    const registerLocalAdmin = await requestJson(baseUrl, "/v1/identity", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json",
        "x-loom-admin-token": args.adminToken
      },
      body: JSON.stringify({
        id: localAdminIdentity,
        display_name: "Interop Admin",
        signing_keys: [{ key_id: localAdminKeyId, public_key_pem: localAdminKeys.publicKeyPem }]
      })
    });
    pushStep("register_local_admin_identity", registerLocalAdmin);
    assertStatus(registerLocalAdmin, 201, "Register local admin identity");

    const authChallenge = await requestJson(baseUrl, "/v1/auth/challenge", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        identity: localAdminIdentity,
        key_id: localAdminKeyId
      })
    });
    pushStep("issue_local_auth_challenge", authChallenge);
    assertStatus(authChallenge, 200, "Issue local auth challenge");

    const authToken = await requestJson(baseUrl, "/v1/auth/token", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        identity: localAdminIdentity,
        key_id: localAdminKeyId,
        challenge_id: authChallenge.json?.challenge_id,
        signature: signUtf8Message(localAdminKeys.privateKeyPem, authChallenge.json?.nonce || "")
      })
    });
    pushStep("exchange_local_auth_token", authToken);
    assertStatus(authToken, 200, "Exchange local auth token");
    const actorToken = String(authToken.json?.access_token || "").trim();
    if (!actorToken) {
      throw new Error("Auth token response missing access_token.");
    }

    const registerRemoteSender = await requestJson(baseUrl, "/v1/identity", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json",
        "x-loom-admin-token": args.adminToken
      },
      body: JSON.stringify({
        id: remoteSenderIdentity,
        imported_remote: true,
        display_name: "Interop Remote Sender",
        signing_keys: [{ key_id: remoteSenderKeyId, public_key_pem: remoteSenderKeys.publicKeyPem }]
      })
    });
    pushStep("register_remote_sender_identity", registerRemoteSender);
    assertStatus(registerRemoteSender, 201, "Register remote sender identity");

    const registerRemoteNode = await requestJson(baseUrl, "/v1/federation/nodes", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        authorization: `Bearer ${actorToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        node_id: args.remoteNodeId,
        key_id: args.remoteNodeKeyId,
        public_key_pem: remoteNodeKeys.publicKeyPem,
        policy: "trusted"
      })
    });
    pushStep("register_remote_federation_node", registerRemoteNode);
    if (registerRemoteNode.status !== 201 && registerRemoteNode.status !== 200) {
      throw new Error(`Register remote federation node failed with HTTP ${registerRemoteNode.status}`);
    }

    const challengeRawBody = JSON.stringify({
      reason: "interop-drill"
    });
    const challengeHeaders = buildSignedFederationHeaders({
      nodeId: args.remoteNodeId,
      keyId: args.remoteNodeKeyId,
      nonce: `nonce_interop_challenge_${suffix}`,
      path: "/v1/federation/challenge",
      rawBody: challengeRawBody,
      privateKeyPem: remoteNodeKeys.privateKeyPem
    });
    const issueFederationChallenge = await requestJson(baseUrl, "/v1/federation/challenge", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json",
        ...challengeHeaders
      },
      body: challengeRawBody
    });
    pushStep("issue_federation_challenge_token", issueFederationChallenge);
    assertStatus(issueFederationChallenge, 200, "Issue federation challenge token");
    const challengeToken = String(issueFederationChallenge.json?.challenge_token || "").trim();
    if (!challengeToken) {
      throw new Error("Federation challenge response missing challenge_token.");
    }

    const envelopeUlid = generateUlid();
    const threadUlid = generateUlid();
    const signedEnvelope = signEnvelope(
      {
        loom: "1.1",
        id: `env_${envelopeUlid}`,
        thread_id: `thr_${threadUlid}`,
        parent_id: null,
        type: "message",
        from: {
          identity: remoteSenderIdentity,
          display: "Interop Remote Sender",
          key_id: remoteSenderKeyId,
          type: "human"
        },
        to: [{ identity: `loom://interop-recipient@${targetNodeId}`, role: "primary" }],
        created_at: new Date().toISOString(),
        priority: "normal",
        content: {
          human: { text: "federation interop drill message", format: "markdown" },
          structured: { intent: "message.general@v1", parameters: {} },
          encrypted: false
        },
        attachments: []
      },
      remoteSenderKeys.privateKeyPem,
      remoteSenderKeyId
    );
    const deliveryWrapper = {
      loom: "1.1",
      delivery_id: `fdel_${generateUlid()}`,
      sender_node: args.remoteNodeId,
      timestamp: new Date().toISOString(),
      envelopes: [signedEnvelope]
    };
    const deliveryRawBody = JSON.stringify(deliveryWrapper);
    const deliveryNonce = `nonce_interop_delivery_${suffix}`;
    const deliveryHeaders = buildSignedFederationHeaders({
      nodeId: args.remoteNodeId,
      keyId: args.remoteNodeKeyId,
      nonce: deliveryNonce,
      path: "/v1/federation/deliver",
      rawBody: deliveryRawBody,
      privateKeyPem: remoteNodeKeys.privateKeyPem
    });
    const deliver = await requestJson(baseUrl, "/v1/federation/deliver", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json",
        ...deliveryHeaders,
        "x-loom-challenge-token": challengeToken
      },
      body: deliveryRawBody
    });
    pushStep("federation_deliver_with_challenge_token", deliver);
    assertStatus(deliver, 202, "Signed federation delivery");
    if (Number(deliver.json?.accepted_count || 0) < 1) {
      throw new Error("Delivery did not accept any envelopes.");
    }
    const receipt = deliver.json?.receipt;
    if (!receipt || typeof receipt !== "object") {
      throw new Error("Delivery response missing receipt.");
    }

    const targetSigningKeys = Array.isArray(nodeDocument.json?.federation?.signing_keys)
      ? nodeDocument.json.federation.signing_keys
      : [];
    const receiptKeyId = String(receipt?.signature?.key_id || "").trim();
    const targetSigningKey = targetSigningKeys.find((key) => String(key?.key_id || "").trim() === receiptKeyId);
    if (!targetSigningKey?.public_key_pem) {
      throw new Error(`Receipt signing key not found in node document: ${receiptKeyId}`);
    }
    const receiptPayload = {
      ...receipt
    };
    delete receiptPayload.signature;
    const receiptValid = verifyUtf8MessageSignature(
      targetSigningKey.public_key_pem,
      canonicalizeFederationReceipt(receiptPayload),
      String(receipt?.signature?.value || "")
    );
    if (!receiptValid) {
      throw new Error("Federation delivery receipt signature verification failed.");
    }

    const replayDeliver = await requestJson(baseUrl, "/v1/federation/deliver", {
      method: "POST",
      timeoutMs: args.timeoutMs,
      headers: {
        "content-type": "application/json",
        ...deliveryHeaders,
        "x-loom-challenge-token": challengeToken
      },
      body: deliveryRawBody
    });
    pushStep("replay_nonce_guard_check", replayDeliver);
    if (replayDeliver.status !== 401 || replayDeliver.json?.error?.code !== "SIGNATURE_INVALID") {
      throw new Error(
        `Replay guard check failed (expected HTTP 401 SIGNATURE_INVALID, got ${replayDeliver.status} ${
          replayDeliver.json?.error?.code || ""
        })`
      );
    }

    report.success = true;
    report.finished_at = new Date().toISOString();
    report.assertions = {
      challenge_issue_passed: true,
      delivery_passed: true,
      receipt_signature_verified: true,
      replay_guard_passed: true
    };
    return report;
  } catch (error) {
    report.success = false;
    report.finished_at = new Date().toISOString();
    report.failure = error?.message || String(error);
    error.report = report;
    throw error;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const outputRoot = resolve(args.outputDir);
  const runDir = join(outputRoot, args.drillId);
  mkdirSync(runDir, { recursive: true });

  const reportPath = join(runDir, "report.json");
  const summaryPath = join(runDir, "summary.md");

  try {
    const report = await runDrill(args);
    writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n");
    writeFileSync(summaryPath, buildSummary(report, reportPath));
    console.log("Federation interop drill finished: PASS");
    console.log(`Report: ${reportPath}`);
    console.log(`Summary: ${summaryPath}`);
  } catch (error) {
    const failedReport = error?.report || {
      drill_id: args.drillId,
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      base_url: args.baseUrl,
      success: false,
      failure: error?.message || String(error)
    };
    writeFileSync(reportPath, JSON.stringify(failedReport, null, 2) + "\n");
    writeFileSync(summaryPath, buildSummary(failedReport, reportPath));
    console.error("Federation interop drill finished: FAIL");
    console.error(`Report: ${reportPath}`);
    console.error(`Summary: ${summaryPath}`);
    console.error(`Reason: ${failedReport.failure}`);
    process.exit(1);
  }
}

main();
