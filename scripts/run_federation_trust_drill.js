#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { createLoomServer } from "../src/node/server.js";
import { canonicalizeJson } from "../src/protocol/canonical.js";
import { generateSigningKeyPair, signEnvelope, signUtf8Message } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_OUTPUT_DIR = "scripts/output/federation-trust-drills";

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
    host: process.env.LOOM_DRILL_HOST || DEFAULT_HOST,
    timeoutMs: parsePositiveInt(process.env.LOOM_DRILL_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    outputDir: process.env.LOOM_DRILL_OUTPUT_DIR || DEFAULT_OUTPUT_DIR,
    drillId: `federation-trust-${nowStamp()}`,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--host" && i + 1 < argv.length) {
      args.host = argv[i + 1];
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
  node scripts/run_federation_trust_drill.js [options]

Runs an end-to-end trust freshness drill:
1) bootstrap remote node via public_dns_webpki trust anchor
2) rotate remote trust epoch/version
3) trigger one local revalidation cycle
4) verify stale trust epoch delivery is rejected and fresh epoch delivery is accepted

Options:
  --host <host>             Bind host for ephemeral drill nodes (default: ${DEFAULT_HOST})
  --timeout-ms <int>        Request timeout in ms (default: ${DEFAULT_TIMEOUT_MS})
  --output-dir <path>       Output directory (default: ${DEFAULT_OUTPUT_DIR})
  --drill-id <id>           Override drill ID
  -h, --help                Show help

Example:
  npm run drill:federation-trust
`);
}

function hashSignedDocumentPayload(document) {
  const payload = {
    ...(document && typeof document === "object" ? document : {})
  };
  delete payload.signature;
  return createHash("sha256")
    .update(canonicalizeJson(payload), "utf-8")
    .digest("hex");
}

async function jsonRequest(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = {
      "content-type": "application/json",
      ...(options.headers || {})
    };
    const body = options.body;
    const response = await fetch(url, {
      ...options,
      headers,
      body,
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
  } finally {
    clearTimeout(timer);
  }
}

function assertStatus(result, expectedStatus, label) {
  if (result.status !== expectedStatus) {
    throw new Error(`${label} failed (expected HTTP ${expectedStatus}, got ${result.status})`);
  }
}

function buildSignedDeliveryHeaders({ nodeId, keyId, nonce, rawBody, privateKeyPem, trustEpochHeader = null }) {
  const timestamp = new Date().toISOString();
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}\n${
    trustEpochHeader == null ? "" : String(trustEpochHeader)
  }`;
  return {
    "x-loom-node": nodeId,
    "x-loom-timestamp": timestamp,
    "x-loom-nonce": nonce,
    "x-loom-key-id": keyId,
    "x-loom-signature": signUtf8Message(privateKeyPem, canonical),
    ...(trustEpochHeader == null ? {} : { "x-loom-trust-epoch": String(trustEpochHeader) })
  };
}

function buildSummary(report, reportPath) {
  const lines = [];
  lines.push("# Federation Trust Freshness Drill");
  lines.push("");
  lines.push(`- Drill ID: \`${report.drill_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Local Base URL: \`${report.local_base_url || "n/a"}\``);
  lines.push(`- Remote Base URL: \`${report.remote_base_url || "n/a"}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push("");
  lines.push("## Verified Flow");
  lines.push("");
  lines.push("- Public DNS bootstrap trust registration");
  lines.push("- Remote trust epoch/keyset version rotation");
  lines.push("- Single batch revalidation cycle trigger");
  lines.push("- Freshness enforcement on signed federation delivery");
  lines.push("");
  lines.push(`- Report JSON: \`${reportPath}\``);
  if (report.failure) {
    lines.push(`- Failure: \`${report.failure}\``);
  }
  return lines.join("\n") + "\n";
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  await new Promise((resolve) => {
    server.close(() => resolve());
  });
}

async function runDrill(args) {
  const suffix = randomSuffix();
  const localNodeId = "local.test";
  const remoteNodeId = "remote.test";
  const localAdminIdentity = `loom://admin-${suffix}@${localNodeId}`;
  const localAdminKeyId = `k_sign_local_admin_${suffix}`;
  const remoteSenderIdentity = `loom://sender-${suffix}@${remoteNodeId}`;
  const remoteSenderKeyId = `k_sign_remote_sender_${suffix}`;
  const remoteNodeKeyId = `k_node_sign_remote_${suffix}`;
  const remoteAdminToken = `remote-admin-${suffix}`;

  const localAdminKeys = generateSigningKeyPair();
  const remoteNodeSigningKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  const report = {
    drill_id: args.drillId,
    started_at: new Date().toISOString(),
    success: false,
    steps: []
  };

  let remoteServer = null;
  let localServer = null;
  let remoteBaseUrl = null;
  let localBaseUrl = null;

  function pushStep(name, result) {
    report.steps.push({
      name,
      status: result.status,
      ok: Boolean(result.response?.ok),
      url: result.url,
      response_body: result.json || result.text || null
    });
  }

  try {
    const { server: remote } = createLoomServer({
      nodeId: remoteNodeId,
      domain: args.host,
      adminToken: remoteAdminToken,
      federationSigningKeyId: remoteNodeKeyId,
      federationSigningPrivateKeyPem: remoteNodeSigningKeys.privateKeyPem,
      federationTrustMode: "public_dns_webpki",
      federationTrustLocalEpoch: 1,
      federationTrustKeysetVersion: 1
    });
    remoteServer = remote;
    await new Promise((resolve) => remoteServer.listen(0, args.host, resolve));
    const remoteAddress = remoteServer.address();
    remoteBaseUrl = `http://${args.host}:${remoteAddress.port}`;
    report.remote_base_url = remoteBaseUrl;

    const federationTrustDnsTxtResolver = async () => {
      const keyset = await jsonRequest(`${remoteBaseUrl}/.well-known/loom-keyset.json`, {}, args.timeoutMs);
      if (keyset.status !== 200 || !keyset.json) {
        throw new Error(`Unable to fetch remote keyset for DNS resolver (HTTP ${keyset.status}).`);
      }
      const keysetHash = hashSignedDocumentPayload(keyset.json);
      const trustEpoch = Number(keyset.json?.trust_epoch || 0);
      const keysetVersion = Number(keyset.json?.version || 0);
      return [
        [
          `v=loomfed1;keyset=${remoteBaseUrl}/.well-known/loom-keyset.json;digest=sha256:${keysetHash};revocations=${remoteBaseUrl}/.well-known/loom-revocations.json;trust_epoch=${trustEpoch};version=${keysetVersion}`
        ]
      ];
    };

    const { server: local } = createLoomServer({
      nodeId: localNodeId,
      domain: args.host,
      federationTrustMode: "public_dns_webpki",
      federationTrustDnsTxtResolver,
      federationTrustFailClosed: true
    });
    localServer = local;
    await new Promise((resolve) => localServer.listen(0, args.host, resolve));
    const localAddress = localServer.address();
    localBaseUrl = `http://${args.host}:${localAddress.port}`;
    report.local_base_url = localBaseUrl;

    const registerAdmin = await jsonRequest(
      `${localBaseUrl}/v1/identity`,
      {
        method: "POST",
        body: JSON.stringify({
          id: localAdminIdentity,
          display_name: "Drill Admin",
          signing_keys: [{ key_id: localAdminKeyId, public_key_pem: localAdminKeys.publicKeyPem }]
        })
      },
      args.timeoutMs
    );
    pushStep("register_local_admin_identity", registerAdmin);
    assertStatus(registerAdmin, 201, "Register local admin identity");

    const challenge = await jsonRequest(
      `${localBaseUrl}/v1/auth/challenge`,
      {
        method: "POST",
        body: JSON.stringify({
          identity: localAdminIdentity,
          key_id: localAdminKeyId
        })
      },
      args.timeoutMs
    );
    pushStep("issue_local_auth_challenge", challenge);
    assertStatus(challenge, 200, "Issue local auth challenge");

    const token = await jsonRequest(
      `${localBaseUrl}/v1/auth/token`,
      {
        method: "POST",
        body: JSON.stringify({
          identity: localAdminIdentity,
          key_id: localAdminKeyId,
          challenge_id: challenge.json?.challenge_id,
          signature: signUtf8Message(localAdminKeys.privateKeyPem, challenge.json?.nonce || "")
        })
      },
      args.timeoutMs
    );
    pushStep("exchange_local_auth_token", token);
    assertStatus(token, 200, "Exchange local auth token");
    const actorToken = String(token.json?.access_token || "").trim();
    if (!actorToken) {
      throw new Error("Auth token response missing access_token.");
    }

    const registerRemoteSender = await jsonRequest(
      `${localBaseUrl}/v1/identity`,
      {
        method: "POST",
        body: JSON.stringify({
          id: remoteSenderIdentity,
          imported_remote: true,
          display_name: "Remote Sender",
          signing_keys: [{ key_id: remoteSenderKeyId, public_key_pem: remoteSenderKeys.publicKeyPem }]
        })
      },
      args.timeoutMs
    );
    pushStep("register_remote_sender_identity", registerRemoteSender);
    assertStatus(registerRemoteSender, 201, "Register remote sender identity");

    const bootstrap = await jsonRequest(
      `${localBaseUrl}/v1/federation/nodes/bootstrap`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${actorToken}`
        },
        body: JSON.stringify({
          node_document_url: `${remoteBaseUrl}/.well-known/loom.json`,
          trust_anchor_mode: "public_dns_webpki",
          allow_insecure_http: true,
          allow_private_network: true,
          deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
          identity_resolve_url: `${remoteBaseUrl}/v1/identity/{identity}`
        })
      },
      args.timeoutMs
    );
    pushStep("bootstrap_remote_federation_trust", bootstrap);
    assertStatus(bootstrap, 201, "Bootstrap remote federation trust");
    const bootstrapEpoch = Number(bootstrap.json?.node?.trust_anchor_epoch || 0);
    const bootstrapVersion = Number(bootstrap.json?.node?.trust_anchor_keyset_version || 0);
    if (bootstrapEpoch < 1 || bootstrapVersion < 1) {
      throw new Error(
        `Unexpected bootstrap trust metadata (epoch=${bootstrapEpoch}, keyset_version=${bootstrapVersion}).`
      );
    }

    const rotateRemoteTrust = await jsonRequest(
      `${remoteBaseUrl}/v1/federation/trust`,
      {
        method: "POST",
        headers: {
          "x-loom-admin-token": remoteAdminToken
        },
        body: JSON.stringify({
          bump_trust_epoch: true,
          bump_keyset_version: true
        })
      },
      args.timeoutMs
    );
    pushStep("rotate_remote_trust_epoch_and_version", rotateRemoteTrust);
    assertStatus(rotateRemoteTrust, 200, "Rotate remote trust");
    const rotatedEpoch = Number(rotateRemoteTrust.json?.trust_epoch || 0);
    const rotatedVersion = Number(rotateRemoteTrust.json?.keyset_version || 0);
    if (rotatedEpoch <= bootstrapEpoch || rotatedVersion <= bootstrapVersion) {
      throw new Error(
        `Remote trust rotation did not advance epoch/version (before=${bootstrapEpoch}/${bootstrapVersion}, after=${rotatedEpoch}/${rotatedVersion}).`
      );
    }

    const revalidate = await jsonRequest(
      `${localBaseUrl}/v1/federation/nodes/revalidate`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${actorToken}`
        },
        body: JSON.stringify({
          node_ids: [remoteNodeId],
          limit: 1
        })
      },
      args.timeoutMs
    );
    pushStep("trigger_one_revalidation_cycle", revalidate);
    assertStatus(revalidate, 200, "Trigger revalidation cycle");
    const processed = Array.isArray(revalidate.json?.processed) ? revalidate.json.processed : [];
    if (processed.length !== 1 || processed[0]?.status !== "revalidated") {
      throw new Error("Revalidation cycle did not produce exactly one revalidated node result.");
    }
    const previousEpoch = Number(processed[0]?.previous?.trust_epoch || 0);
    const nextEpoch = Number(processed[0]?.next?.trust_epoch || 0);
    const previousVersion = Number(processed[0]?.previous?.keyset_version || 0);
    const nextVersion = Number(processed[0]?.next?.keyset_version || 0);
    if (nextEpoch <= previousEpoch || nextVersion <= previousVersion) {
      throw new Error(
        `Revalidation did not advance trust freshness (prev=${previousEpoch}/${previousVersion}, next=${nextEpoch}/${nextVersion}).`
      );
    }
    if (nextEpoch !== rotatedEpoch || nextVersion !== rotatedVersion) {
      throw new Error(
        `Revalidation did not converge to rotated remote trust values (next=${nextEpoch}/${nextVersion}, rotated=${rotatedEpoch}/${rotatedVersion}).`
      );
    }

    const listNodes = await jsonRequest(
      `${localBaseUrl}/v1/federation/nodes`,
      {
        method: "GET",
        headers: {
          authorization: `Bearer ${actorToken}`
        }
      },
      args.timeoutMs
    );
    pushStep("list_local_federation_nodes_after_revalidation", listNodes);
    assertStatus(listNodes, 200, "List federation nodes");
    const remoteNode = Array.isArray(listNodes.json?.nodes)
      ? listNodes.json.nodes.find((entry) => String(entry?.node_id || "").trim() === remoteNodeId)
      : null;
    if (!remoteNode) {
      throw new Error("Remote node missing from local federation node list after revalidation.");
    }
    if (Number(remoteNode.trust_anchor_epoch || 0) !== rotatedEpoch) {
      throw new Error(
        `Persisted local trust epoch mismatch after revalidation (got=${remoteNode.trust_anchor_epoch}, expected=${rotatedEpoch}).`
      );
    }

    const signedEnvelope = signEnvelope(
      {
        loom: "1.1",
        id: `env_${generateUlid()}`,
        thread_id: `thr_${generateUlid()}`,
        parent_id: null,
        type: "message",
        from: {
          identity: remoteSenderIdentity,
          display: "Remote Sender",
          key_id: remoteSenderKeyId,
          type: "human"
        },
        to: [{ identity: `loom://recipient@${localNodeId}`, role: "primary" }],
        created_at: new Date().toISOString(),
        priority: "normal",
        content: {
          human: { text: "federation trust freshness drill", format: "markdown" },
          structured: { intent: "message.general@v1", parameters: {} },
          encrypted: false
        },
        attachments: []
      },
      remoteSenderKeys.privateKeyPem,
      remoteSenderKeyId
    );

    const wrapper = {
      loom: "1.1",
      sender_node: remoteNodeId,
      timestamp: new Date().toISOString(),
      envelopes: [signedEnvelope]
    };
    const rawBody = JSON.stringify(wrapper);

    const staleHeaders = buildSignedDeliveryHeaders({
      nodeId: remoteNodeId,
      keyId: remoteNodeKeyId,
      nonce: `nonce_stale_${randomSuffix()}`,
      rawBody,
      privateKeyPem: remoteNodeSigningKeys.privateKeyPem,
      trustEpochHeader: previousEpoch
    });
    const staleDelivery = await jsonRequest(
      `${localBaseUrl}/v1/federation/deliver`,
      {
        method: "POST",
        headers: staleHeaders,
        body: rawBody
      },
      args.timeoutMs
    );
    pushStep("deliver_with_stale_trust_epoch_header", staleDelivery);
    if (staleDelivery.status !== 401 || staleDelivery.json?.error?.code !== "SIGNATURE_INVALID") {
      throw new Error(
        `Expected stale trust epoch delivery rejection (HTTP 401/SIGNATURE_INVALID), got ${staleDelivery.status}/${staleDelivery.json?.error?.code || "n/a"}.`
      );
    }

    const freshHeaders = buildSignedDeliveryHeaders({
      nodeId: remoteNodeId,
      keyId: remoteNodeKeyId,
      nonce: `nonce_fresh_${randomSuffix()}`,
      rawBody,
      privateKeyPem: remoteNodeSigningKeys.privateKeyPem,
      trustEpochHeader: nextEpoch
    });
    const freshDelivery = await jsonRequest(
      `${localBaseUrl}/v1/federation/deliver`,
      {
        method: "POST",
        headers: freshHeaders,
        body: rawBody
      },
      args.timeoutMs
    );
    pushStep("deliver_with_fresh_trust_epoch_header", freshDelivery);
    assertStatus(freshDelivery, 202, "Fresh trust epoch delivery");
    if (Number(freshDelivery.json?.accepted_count || 0) < 1) {
      throw new Error("Fresh trust epoch delivery did not accept any envelopes.");
    }

    report.assertions = {
      bootstrap_epoch: bootstrapEpoch,
      bootstrap_keyset_version: bootstrapVersion,
      rotated_epoch: rotatedEpoch,
      rotated_keyset_version: rotatedVersion,
      revalidation_previous_epoch: previousEpoch,
      revalidation_next_epoch: nextEpoch,
      revalidation_previous_keyset_version: previousVersion,
      revalidation_next_keyset_version: nextVersion,
      stale_epoch_delivery_rejected: true,
      fresh_epoch_delivery_accepted: true
    };
    report.success = true;
    report.finished_at = new Date().toISOString();
    return report;
  } catch (error) {
    report.success = false;
    report.finished_at = new Date().toISOString();
    report.failure = error?.message || String(error);
    error.report = report;
    throw error;
  } finally {
    await closeServer(localServer);
    await closeServer(remoteServer);
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
    console.log("Federation trust freshness drill finished: PASS");
    console.log(`Report: ${reportPath}`);
    console.log(`Summary: ${summaryPath}`);
  } catch (error) {
    const failedReport = error?.report || {
      drill_id: args.drillId,
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      success: false,
      failure: error?.message || String(error)
    };
    writeFileSync(reportPath, JSON.stringify(failedReport, null, 2) + "\n");
    writeFileSync(summaryPath, buildSummary(failedReport, reportPath));
    console.error("Federation trust freshness drill finished: FAIL");
    console.error(`Report: ${reportPath}`);
    console.error(`Summary: ${summaryPath}`);
    console.error(`Reason: ${failedReport.failure}`);
    process.exit(1);
  }
}

main();
