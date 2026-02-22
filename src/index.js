import { createLoomServer } from "./node/server.js";
import { createEmailRelayFromEnv } from "./node/email_relay.js";
import { createPostgresPersistenceFromEnv } from "./node/persistence_postgres.js";
import { createWireGatewayFromEnv } from "./node/wire_gateway.js";
import { parseBoolean, parseHostAllowlist } from "./node/env.js";
import { applyConfigProfileEnvDefaults } from "./node/config_profile.js";
import { randomUUID } from "node:crypto";

function isPublicBindHost(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1") {
    return false;
  }

  if (normalized.startsWith("127.")) {
    return false;
  }

  return true;
}

function normalizePositiveInteger(value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  const floored = Math.floor(parsed);
  if (floored < min) {
    return fallback;
  }

  return Math.min(max, floored);
}

applyConfigProfileEnvDefaults(process.env, process.env.LOOM_CONFIG_PROFILE);

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || "127.0.0.1";
const domain = process.env.LOOM_DOMAIN || `${host}:${port}`;
const adminToken = process.env.LOOM_ADMIN_TOKEN || null;
const metricsPublic = parseBoolean(process.env.LOOM_METRICS_PUBLIC, false);
const allowPublicMetricsOnPublicBind = parseBoolean(process.env.LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND, false);
const requireTlsProxyOnPublicBind = parseBoolean(process.env.LOOM_REQUIRE_TLS_PROXY, true);
const tlsProxyConfirmed = parseBoolean(process.env.LOOM_TLS_PROXY_CONFIRMED, false);
const nativeTlsEnabled = parseBoolean(process.env.LOOM_NATIVE_TLS_ENABLED, false);
const demoPublicReads = parseBoolean(process.env.LOOM_DEMO_PUBLIC_READS, false);
const demoPublicReadsConfirmed = parseBoolean(process.env.LOOM_DEMO_PUBLIC_READS_CONFIRMED, false);
const allowOpenOutboundHostsOnPublicBind = parseBoolean(
  process.env.LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND,
  false
);
const federationResolveRemoteIdentities = parseBoolean(
  process.env.LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED,
  true
);
const publicBind = isPublicBindHost(host);
const publicService = parseBoolean(process.env.LOOM_PUBLIC_SERVICE, publicBind);
const identityRequireProof = parseBoolean(process.env.LOOM_IDENTITY_REQUIRE_PROOF, publicService);
const requireHttpsFromProxy = parseBoolean(
  process.env.LOOM_REQUIRE_HTTPS_FROM_PROXY,
  publicService && !nativeTlsEnabled
);
const trustProxyConfigured =
  parseBoolean(process.env.LOOM_TRUST_PROXY, false) ||
  String(process.env.LOOM_TRUST_PROXY_ALLOWLIST || "").trim().length > 0;
const requirePortableThreadOpCapability = parseBoolean(
  process.env.LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY,
  publicService
);
const federationOutboundHostAllowlist = parseHostAllowlist(process.env.LOOM_FEDERATION_HOST_ALLOWLIST);
const federationBootstrapHostAllowlist = parseHostAllowlist(process.env.LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST);
const remoteIdentityHostAllowlist = parseHostAllowlist(process.env.LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST);
const webhookHostAllowlist = parseHostAllowlist(process.env.LOOM_WEBHOOK_HOST_ALLOWLIST);

if (publicService && !adminToken) {
  throw new Error("Refusing public service without LOOM_ADMIN_TOKEN");
}

if (publicService && metricsPublic && !allowPublicMetricsOnPublicBind) {
  throw new Error(
    "Refusing LOOM_METRICS_PUBLIC=true on public service without LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND=true"
  );
}

if (publicService && requireTlsProxyOnPublicBind && !tlsProxyConfirmed && !nativeTlsEnabled) {
  throw new Error(
    "Refusing public service without LOOM_TLS_PROXY_CONFIRMED=true when LOOM_REQUIRE_TLS_PROXY=true (or enable LOOM_NATIVE_TLS_ENABLED=true)"
  );
}

if (publicService && demoPublicReads && !demoPublicReadsConfirmed) {
  throw new Error(
    "Refusing LOOM_DEMO_PUBLIC_READS=true on public service without LOOM_DEMO_PUBLIC_READS_CONFIRMED=true"
  );
}

if (publicService && requireHttpsFromProxy && !nativeTlsEnabled && !trustProxyConfigured) {
  throw new Error(
    "Refusing public service without trusted proxy headers; set LOOM_TRUST_PROXY=true or configure LOOM_TRUST_PROXY_ALLOWLIST"
  );
}

if (publicService && !allowOpenOutboundHostsOnPublicBind) {
  if (federationOutboundHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public service without LOOM_FEDERATION_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (federationBootstrapHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public service without LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (webhookHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public service without LOOM_WEBHOOK_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (federationResolveRemoteIdentities && remoteIdentityHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public service with remote identity resolution enabled and no LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }
}

const federationOutboxAutoProcessIntervalMs = Number(process.env.LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const federationOutboxAutoProcessBatchSize = Number(process.env.LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
const emailOutboxAutoProcessIntervalMs = Number(process.env.LOOM_EMAIL_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const emailOutboxAutoProcessBatchSize = Number(process.env.LOOM_EMAIL_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
const webhookOutboxAutoProcessIntervalMs = Number(process.env.LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const webhookOutboxAutoProcessBatchSize = Number(process.env.LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
const maintenanceSweepIntervalMs = Number(process.env.LOOM_MAINTENANCE_SWEEP_INTERVAL_MS || 60000);
const federationTrustRevalidateIntervalMs = Number(
  process.env.LOOM_FEDERATION_TRUST_REVALIDATE_INTERVAL_MS || 15 * 60 * 1000
);
const federationTrustRevalidateBatchLimit = Number(
  process.env.LOOM_FEDERATION_TRUST_REVALIDATE_BATCH_LIMIT || 100
);
const federationTrustRevalidateIncludeNonPublicModes = parseBoolean(
  process.env.LOOM_FEDERATION_TRUST_REVALIDATE_INCLUDE_NON_PUBLIC_MODES,
  false
);
const federationTrustRevalidateTimeoutMs = Number(
  process.env.LOOM_FEDERATION_TRUST_REVALIDATE_TIMEOUT_MS || 5000
);
const federationTrustRevalidateMaxResponseBytes = Number(
  process.env.LOOM_FEDERATION_TRUST_REVALIDATE_MAX_RESPONSE_BYTES || 256 * 1024
);
const normalizedFederationTrustRevalidateBatchLimit = normalizePositiveInteger(
  federationTrustRevalidateBatchLimit,
  100,
  {
    min: 1,
    max: 1000
  }
);
const normalizedFederationTrustRevalidateTimeoutMs = normalizePositiveInteger(
  federationTrustRevalidateTimeoutMs,
  5000,
  {
    min: 500,
    max: 20000
  }
);
const normalizedFederationTrustRevalidateMaxResponseBytes = normalizePositiveInteger(
  federationTrustRevalidateMaxResponseBytes,
  256 * 1024,
  {
    min: 1024,
    max: 1024 * 1024
  }
);
const federationSigningPrivateKeyPem = process.env.LOOM_NODE_SIGNING_PRIVATE_KEY_PEM
  ? process.env.LOOM_NODE_SIGNING_PRIVATE_KEY_PEM.replace(/\\n/g, "\n")
  : null;
const emailRelay = createEmailRelayFromEnv();
const postgresPersistence = createPostgresPersistenceFromEnv();
const runtimeStatus = {
  started_at: new Date().toISOString(),
  persistence_hydration: null,
  federation_outbox_worker: {
    enabled: false,
    interval_ms: federationOutboxAutoProcessIntervalMs,
    batch_size: federationOutboxAutoProcessBatchSize,
    runs_total: 0,
    in_progress: false,
    last_run_at: null,
    last_processed_count: 0,
    last_error: null,
    last_error_at: null,
    batch_backoff_ms: 0
  },
  email_outbox_worker: {
    enabled: false,
    interval_ms: emailOutboxAutoProcessIntervalMs,
    batch_size: emailOutboxAutoProcessBatchSize,
    runs_total: 0,
    in_progress: false,
    last_run_at: null,
    last_processed_count: 0,
    last_error: null,
    last_error_at: null,
    batch_backoff_ms: 0
  },
  webhook_outbox_worker: {
    enabled: false,
    interval_ms: webhookOutboxAutoProcessIntervalMs,
    batch_size: webhookOutboxAutoProcessBatchSize,
    runs_total: 0,
    in_progress: false,
    last_run_at: null,
    last_processed_count: 0,
    last_error: null,
    last_error_at: null,
    batch_backoff_ms: 0
  },
  federation_trust_revalidation_worker: {
    enabled: false,
    interval_ms: federationTrustRevalidateIntervalMs,
    batch_limit: normalizedFederationTrustRevalidateBatchLimit,
    include_non_public_modes: federationTrustRevalidateIncludeNonPublicModes,
    runs_total: 0,
    in_progress: false,
    last_run_at: null,
    last_revalidated_count: 0,
    last_skipped_count: 0,
    last_failed_count: 0,
    last_error: null,
    last_error_at: null,
    batch_backoff_ms: 0
  }
};

let storeRef = null;
let wireGatewayRef = null;

function runtimeStatusProvider() {
  return {
    ...runtimeStatus,
    email_relay: typeof emailRelay.getStatus === "function" ? emailRelay.getStatus() : null,
    wire_gateway: typeof wireGatewayRef?.getStatus === "function" ? wireGatewayRef.getStatus() : null,
    postgres: typeof postgresPersistence?.getStatus === "function" ? postgresPersistence.getStatus() : null,
    persistence: storeRef?.getPersistenceStatus?.() || null
  };
}

const { server, store } = createLoomServer({
  nodeId: process.env.LOOM_NODE_ID || "loom-node.local",
  domain,
  dataDir: process.env.LOOM_DATA_DIR || null,
  adminToken,
  metricsPublic,
  federationSigningKeyId: process.env.LOOM_NODE_SIGNING_KEY_ID || "k_node_sign_local_1",
  federationSigningPrivateKeyPem,
  identityRequireProof,
  requirePortableThreadOpCapability,
  publicService,
  requireHttpsFromProxy,
  persistenceAdapter: postgresPersistence,
  emailRelay,
  runtimeStatusProvider
});
storeRef = store;
const wireGateway = createWireGatewayFromEnv({ store });
wireGatewayRef = wireGateway;

let federationOutboxTimer = null;
let isFederationOutboxProcessing = false;
let federationOutboxBackoffUntil = 0;
let federationOutboxBackoffMs = 0;
let emailOutboxTimer = null;
let isEmailOutboxProcessing = false;
let emailOutboxBackoffUntil = 0;
let emailOutboxBackoffMs = 0;
let webhookOutboxTimer = null;
let isWebhookOutboxProcessing = false;
let webhookOutboxBackoffUntil = 0;
let webhookOutboxBackoffMs = 0;
let federationTrustRevalidationTimer = null;
let isFederationTrustRevalidationProcessing = false;
let federationTrustRevalidationBackoffUntil = 0;
let federationTrustRevalidationBackoffMs = 0;

function buildWorkerTraceId(worker) {
  const normalizedWorker = String(worker || "worker")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `trace_${normalizedWorker || "worker"}_${randomUUID()}`;
}

async function runWithWorkerTrace(worker, callback) {
  const traceId = buildWorkerTraceId(worker);
  const context = {
    trace_id: traceId,
    trace_source: "worker",
    worker,
    actor: "system"
  };
  if (typeof store.runWithTraceContext !== "function") {
    const result = await callback();
    return { traceId, result };
  }
  const result = await store.runWithTraceContext(context, callback);
  return { traceId, result };
}

function logWorkerBatchProcessed(worker, traceId, result) {
  if (!result || Number(result.processed_count || 0) <= 0) {
    return;
  }

  const processed = Array.isArray(result.processed) ? result.processed : [];
  const sourceRequestIds = Array.from(
    new Set(
      processed
        .map((item) => (item && typeof item === "object" ? item.source_request_id : null))
        .filter(Boolean)
    )
  ).slice(0, 20);
  const sourceTraceIds = Array.from(
    new Set(
      processed
        .map((item) => (item && typeof item === "object" ? item.source_trace_id : null))
        .filter(Boolean)
    )
  ).slice(0, 20);
  const outboxIds = processed
    .map((item) => (item && typeof item === "object" ? item.outbox_id : null))
    .filter(Boolean)
    .slice(0, 20);

  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      event: "worker.batch.processed",
      worker,
      trace_id: traceId,
      processed_count: result.processed_count,
      outbox_ids: outboxIds,
      source_request_ids: sourceRequestIds,
      source_trace_ids: sourceTraceIds
    })
  );
}

function logFederationTrustRevalidationProcessed(traceId, result) {
  if (!result || typeof result !== "object") {
    return;
  }

  const revalidatedCount = Number(result.revalidated_count || 0);
  const skippedCount = Number(result.skipped_count || 0);
  const failedCount = Number(result.failed_count || 0);
  if (revalidatedCount <= 0 && failedCount <= 0) {
    return;
  }

  const revalidatedNodeIds = Array.isArray(result.processed)
    ? result.processed
        .map((entry) => (entry && typeof entry === "object" ? String(entry.node_id || "").trim() : ""))
        .filter(Boolean)
        .slice(0, 20)
    : [];
  const skippedNodeIds = Array.isArray(result.skipped)
    ? result.skipped
        .map((entry) => (entry && typeof entry === "object" ? String(entry.node_id || "").trim() : ""))
        .filter(Boolean)
        .slice(0, 20)
    : [];
  const failedNodeIds = Array.isArray(result.failed)
    ? result.failed
        .map((entry) => (entry && typeof entry === "object" ? String(entry.node_id || "").trim() : ""))
        .filter(Boolean)
        .slice(0, 20)
    : [];

  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      event: "worker.federation.trust.revalidation",
      worker: "federation_trust_revalidation",
      trace_id: traceId,
      revalidated_count: revalidatedCount,
      skipped_count: skippedCount,
      failed_count: failedCount,
      revalidated_node_ids: revalidatedNodeIds,
      skipped_node_ids: skippedNodeIds,
      failed_node_ids: failedNodeIds
    })
  );
}

function startFederationOutboxWorker() {
  if (!Number.isFinite(federationOutboxAutoProcessIntervalMs) || federationOutboxAutoProcessIntervalMs <= 0) {
    runtimeStatus.federation_outbox_worker.enabled = false;
    return;
  }

  runtimeStatus.federation_outbox_worker.enabled = true;

  federationOutboxTimer = setInterval(() => {
    if (isFederationOutboxProcessing) {
      return;
    }
    if (federationOutboxBackoffUntil > Date.now()) {
      return;
    }

    isFederationOutboxProcessing = true;
    void (async () => {
    runtimeStatus.federation_outbox_worker.in_progress = true;
    runtimeStatus.federation_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.federation_outbox_worker.runs_total += 1;
    try {
      const { traceId, result } = await runWithWorkerTrace("federation_outbox", () =>
        store.processFederationOutboxBatch(federationOutboxAutoProcessBatchSize, "system")
      );
      runtimeStatus.federation_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.federation_outbox_worker.last_error = null;
      runtimeStatus.federation_outbox_worker.last_error_at = null;
      federationOutboxBackoffMs = 0;
      federationOutboxBackoffUntil = 0;
      runtimeStatus.federation_outbox_worker.batch_backoff_ms = 0;
      logWorkerBatchProcessed("federation_outbox", traceId, result);
    } catch (error) {
      runtimeStatus.federation_outbox_worker.last_error = error?.message || "Unknown federation outbox worker error";
      runtimeStatus.federation_outbox_worker.last_error_at = new Date().toISOString();
      federationOutboxBackoffMs = Math.min(300000, federationOutboxBackoffMs === 0 ? 10000 : federationOutboxBackoffMs * 2);
      federationOutboxBackoffUntil = Date.now() + federationOutboxBackoffMs;
      runtimeStatus.federation_outbox_worker.batch_backoff_ms = federationOutboxBackoffMs;
      // eslint-disable-next-line no-console
      console.error("LOOM federation outbox worker failed", error);
    } finally {
      isFederationOutboxProcessing = false;
      runtimeStatus.federation_outbox_worker.in_progress = false;
    }
    })();
  }, federationOutboxAutoProcessIntervalMs);

  federationOutboxTimer.unref?.();
}

function stopFederationOutboxWorker() {
  if (federationOutboxTimer) {
    clearInterval(federationOutboxTimer);
    federationOutboxTimer = null;
  }
}

function startEmailOutboxWorker() {
  if (!emailRelay?.isEnabled?.()) {
    runtimeStatus.email_outbox_worker.enabled = false;
    return;
  }

  if (!Number.isFinite(emailOutboxAutoProcessIntervalMs) || emailOutboxAutoProcessIntervalMs <= 0) {
    runtimeStatus.email_outbox_worker.enabled = false;
    return;
  }

  runtimeStatus.email_outbox_worker.enabled = true;

  emailOutboxTimer = setInterval(() => {
    if (isEmailOutboxProcessing) {
      return;
    }
    if (emailOutboxBackoffUntil > Date.now()) {
      return;
    }

    isEmailOutboxProcessing = true;
    void (async () => {
    runtimeStatus.email_outbox_worker.in_progress = true;
    runtimeStatus.email_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.email_outbox_worker.runs_total += 1;

    try {
      const { traceId, result } = await runWithWorkerTrace("email_outbox", () =>
        store.processEmailOutboxBatch(emailOutboxAutoProcessBatchSize, emailRelay, "system")
      );
      runtimeStatus.email_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.email_outbox_worker.last_error = null;
      runtimeStatus.email_outbox_worker.last_error_at = null;
      emailOutboxBackoffMs = 0;
      emailOutboxBackoffUntil = 0;
      runtimeStatus.email_outbox_worker.batch_backoff_ms = 0;
      logWorkerBatchProcessed("email_outbox", traceId, result);
    } catch (error) {
      runtimeStatus.email_outbox_worker.last_error = error?.message || "Unknown email outbox worker error";
      runtimeStatus.email_outbox_worker.last_error_at = new Date().toISOString();
      emailOutboxBackoffMs = Math.min(300000, emailOutboxBackoffMs === 0 ? 10000 : emailOutboxBackoffMs * 2);
      emailOutboxBackoffUntil = Date.now() + emailOutboxBackoffMs;
      runtimeStatus.email_outbox_worker.batch_backoff_ms = emailOutboxBackoffMs;
      // eslint-disable-next-line no-console
      console.error("LOOM email outbox worker failed", error);
    } finally {
      isEmailOutboxProcessing = false;
      runtimeStatus.email_outbox_worker.in_progress = false;
    }
    })();
  }, emailOutboxAutoProcessIntervalMs);

  emailOutboxTimer.unref?.();
}

function stopEmailOutboxWorker() {
  if (emailOutboxTimer) {
    clearInterval(emailOutboxTimer);
    emailOutboxTimer = null;
  }
}

function startWebhookOutboxWorker() {
  if (!Number.isFinite(webhookOutboxAutoProcessIntervalMs) || webhookOutboxAutoProcessIntervalMs <= 0) {
    runtimeStatus.webhook_outbox_worker.enabled = false;
    return;
  }

  runtimeStatus.webhook_outbox_worker.enabled = true;

  webhookOutboxTimer = setInterval(() => {
    if (isWebhookOutboxProcessing) {
      return;
    }
    if (webhookOutboxBackoffUntil > Date.now()) {
      return;
    }

    isWebhookOutboxProcessing = true;
    void (async () => {
    runtimeStatus.webhook_outbox_worker.in_progress = true;
    runtimeStatus.webhook_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.webhook_outbox_worker.runs_total += 1;

    try {
      const { traceId, result } = await runWithWorkerTrace("webhook_outbox", () =>
        store.processWebhookOutboxBatch(webhookOutboxAutoProcessBatchSize, "system")
      );
      runtimeStatus.webhook_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.webhook_outbox_worker.last_error = null;
      runtimeStatus.webhook_outbox_worker.last_error_at = null;
      webhookOutboxBackoffMs = 0;
      webhookOutboxBackoffUntil = 0;
      runtimeStatus.webhook_outbox_worker.batch_backoff_ms = 0;
      logWorkerBatchProcessed("webhook_outbox", traceId, result);
    } catch (error) {
      runtimeStatus.webhook_outbox_worker.last_error = error?.message || "Unknown webhook outbox worker error";
      runtimeStatus.webhook_outbox_worker.last_error_at = new Date().toISOString();
      webhookOutboxBackoffMs = Math.min(300000, webhookOutboxBackoffMs === 0 ? 10000 : webhookOutboxBackoffMs * 2);
      webhookOutboxBackoffUntil = Date.now() + webhookOutboxBackoffMs;
      runtimeStatus.webhook_outbox_worker.batch_backoff_ms = webhookOutboxBackoffMs;
      // eslint-disable-next-line no-console
      console.error("LOOM webhook outbox worker failed", error);
    } finally {
      isWebhookOutboxProcessing = false;
      runtimeStatus.webhook_outbox_worker.in_progress = false;
    }
    })();
  }, webhookOutboxAutoProcessIntervalMs);

  webhookOutboxTimer.unref?.();
}

function stopWebhookOutboxWorker() {
  if (webhookOutboxTimer) {
    clearInterval(webhookOutboxTimer);
    webhookOutboxTimer = null;
  }
}

function startFederationTrustRevalidationWorker() {
  if (!Number.isFinite(federationTrustRevalidateIntervalMs) || federationTrustRevalidateIntervalMs <= 0) {
    runtimeStatus.federation_trust_revalidation_worker.enabled = false;
    return;
  }

  runtimeStatus.federation_trust_revalidation_worker.enabled = true;

  federationTrustRevalidationTimer = setInterval(() => {
    if (isFederationTrustRevalidationProcessing) {
      return;
    }
    if (federationTrustRevalidationBackoffUntil > Date.now()) {
      return;
    }

    isFederationTrustRevalidationProcessing = true;
    void (async () => {
      runtimeStatus.federation_trust_revalidation_worker.in_progress = true;
      runtimeStatus.federation_trust_revalidation_worker.last_run_at = new Date().toISOString();
      runtimeStatus.federation_trust_revalidation_worker.runs_total += 1;
      try {
        const { traceId, result } = await runWithWorkerTrace("federation_trust_revalidation", () =>
          store.revalidateFederationNodesTrust(
            {
              limit: normalizedFederationTrustRevalidateBatchLimit,
              include_non_public_modes: federationTrustRevalidateIncludeNonPublicModes,
              continue_on_error: true,
              timeout_ms: normalizedFederationTrustRevalidateTimeoutMs,
              max_response_bytes: normalizedFederationTrustRevalidateMaxResponseBytes
            },
            "system"
          )
        );
        runtimeStatus.federation_trust_revalidation_worker.last_revalidated_count = Number(
          result?.revalidated_count || 0
        );
        runtimeStatus.federation_trust_revalidation_worker.last_skipped_count = Number(
          result?.skipped_count || 0
        );
        runtimeStatus.federation_trust_revalidation_worker.last_failed_count = Number(
          result?.failed_count || 0
        );
        runtimeStatus.federation_trust_revalidation_worker.last_error = null;
        runtimeStatus.federation_trust_revalidation_worker.last_error_at = null;
        federationTrustRevalidationBackoffMs = 0;
        federationTrustRevalidationBackoffUntil = 0;
        runtimeStatus.federation_trust_revalidation_worker.batch_backoff_ms = 0;
        logFederationTrustRevalidationProcessed(traceId, result);
      } catch (error) {
        runtimeStatus.federation_trust_revalidation_worker.last_error =
          error?.message || "Unknown federation trust revalidation worker error";
        runtimeStatus.federation_trust_revalidation_worker.last_error_at = new Date().toISOString();
        federationTrustRevalidationBackoffMs = Math.min(
          300000,
          federationTrustRevalidationBackoffMs === 0 ? 10000 : federationTrustRevalidationBackoffMs * 2
        );
        federationTrustRevalidationBackoffUntil = Date.now() + federationTrustRevalidationBackoffMs;
        runtimeStatus.federation_trust_revalidation_worker.batch_backoff_ms =
          federationTrustRevalidationBackoffMs;
        // eslint-disable-next-line no-console
        console.error("LOOM federation trust revalidation worker failed", error);
      } finally {
        isFederationTrustRevalidationProcessing = false;
        runtimeStatus.federation_trust_revalidation_worker.in_progress = false;
      }
    })();
  }, federationTrustRevalidateIntervalMs);

  federationTrustRevalidationTimer.unref?.();
}

function stopFederationTrustRevalidationWorker() {
  if (federationTrustRevalidationTimer) {
    clearInterval(federationTrustRevalidationTimer);
    federationTrustRevalidationTimer = null;
  }
}

let maintenanceSweepTimer = null;

function startMaintenanceSweep() {
  if (!Number.isFinite(maintenanceSweepIntervalMs) || maintenanceSweepIntervalMs <= 0) {
    return;
  }

  maintenanceSweepTimer = setInterval(() => {
    try {
      store.runMaintenanceSweep();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("LOOM maintenance sweep failed", error);
    }
  }, maintenanceSweepIntervalMs);

  maintenanceSweepTimer.unref?.();
}

function stopMaintenanceSweep() {
  if (maintenanceSweepTimer) {
    clearInterval(maintenanceSweepTimer);
    maintenanceSweepTimer = null;
  }
}

async function initializePersistence() {
  if (!postgresPersistence) {
    runtimeStatus.persistence_hydration = {
      enabled: false,
      skipped: true,
      completed_at: new Date().toISOString()
    };
    return;
  }

  const startedAt = new Date().toISOString();
  runtimeStatus.persistence_hydration = {
    enabled: true,
    started_at: startedAt,
    status: "in_progress"
  };

  try {
    await postgresPersistence.initialize();
    const hydration = await store.hydrateFromPersistence();
    runtimeStatus.persistence_hydration = {
      ...hydration,
      enabled: true,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      status: "ok"
    };

    // eslint-disable-next-line no-console
    console.log(
      `LOOM persistence hydrated (loaded=${runtimeStatus.persistence_hydration.loaded ? "yes" : "no"})`
    );
  } catch (error) {
    runtimeStatus.persistence_hydration = {
      enabled: true,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      status: "failed",
      error: error?.message || String(error)
    };
    throw error;
  }
}

async function flushAndClosePersistence() {
  let flushFailed = false;
  try {
    await store.flushPersistenceQueueNow(15000);
  } catch (error) {
    flushFailed = true;
    // eslint-disable-next-line no-console
    console.error("LOOM persistence flush failed — potential data loss", error);
  }

  if (postgresPersistence?.close) {
    try {
      await postgresPersistence.close();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("LOOM postgres persistence close failed", error);
    }
  }

  return { flushFailed };
}

let shuttingDown = false;

async function shutdown(signal, exitCode = 0) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;

  stopFederationOutboxWorker();
  stopEmailOutboxWorker();
  stopWebhookOutboxWorker();
  stopFederationTrustRevalidationWorker();
  stopMaintenanceSweep();
  try {
    await wireGateway.stop();
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("LOOM wire gateway shutdown failed", error);
  }
  // eslint-disable-next-line no-console
  console.log(`Received ${signal}, shutting down LOOM MVN...`);

  const { flushFailed } = await flushAndClosePersistence();

  await new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }

    server.close(() => {
      resolve();
    });
  });

  process.exit(flushFailed ? 1 : exitCode);
}

process.once("SIGINT", () => {
  void shutdown("SIGINT", 0);
});
process.once("SIGTERM", () => {
  void shutdown("SIGTERM", 0);
});

async function start() {
  await initializePersistence();
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("error", onError);
      reject(error);
    };
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  const boundPort = typeof address === "object" && address ? address.port : port;
  // eslint-disable-next-line no-console
  console.log(`LOOM MVN listening at http://${host}:${boundPort}`);
  if (wireGateway.isEnabled()) {
    await wireGateway.start();
    const wireStatus = wireGateway.getStatus();
    if (wireStatus.smtp.listening) {
      // eslint-disable-next-line no-console
      console.log(`LOOM wire SMTP gateway listening at ${wireStatus.host}:${wireStatus.smtp.bound_port}`);
    }
    if (wireStatus.imap.listening) {
      // eslint-disable-next-line no-console
      console.log(`LOOM wire IMAP gateway listening at ${wireStatus.host}:${wireStatus.imap.bound_port}`);
    }
  }
  startFederationOutboxWorker();
  startEmailOutboxWorker();
  startWebhookOutboxWorker();
  startFederationTrustRevalidationWorker();
  startMaintenanceSweep();
}

process.on("unhandledRejection", (reason) => {
  // eslint-disable-next-line no-console
  console.error("LOOM unhandled promise rejection", reason);
});

process.on("uncaughtException", (error) => {
  // eslint-disable-next-line no-console
  console.error("LOOM uncaught exception — shutting down", error);
  void shutdown("UNCAUGHT_EXCEPTION", 1);
});

start().catch((error) => {
  // eslint-disable-next-line no-console
  console.error("LOOM MVN failed to start", error);
  void shutdown("STARTUP_FAILURE", 1);
});
