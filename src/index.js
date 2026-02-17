import { createLoomServer } from "./node/server.js";
import { createEmailRelayFromEnv } from "./node/email_relay.js";
import { createPostgresPersistenceFromEnv } from "./node/persistence_postgres.js";
import { createWireGatewayFromEnv } from "./node/wire_gateway.js";

function parseBoolean(value, fallback = false) {
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

function parseHostAllowlist(value) {
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
const identityRequireProof = parseBoolean(
  process.env.LOOM_IDENTITY_REQUIRE_PROOF,
  isPublicBindHost(process.env.HOST || "127.0.0.1")
);
const allowOpenOutboundHostsOnPublicBind = parseBoolean(
  process.env.LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND,
  false
);
const federationResolveRemoteIdentities = parseBoolean(
  process.env.LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED,
  true
);
const requirePortableThreadOpCapability = parseBoolean(
  process.env.LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY,
  publicBind
);
const federationOutboundHostAllowlist = parseHostAllowlist(process.env.LOOM_FEDERATION_HOST_ALLOWLIST);
const federationBootstrapHostAllowlist = parseHostAllowlist(process.env.LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST);
const remoteIdentityHostAllowlist = parseHostAllowlist(process.env.LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST);
const webhookHostAllowlist = parseHostAllowlist(process.env.LOOM_WEBHOOK_HOST_ALLOWLIST);
const publicBind = isPublicBindHost(host);

if (publicBind && !adminToken) {
  throw new Error("Refusing public bind without LOOM_ADMIN_TOKEN");
}

if (publicBind && metricsPublic && !allowPublicMetricsOnPublicBind) {
  throw new Error(
    "Refusing LOOM_METRICS_PUBLIC=true on public bind without LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND=true"
  );
}

if (publicBind && requireTlsProxyOnPublicBind && !tlsProxyConfirmed && !nativeTlsEnabled) {
  throw new Error(
    "Refusing public bind without LOOM_TLS_PROXY_CONFIRMED=true when LOOM_REQUIRE_TLS_PROXY=true (or enable LOOM_NATIVE_TLS_ENABLED=true)"
  );
}

if (publicBind && demoPublicReads && !demoPublicReadsConfirmed) {
  throw new Error("Refusing LOOM_DEMO_PUBLIC_READS=true on public bind without LOOM_DEMO_PUBLIC_READS_CONFIRMED=true");
}

if (publicBind && !allowOpenOutboundHostsOnPublicBind) {
  if (federationOutboundHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public bind without LOOM_FEDERATION_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (federationBootstrapHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public bind without LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (webhookHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public bind without LOOM_WEBHOOK_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }

  if (federationResolveRemoteIdentities && remoteIdentityHostAllowlist.length === 0) {
    throw new Error(
      "Refusing public bind with remote identity resolution enabled and no LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST; set LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true to override"
    );
  }
}

const federationOutboxAutoProcessIntervalMs = Number(process.env.LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const federationOutboxAutoProcessBatchSize = Number(process.env.LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
const emailOutboxAutoProcessIntervalMs = Number(process.env.LOOM_EMAIL_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const emailOutboxAutoProcessBatchSize = Number(process.env.LOOM_EMAIL_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
const webhookOutboxAutoProcessIntervalMs = Number(process.env.LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_INTERVAL_MS || 5000);
const webhookOutboxAutoProcessBatchSize = Number(process.env.LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_BATCH_SIZE || 20);
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
    last_error_at: null
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
    last_error_at: null
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
    last_error_at: null
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
  persistenceAdapter: postgresPersistence,
  emailRelay,
  runtimeStatusProvider
});
storeRef = store;
const wireGateway = createWireGatewayFromEnv({ store });
wireGatewayRef = wireGateway;

let federationOutboxTimer = null;
let isFederationOutboxProcessing = false;
let emailOutboxTimer = null;
let isEmailOutboxProcessing = false;
let webhookOutboxTimer = null;
let isWebhookOutboxProcessing = false;

function startFederationOutboxWorker() {
  if (!Number.isFinite(federationOutboxAutoProcessIntervalMs) || federationOutboxAutoProcessIntervalMs <= 0) {
    runtimeStatus.federation_outbox_worker.enabled = false;
    return;
  }

  runtimeStatus.federation_outbox_worker.enabled = true;

  federationOutboxTimer = setInterval(async () => {
    if (isFederationOutboxProcessing) {
      return;
    }

    isFederationOutboxProcessing = true;
    runtimeStatus.federation_outbox_worker.in_progress = true;
    runtimeStatus.federation_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.federation_outbox_worker.runs_total += 1;
    try {
      const result = await store.processFederationOutboxBatch(federationOutboxAutoProcessBatchSize, null);
      runtimeStatus.federation_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.federation_outbox_worker.last_error = null;
      runtimeStatus.federation_outbox_worker.last_error_at = null;
      if (result.processed_count > 0) {
        // eslint-disable-next-line no-console
        console.log(`LOOM federation outbox worker processed ${result.processed_count} item(s)`);
      }
    } catch (error) {
      runtimeStatus.federation_outbox_worker.last_error = error?.message || "Unknown federation outbox worker error";
      runtimeStatus.federation_outbox_worker.last_error_at = new Date().toISOString();
      // eslint-disable-next-line no-console
      console.error("LOOM federation outbox worker failed", error);
    } finally {
      isFederationOutboxProcessing = false;
      runtimeStatus.federation_outbox_worker.in_progress = false;
    }
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

  emailOutboxTimer = setInterval(async () => {
    if (isEmailOutboxProcessing) {
      return;
    }

    isEmailOutboxProcessing = true;
    runtimeStatus.email_outbox_worker.in_progress = true;
    runtimeStatus.email_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.email_outbox_worker.runs_total += 1;

    try {
      const result = await store.processEmailOutboxBatch(emailOutboxAutoProcessBatchSize, emailRelay, null);
      runtimeStatus.email_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.email_outbox_worker.last_error = null;
      runtimeStatus.email_outbox_worker.last_error_at = null;
      if (result.processed_count > 0) {
        // eslint-disable-next-line no-console
        console.log(`LOOM email outbox worker processed ${result.processed_count} item(s)`);
      }
    } catch (error) {
      runtimeStatus.email_outbox_worker.last_error = error?.message || "Unknown email outbox worker error";
      runtimeStatus.email_outbox_worker.last_error_at = new Date().toISOString();
      // eslint-disable-next-line no-console
      console.error("LOOM email outbox worker failed", error);
    } finally {
      isEmailOutboxProcessing = false;
      runtimeStatus.email_outbox_worker.in_progress = false;
    }
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

  webhookOutboxTimer = setInterval(async () => {
    if (isWebhookOutboxProcessing) {
      return;
    }

    isWebhookOutboxProcessing = true;
    runtimeStatus.webhook_outbox_worker.in_progress = true;
    runtimeStatus.webhook_outbox_worker.last_run_at = new Date().toISOString();
    runtimeStatus.webhook_outbox_worker.runs_total += 1;

    try {
      const result = await store.processWebhookOutboxBatch(webhookOutboxAutoProcessBatchSize, "system");
      runtimeStatus.webhook_outbox_worker.last_processed_count = result.processed_count;
      runtimeStatus.webhook_outbox_worker.last_error = null;
      runtimeStatus.webhook_outbox_worker.last_error_at = null;
      if (result.processed_count > 0) {
        // eslint-disable-next-line no-console
        console.log(`LOOM webhook outbox worker processed ${result.processed_count} item(s)`);
      }
    } catch (error) {
      runtimeStatus.webhook_outbox_worker.last_error = error?.message || "Unknown webhook outbox worker error";
      runtimeStatus.webhook_outbox_worker.last_error_at = new Date().toISOString();
      // eslint-disable-next-line no-console
      console.error("LOOM webhook outbox worker failed", error);
    } finally {
      isWebhookOutboxProcessing = false;
      runtimeStatus.webhook_outbox_worker.in_progress = false;
    }
  }, webhookOutboxAutoProcessIntervalMs);

  webhookOutboxTimer.unref?.();
}

function stopWebhookOutboxWorker() {
  if (webhookOutboxTimer) {
    clearInterval(webhookOutboxTimer);
    webhookOutboxTimer = null;
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
  try {
    await store.flushPersistenceQueueNow(15000);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("LOOM persistence flush failed", error);
  }

  if (postgresPersistence?.close) {
    try {
      await postgresPersistence.close();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("LOOM postgres persistence close failed", error);
    }
  }
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
  try {
    await wireGateway.stop();
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("LOOM wire gateway shutdown failed", error);
  }
  // eslint-disable-next-line no-console
  console.log(`Received ${signal}, shutting down LOOM MVN...`);

  await flushAndClosePersistence();

  await new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }

    server.close(() => {
      resolve();
    });
  });

  process.exit(exitCode);
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
}

start().catch((error) => {
  // eslint-disable-next-line no-console
  console.error("LOOM MVN failed to start", error);
  void shutdown("STARTUP_FAILURE", 1);
});
