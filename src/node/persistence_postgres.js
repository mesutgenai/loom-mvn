import { Pool } from "pg";

import { parseBoolean, parsePositiveInt } from "./env.js";

const CURRENT_SCHEMA_VERSION = 3;

function parseNonNegativeInt(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function redactConnectionString(connectionString) {
  if (!connectionString || typeof connectionString !== "string") {
    return null;
  }
  try {
    const url = new URL(connectionString);
    if (url.password) {
      url.password = "***";
    }
    return url.toString();
  } catch {
    return "***";
  }
}

export class LoomPostgresPersistence {
  constructor(options = {}) {
    this.connectionString = options.connectionString;
    this.stateKey = options.stateKey || "default";
    this.pool =
      options.pool ||
      new Pool({
        connectionString: options.connectionString,
        max: parsePositiveInt(options.maxPoolSize, 20),
        idleTimeoutMillis: parsePositiveInt(options.idleTimeoutMs, 30_000),
        connectionTimeoutMillis: parsePositiveInt(options.connectTimeoutMs, 10_000),
        ssl: options.ssl || undefined
      });
    this.initialized = false;
    this.schemaVersion = null;
    this.lastBackupAt = null;
    this.lastRestoreAt = null;
    this.maintenanceCounter = 0;
    this.outboxClaimSweepCounter = 0;
  }

  async initialize() {
    if (this.initialized) {
      return;
    }

    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_meta (
          key TEXT PRIMARY KEY,
          value_json JSONB NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_state (
          id TEXT PRIMARY KEY,
          state_json JSONB NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_audit (
          seq BIGSERIAL PRIMARY KEY,
          event_id TEXT NOT NULL UNIQUE,
          entry_json JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS loom_audit_created_at_idx
        ON loom_audit (created_at DESC)
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_federation_rate_events (
          id BIGSERIAL PRIMARY KEY,
          state_key TEXT NOT NULL,
          node_id TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS loom_federation_rate_events_state_node_created_idx
        ON loom_federation_rate_events (state_key, node_id, created_at DESC)
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_federation_abuse_events (
          id BIGSERIAL PRIMARY KEY,
          state_key TEXT NOT NULL,
          node_id TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS loom_federation_abuse_events_state_node_created_idx
        ON loom_federation_abuse_events (state_key, node_id, created_at DESC)
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_federation_reputation (
          state_key TEXT NOT NULL,
          node_id TEXT NOT NULL,
          score INTEGER NOT NULL DEFAULT 0,
          last_reason_code TEXT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (state_key, node_id)
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_federation_challenges (
          id BIGSERIAL PRIMARY KEY,
          state_key TEXT NOT NULL,
          node_id TEXT NOT NULL,
          token TEXT NOT NULL UNIQUE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          consumed_at TIMESTAMPTZ NULL
        )
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS loom_federation_challenges_state_node_expiry_idx
        ON loom_federation_challenges (state_key, node_id, expires_at DESC)
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS loom_outbox_claims (
          state_key TEXT NOT NULL,
          kind TEXT NOT NULL,
          outbox_id TEXT NOT NULL,
          worker_id TEXT NOT NULL,
          claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          claimed_until TIMESTAMPTZ NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (state_key, kind, outbox_id)
        )
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS loom_outbox_claims_state_kind_expiry_idx
        ON loom_outbox_claims (state_key, kind, claimed_until)
      `);

      await client.query(
        `
          INSERT INTO loom_meta (key, value_json, updated_at)
          VALUES ('schema_version', jsonb_build_object('version', $1::int), NOW())
          ON CONFLICT (key)
          DO UPDATE SET
            value_json = EXCLUDED.value_json,
            updated_at = NOW()
        `,
        [CURRENT_SCHEMA_VERSION]
      );

      const schemaResult = await client.query(
        "SELECT value_json FROM loom_meta WHERE key = 'schema_version' LIMIT 1"
      );
      const rawVersion = schemaResult.rowCount > 0 ? schemaResult.rows[0].value_json?.version : null;
      this.schemaVersion = parsePositiveInt(rawVersion, CURRENT_SCHEMA_VERSION);
    } finally {
      client.release();
    }

    this.initialized = true;
  }

  async maybeCleanupFederationGuardTables(windowMs) {
    this.maintenanceCounter += 1;
    if (this.maintenanceCounter % 500 !== 0) {
      return;
    }

    const retentionMs = Math.max(60 * 60 * 1000, Number(windowMs || 0) * 8);
    const client = await this.pool.connect();
    try {
      await client.query(
        `
          DELETE FROM loom_federation_rate_events
          WHERE state_key = $1
            AND created_at < NOW() - ($2::bigint * INTERVAL '1 millisecond')
        `,
        [this.stateKey, retentionMs]
      );
      await client.query(
        `
          DELETE FROM loom_federation_abuse_events
          WHERE state_key = $1
            AND created_at < NOW() - ($2::bigint * INTERVAL '1 millisecond')
        `,
        [this.stateKey, retentionMs]
      );
      await client.query(
        `
          DELETE FROM loom_federation_challenges
          WHERE state_key = $1
            AND (consumed_at IS NOT NULL OR expires_at < NOW() - INTERVAL '1 day')
        `,
        [this.stateKey]
      );
    } finally {
      client.release();
    }
  }

  async maybeCleanupOutboxClaims() {
    this.outboxClaimSweepCounter += 1;
    if (this.outboxClaimSweepCounter % 200 !== 0) {
      return;
    }

    const client = await this.pool.connect();
    try {
      await client.query(
        `
          DELETE FROM loom_outbox_claims
          WHERE state_key = $1
            AND claimed_until < NOW() - INTERVAL '6 hours'
        `,
        [this.stateKey]
      );
    } finally {
      client.release();
    }
  }

  async getSchemaStatus() {
    await this.initialize();
    return {
      backend: "postgres",
      state_key: this.stateKey,
      initialized: this.initialized,
      schema_version: this.schemaVersion || CURRENT_SCHEMA_VERSION
    };
  }

  async claimOutboxItem({ kind, outboxId, leaseMs, workerId }) {
    await this.initialize();

    const safeKind = String(kind || "").trim().toLowerCase();
    const safeOutboxId = String(outboxId || "").trim();
    const safeWorkerId = String(workerId || "").trim() || `worker_${process.pid}`;
    if (!safeKind || !safeOutboxId) {
      return {
        claimed: false
      };
    }
    const safeLeaseMs = Math.max(5000, parsePositiveInt(leaseMs, 60 * 1000));

    const client = await this.pool.connect();
    try {
      const result = await client.query(
        `
          INSERT INTO loom_outbox_claims (
            state_key,
            kind,
            outbox_id,
            worker_id,
            claimed_at,
            claimed_until,
            updated_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            NOW(),
            NOW() + ($5::bigint * INTERVAL '1 millisecond'),
            NOW()
          )
          ON CONFLICT (state_key, kind, outbox_id)
          DO UPDATE SET
            worker_id = EXCLUDED.worker_id,
            claimed_at = NOW(),
            claimed_until = EXCLUDED.claimed_until,
            updated_at = NOW()
          WHERE loom_outbox_claims.claimed_until <= NOW()
            OR loom_outbox_claims.worker_id = EXCLUDED.worker_id
          RETURNING worker_id, claimed_until
        `,
        [this.stateKey, safeKind, safeOutboxId, safeWorkerId, safeLeaseMs]
      );

      void this.maybeCleanupOutboxClaims();

      return {
        claimed: result.rowCount > 0,
        worker_id: result.rows[0]?.worker_id || null,
        claimed_until: result.rows[0]?.claimed_until || null
      };
    } finally {
      client.release();
    }
  }

  async releaseOutboxClaim({ kind, outboxId, workerId }) {
    await this.initialize();

    const safeKind = String(kind || "").trim().toLowerCase();
    const safeOutboxId = String(outboxId || "").trim();
    if (!safeKind || !safeOutboxId) {
      return {
        released: false
      };
    }
    const safeWorkerId = typeof workerId === "string" && workerId.trim().length > 0 ? workerId.trim() : null;

    const client = await this.pool.connect();
    try {
      const result = await client.query(
        `
          DELETE FROM loom_outbox_claims
          WHERE state_key = $1
            AND kind = $2
            AND outbox_id = $3
            AND ($4::text IS NULL OR worker_id = $4)
        `,
        [this.stateKey, safeKind, safeOutboxId, safeWorkerId]
      );
      return {
        released: result.rowCount > 0
      };
    } finally {
      client.release();
    }
  }

  async loadStateAndAudit() {
    await this.initialize();

    const client = await this.pool.connect();
    try {
      const stateResult = await client.query(
        "SELECT state_json FROM loom_state WHERE id = $1",
        [this.stateKey]
      );

      const auditResult = await client.query(
        "SELECT entry_json FROM loom_audit ORDER BY seq ASC"
      );

      const state = stateResult.rowCount > 0 ? stateResult.rows[0].state_json : null;
      const auditEntries = auditResult.rows.map((row) => row.entry_json).filter(Boolean);

      return {
        state,
        audit_entries: auditEntries
      };
    } finally {
      client.release();
    }
  }

  async persistSnapshotAndAudit(snapshot, auditEntry) {
    await this.initialize();

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      await client.query(
        `
          INSERT INTO loom_state (id, state_json, updated_at)
          VALUES ($1, $2::jsonb, NOW())
          ON CONFLICT (id)
          DO UPDATE SET
            state_json = EXCLUDED.state_json,
            updated_at = NOW()
        `,
        [this.stateKey, JSON.stringify(snapshot)]
      );

      await client.query(
        `
          INSERT INTO loom_audit (event_id, entry_json, created_at)
          VALUES ($1, $2::jsonb, NOW())
          ON CONFLICT (event_id) DO NOTHING
        `,
        [auditEntry.event_id, JSON.stringify(auditEntry)]
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async exportBackup(options = {}) {
    await this.initialize();

    const includeAudit = options.includeAudit !== false;
    const auditLimit = parseNonNegativeInt(options.auditLimit, 0);

    const client = await this.pool.connect();
    try {
      const stateResult = await client.query(
        "SELECT state_json, updated_at FROM loom_state WHERE id = $1",
        [this.stateKey]
      );

      let auditEntries = [];
      if (includeAudit) {
        if (auditLimit > 0) {
          const auditResult = await client.query(
            `
              SELECT entry_json
              FROM (
                SELECT seq, entry_json
                FROM loom_audit
                ORDER BY seq DESC
                LIMIT $1
              ) recent
              ORDER BY seq ASC
            `,
            [auditLimit]
          );
          auditEntries = auditResult.rows.map((row) => row.entry_json).filter(Boolean);
        } else {
          const auditResult = await client.query(
            "SELECT entry_json FROM loom_audit ORDER BY seq ASC"
          );
          auditEntries = auditResult.rows.map((row) => row.entry_json).filter(Boolean);
        }
      }

      const backup = {
        loom_backup_version: 1,
        backend: "postgres",
        state_key: this.stateKey,
        schema_version: this.schemaVersion || CURRENT_SCHEMA_VERSION,
        exported_at: new Date().toISOString(),
        state: stateResult.rowCount > 0 ? stateResult.rows[0].state_json : null,
        state_updated_at: stateResult.rowCount > 0 ? stateResult.rows[0].updated_at : null,
        audit_entries: auditEntries
      };

      this.lastBackupAt = backup.exported_at;
      return backup;
    } finally {
      client.release();
    }
  }

  async importBackup(backup, options = {}) {
    await this.initialize();

    if (!backup || typeof backup !== "object") {
      throw new Error("Backup payload must be an object");
    }

    const replaceState = options.replaceState !== false;
    const truncateAudit = options.truncateAudit === true;
    const statePayload = backup.state || null;
    const auditEntries = Array.isArray(backup.audit_entries) ? backup.audit_entries.filter(Boolean) : [];

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      if (truncateAudit) {
        await client.query("DELETE FROM loom_audit");
      }

      if (replaceState && statePayload) {
        await client.query(
          `
            INSERT INTO loom_state (id, state_json, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (id)
            DO UPDATE SET
              state_json = EXCLUDED.state_json,
              updated_at = NOW()
          `,
          [this.stateKey, JSON.stringify(statePayload)]
        );
      }

      let importedAuditCount = 0;
      for (const entry of auditEntries) {
        if (!entry?.event_id) {
          continue;
        }
        const result = await client.query(
          `
            INSERT INTO loom_audit (event_id, entry_json, created_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (event_id) DO NOTHING
          `,
          [entry.event_id, JSON.stringify(entry)]
        );
        importedAuditCount += Number(result.rowCount || 0);
      }

      await client.query("COMMIT");
      this.lastRestoreAt = new Date().toISOString();

      return {
        restored_at: this.lastRestoreAt,
        imported_audit_count: importedAuditCount,
        replaced_state: Boolean(replaceState && statePayload),
        truncated_audit: truncateAudit
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async incrementFederationInboundRate({ nodeId, windowMs }) {
    await this.initialize();

    const safeNodeId = String(nodeId || "").trim();
    if (!safeNodeId) {
      return {
        count: 0,
        oldest_ms: null
      };
    }

    const safeWindowMs = Math.max(1000, parsePositiveInt(windowMs, 60_000));
    const client = await this.pool.connect();
    try {
      await client.query(
        `
          INSERT INTO loom_federation_rate_events (state_key, node_id, created_at)
          VALUES ($1, $2, NOW())
        `,
        [this.stateKey, safeNodeId]
      );

      const result = await client.query(
        `
          SELECT
            COUNT(*)::int AS count,
            MIN(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS oldest_ms
          FROM loom_federation_rate_events
          WHERE state_key = $1
            AND node_id = $2
            AND created_at >= NOW() - ($3::bigint * INTERVAL '1 millisecond')
        `,
        [this.stateKey, safeNodeId, safeWindowMs]
      );

      await this.maybeCleanupFederationGuardTables(safeWindowMs);

      return {
        count: Number(result.rows[0]?.count || 0),
        oldest_ms: result.rows[0]?.oldest_ms ? Number(result.rows[0].oldest_ms) : null
      };
    } finally {
      client.release();
    }
  }

  async recordFederationAbuseFailure({ nodeId, reasonCode, windowMs }) {
    await this.initialize();

    const safeNodeId = String(nodeId || "").trim();
    if (!safeNodeId) {
      return {
        window_count: 0,
        reputation_score: 0
      };
    }

    const safeReasonCode = String(reasonCode || "UNKNOWN").trim() || "UNKNOWN";
    const safeWindowMs = Math.max(1000, parsePositiveInt(windowMs, 5 * 60 * 1000));
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      await client.query(
        `
          INSERT INTO loom_federation_abuse_events (state_key, node_id, reason_code, created_at)
          VALUES ($1, $2, $3, NOW())
        `,
        [this.stateKey, safeNodeId, safeReasonCode]
      );

      const windowResult = await client.query(
        `
          SELECT COUNT(*)::int AS count
          FROM loom_federation_abuse_events
          WHERE state_key = $1
            AND node_id = $2
            AND created_at >= NOW() - ($3::bigint * INTERVAL '1 millisecond')
        `,
        [this.stateKey, safeNodeId, safeWindowMs]
      );

      const reputationResult = await client.query(
        `
          INSERT INTO loom_federation_reputation (state_key, node_id, score, last_reason_code, updated_at)
          VALUES ($1, $2, 1, $3, NOW())
          ON CONFLICT (state_key, node_id)
          DO UPDATE SET
            score = loom_federation_reputation.score + 1,
            last_reason_code = EXCLUDED.last_reason_code,
            updated_at = NOW()
          RETURNING score
        `,
        [this.stateKey, safeNodeId, safeReasonCode]
      );

      await client.query("COMMIT");
      await this.maybeCleanupFederationGuardTables(safeWindowMs);

      return {
        window_count: Number(windowResult.rows[0]?.count || 0),
        reputation_score: Number(reputationResult.rows[0]?.score || 0)
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async recordFederationAbuseSuccess({ nodeId }) {
    await this.initialize();

    const safeNodeId = String(nodeId || "").trim();
    if (!safeNodeId) {
      return {
        reputation_score: 0
      };
    }

    const client = await this.pool.connect();
    try {
      const result = await client.query(
        `
          INSERT INTO loom_federation_reputation (state_key, node_id, score, updated_at)
          VALUES ($1, $2, 0, NOW())
          ON CONFLICT (state_key, node_id)
          DO UPDATE SET
            score = GREATEST(loom_federation_reputation.score - 1, 0),
            updated_at = NOW()
          RETURNING score
        `,
        [this.stateKey, safeNodeId]
      );

      return {
        reputation_score: Number(result.rows[0]?.score || 0)
      };
    } finally {
      client.release();
    }
  }

  async issueFederationChallengeToken({ nodeId, token, expiresAt }) {
    await this.initialize();

    const safeNodeId = String(nodeId || "").trim();
    const safeToken = String(token || "").trim();
    if (!safeNodeId || !safeToken || !expiresAt) {
      return null;
    }

    const client = await this.pool.connect();
    try {
      await client.query(
        `
          INSERT INTO loom_federation_challenges (state_key, node_id, token, expires_at, created_at)
          VALUES ($1, $2, $3, $4::timestamptz, NOW())
        `,
        [this.stateKey, safeNodeId, safeToken, expiresAt]
      );
      return {
        node_id: safeNodeId,
        token: safeToken,
        expires_at: expiresAt
      };
    } finally {
      client.release();
    }
  }

  async consumeFederationChallengeToken({ nodeId, token }) {
    await this.initialize();

    const safeNodeId = String(nodeId || "").trim();
    const safeToken = String(token || "").trim();
    if (!safeNodeId || !safeToken) {
      return false;
    }

    const client = await this.pool.connect();
    try {
      const result = await client.query(
        `
          UPDATE loom_federation_challenges
          SET consumed_at = NOW()
          WHERE state_key = $1
            AND node_id = $2
            AND token = $3
            AND consumed_at IS NULL
            AND expires_at > NOW()
          RETURNING id
        `,
        [this.stateKey, safeNodeId, safeToken]
      );
      return result.rowCount > 0;
    } finally {
      client.release();
    }
  }

  async getFederationGuardStatus() {
    await this.initialize();

    const client = await this.pool.connect();
    try {
      const [rateResult, abuseResult, challengeResult] = await Promise.all([
        client.query(
          `
            SELECT COUNT(*)::int AS count
            FROM loom_federation_rate_events
            WHERE state_key = $1
              AND created_at >= NOW() - INTERVAL '1 hour'
          `,
          [this.stateKey]
        ),
        client.query(
          `
            SELECT COUNT(*)::int AS count
            FROM loom_federation_abuse_events
            WHERE state_key = $1
              AND created_at >= NOW() - INTERVAL '1 hour'
          `,
          [this.stateKey]
        ),
        client.query(
          `
            SELECT COUNT(*)::int AS count
            FROM loom_federation_challenges
            WHERE state_key = $1
              AND consumed_at IS NULL
              AND expires_at > NOW()
          `,
          [this.stateKey]
        )
      ]);

      return {
        backend: "postgres",
        state_key: this.stateKey,
        rate_events_last_hour: Number(rateResult.rows[0]?.count || 0),
        abuse_events_last_hour: Number(abuseResult.rows[0]?.count || 0),
        active_challenges: Number(challengeResult.rows[0]?.count || 0)
      };
    } finally {
      client.release();
    }
  }

  getStatus() {
    return {
      backend: "postgres",
      state_key: this.stateKey,
      initialized: this.initialized,
      schema_version: this.schemaVersion || null,
      last_backup_at: this.lastBackupAt,
      last_restore_at: this.lastRestoreAt,
      connection: redactConnectionString(this.connectionString)
    };
  }

  async close() {
    await this.pool.end();
  }
}

export function createPostgresPersistenceFromEnv(options = {}) {
  const connectionString = options.connectionString ?? process.env.LOOM_PG_URL ?? null;
  if (!connectionString) {
    return null;
  }

  const sslEnabled = parseBoolean(options.sslEnabled ?? process.env.LOOM_PG_SSL, false);
  const sslRejectUnauthorized = parseBoolean(
    options.sslRejectUnauthorized ?? process.env.LOOM_PG_SSL_REJECT_UNAUTHORIZED,
    true
  );

  return new LoomPostgresPersistence({
    connectionString,
    stateKey: options.stateKey ?? process.env.LOOM_PG_STATE_KEY ?? "default",
    maxPoolSize: options.maxPoolSize ?? process.env.LOOM_PG_POOL_MAX ?? 20,
    idleTimeoutMs: options.idleTimeoutMs ?? process.env.LOOM_PG_IDLE_TIMEOUT_MS ?? 30000,
    connectTimeoutMs: options.connectTimeoutMs ?? process.env.LOOM_PG_CONNECT_TIMEOUT_MS ?? 10000,
    ssl: sslEnabled
      ? {
          rejectUnauthorized: sslRejectUnauthorized
        }
      : null
  });
}
