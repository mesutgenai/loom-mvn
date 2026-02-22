import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalizeEnvelope, canonicalizeJson } from "../src/protocol/canonical.js";
import {
  generateSigningKeyPair,
  signEnvelope,
  signUtf8Message,
  verifyEnvelopeSignature
} from "../src/protocol/crypto.js";
import { canonicalizeDelegationLink } from "../src/protocol/delegation.js";
import { validateEnvelopeShape } from "../src/protocol/envelope.js";
import { isIsoDateTime, isLoomIdentity } from "../src/protocol/ids.js";
import { LoomStore } from "../src/node/store.js";

function makeEnvelope(overrides = {}) {
  return {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-16T20:00:00Z",
    priority: "normal",
    content: {
      human: {
        text: "Hello",
        format: "markdown"
      },
      structured: {
        intent: "message.general@v1",
        parameters: {}
      },
      encrypted: false
    },
    attachments: [],
    signature: {
      algorithm: "Ed25519",
      key_id: "k_sign_alice_1",
      value: "placeholder"
    },
    ...overrides
  };
}

function signBaseEnvelope(privateKeyPem, overrides = {}) {
  const unsigned = makeEnvelope(overrides);
  const withoutSignature = { ...unsigned };
  delete withoutSignature.signature;
  return signEnvelope(withoutSignature, privateKeyPem, withoutSignature.from.key_id);
}

test("canonical envelope excludes signature and meta", () => {
  const envelope = makeEnvelope({
    signature: {
      algorithm: "Ed25519",
      key_id: "k_sign_alice_1",
      value: "abc"
    },
    meta: {
      node_id: "test"
    }
  });

  const canonical = canonicalizeEnvelope(envelope);
  assert.equal(canonical.includes("signature"), false);
  assert.equal(canonical.includes("meta"), false);
  assert.equal(canonical.includes("\"loom\":\"1.1\""), true);
});

test("canonical JSON uses deterministic member ordering and rejects unsupported values", () => {
  const canonical = canonicalizeJson({
    z: 1,
    a: {
      d: false,
      c: [3, 2, 1]
    }
  });
  assert.equal(canonical, "{\"a\":{\"c\":[3,2,1],\"d\":false},\"z\":1}");

  assert.throws(
    () =>
      canonicalizeJson({
        bad: Number.NaN
      }),
    /finite numbers/
  );

  assert.throws(
    () =>
      canonicalizeJson({
        bad: undefined
      }),
    /undefined/
  );

  assert.throws(
    () =>
      canonicalizeJson({
        bad: "broken-\uD800"
      }),
    /unpaired surrogate/
  );
});

test("signed envelope verifies; tampered envelope fails verification", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const envelope = signBaseEnvelope(privateKeyPem);

  assert.equal(
    verifyEnvelopeSignature(envelope, {
      k_sign_alice_1: publicKeyPem
    }),
    true
  );

  const tampered = {
    ...envelope,
    content: {
      ...envelope.content,
      human: {
        ...envelope.content.human,
        text: "Tampered"
      }
    }
  };

  assert.throws(
    () =>
      verifyEnvelopeSignature(tampered, {
        k_sign_alice_1: publicKeyPem
      }),
    (error) => error?.code === "SIGNATURE_INVALID"
  );
});

test("shape validation rejects recipient lists without primary role", () => {
  const envelope = makeEnvelope({
    to: [{ identity: "loom://bob@node.test", role: "cc" }]
  });

  const errors = validateEnvelopeShape(envelope);
  assert.equal(errors.some((error) => error.field === "to"), true);
});

test("store ingests signed envelope and rejects duplicates", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  const envelope = signBaseEnvelope(privateKeyPem);
  const stored = store.ingestEnvelope(envelope);

  assert.equal(stored.meta.event_seq, 1);
  assert.equal(stored.meta.pending_parent, false);

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "ENVELOPE_DUPLICATE");
});

test("store trace context propagates request and worker IDs into audit and outbox flows", async () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_trace_1", public_key_pem: publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      ...makeEnvelope(),
      id: "env_01ARZ3NDEKTSV4RRFFQ69TRACE",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_trace_1",
        type: "human"
      }
    },
    privateKeyPem,
    "k_sign_alice_trace_1"
  );
  store.ingestEnvelope(envelope);

  const queueRequestId = "trace_api_queue_001";
  const queued = await store.runWithTraceContext(
    {
      request_id: queueRequestId,
      trace_id: queueRequestId,
      trace_source: "api",
      method: "POST",
      route: "/v1/email/outbox"
    },
    () =>
      store.queueEmailOutbox(
        {
          envelope_id: envelope.id,
          to_email: ["bob@example.net"],
          smtp_from: "alice@example.net"
        },
        "loom://alice@node.test"
      )
  );
  assert.equal(queued.source_request_id, queueRequestId);
  assert.equal(queued.source_trace_id, queueRequestId);

  const relay = {
    send: async () => ({
      provider_message_id: "mock-1",
      response: "250 OK",
      accepted: ["bob@example.net"],
      rejected: []
    })
  };

  const processed = await store.runWithTraceContext(
    {
      trace_id: "trace_worker_email_001",
      trace_source: "worker",
      worker: "email_outbox",
      actor: "system"
    },
    () => store.processEmailOutboxBatch(10, relay, "system")
  );
  assert.equal(processed.processed_count, 1);
  assert.equal(processed.processed[0].source_request_id, queueRequestId);

  const auditEntries = store.getAuditEntries(50);
  const queueAudit = auditEntries.find((entry) => entry.action === "email.outbox.queue");
  assert.equal(queueAudit?.payload?.request_id, queueRequestId);
  assert.equal(queueAudit?.trace?.request_id, queueRequestId);
  assert.equal(queueAudit?.trace?.trace_source, "api");

  const deliveredAudit = auditEntries.find((entry) => entry.action === "email.outbox.process.delivered");
  assert.equal(deliveredAudit?.payload?.source_request_id, queueRequestId);
  assert.equal(deliveredAudit?.trace?.trace_source, "worker");
  assert.equal(deliveredAudit?.trace?.worker, "email_outbox");
});

test("store persists state to disk when dataDir is configured", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "loom-store-"));
  try {
    const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
    const storeA = new LoomStore({ nodeId: "node.test", dataDir });

    storeA.registerIdentity({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
    });

    const envelope = signBaseEnvelope(privateKeyPem);
    storeA.ingestEnvelope(envelope);

    const storeB = new LoomStore({ nodeId: "node.test", dataDir });
    const loadedEnvelope = storeB.getEnvelope(envelope.id);
    assert.equal(loadedEnvelope?.id, envelope.id);

    const threads = storeB.listThreads();
    assert.equal(threads.length, 1);
    assert.equal(threads[0].id, envelope.thread_id);
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("store persists federation nonce replay cache across restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "loom-federation-nonce-"));
  try {
    const remoteNodeKeys = generateSigningKeyPair();
    const nodeId = "remote.test";
    const keyId = "k_node_sign_remote_1";
    const method = "POST";
    const path = "/v1/federation/deliver";
    const rawBody = JSON.stringify({ loom: "1.1", envelopes: [] });
    const timestamp = new Date().toISOString();
    const nonce = `nonce_${Date.now()}`;
    const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
    const canonical = `${method}\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
    const signature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

    const headers = {
      "x-loom-node": nodeId,
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": keyId,
      "x-loom-signature": signature
    };

    const storeA = new LoomStore({ nodeId: "local.test", dataDir });
    storeA.registerFederationNode({
      node_id: nodeId,
      key_id: keyId,
      public_key_pem: remoteNodeKeys.publicKeyPem
    });

    await storeA.verifyFederationRequest({
      method,
      path,
      headers,
      rawBody,
      bypassChallenge: true
    });

    const storeB = new LoomStore({ nodeId: "local.test", dataDir });
    storeB.registerFederationNode({
      node_id: nodeId,
      key_id: keyId,
      public_key_pem: remoteNodeKeys.publicKeyPem
    });

    await assert.rejects(
      () =>
        storeB.verifyFederationRequest({
          method,
          path,
          headers,
          rawBody,
          bypassChallenge: true
        }),
      (error) => error?.code === "SIGNATURE_INVALID"
    );
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("store signs audit entries with HMAC and rejects tampered audit chains", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    auditHmacKey: "test-audit-hmac-key",
    auditRequireMacValidation: true
  });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_hmac_1", public_key_pem: keys.publicKeyPem }]
  });

  assert.equal(store.auditEntries.length >= 1, true);
  assert.equal(typeof store.auditEntries[0].mac, "string");

  const tampered = store.auditEntries.map((entry) => ({ ...entry }));
  tampered[0] = {
    ...tampered[0],
    payload: {
      ...(tampered[0].payload || {}),
      identity: "loom://mallory@node.test"
    }
  };

  const verifier = new LoomStore({
    nodeId: "node.test",
    auditHmacKey: "test-audit-hmac-key",
    auditRequireMacValidation: true
  });

  assert.throws(
    () => verifier.loadAuditFromEntries(tampered),
    (error) => error?.code === "AUDIT_TAMPERED"
  );
});

test("store persists snapshots to external persistence adapter", async () => {
  const writes = [];
  const adapter = {
    async loadStateAndAudit() {
      return {
        state: null,
        audit_entries: []
      };
    },
    async persistSnapshotAndAudit(snapshot, auditEntry) {
      writes.push({
        snapshot,
        auditEntry
      });
    }
  };

  const { publicKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    persistenceAdapter: adapter
  });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  await store.flushPersistenceQueueNow();

  assert.equal(writes.length, 1);
  assert.equal(writes[0].auditEntry.action, "identity.register");
  assert.equal(writes[0].snapshot.node_id, "node.test");

  const status = store.getPersistenceStatus();
  assert.equal(status.enabled, true);
  assert.equal(status.queue_length, 0);
  assert.equal(status.writes_total, 1);
  assert.equal(status.writes_succeeded, 1);
  assert.equal(status.writes_failed, 0);
});

test("store hydrates state and audit from external persistence adapter", async () => {
  const persistedKeys = generateSigningKeyPair();
  const seedStore = new LoomStore({ nodeId: "persisted.node" });
  seedStore.registerIdentity({
    id: "loom://alice@persisted.node",
    display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: persistedKeys.publicKeyPem }]
  });

  const reorderedAuditEntries = seedStore.auditEntries.map((entry) => {
    if (!entry || typeof entry !== "object") {
      return entry;
    }
    const payload =
      entry.payload && typeof entry.payload === "object" && !Array.isArray(entry.payload)
        ? Object.fromEntries(Object.entries(entry.payload).reverse())
        : entry.payload;
    return {
      ...entry,
      payload
    };
  });

  const strictVerifier = new LoomStore({ nodeId: "strict.node" });
  assert.throws(
    () => strictVerifier.loadAuditFromEntries(reorderedAuditEntries),
    (error) => error?.code === "AUDIT_TAMPERED"
  );

  const adapter = {
    async loadStateAndAudit() {
      return {
        state: seedStore.toSerializableState(),
        audit_entries: reorderedAuditEntries
      };
    },
    async persistSnapshotAndAudit() {}
  };

  const store = new LoomStore({
    nodeId: "bootstrap.node",
    persistenceAdapter: adapter
  });

  const hydration = await store.hydrateFromPersistence();
  assert.equal(hydration.enabled, true);
  assert.equal(hydration.loaded, true);
  assert.equal(hydration.state_loaded, true);
  assert.equal(hydration.audit_loaded, true);

  const loadedIdentity = store.resolveIdentity("loom://alice@persisted.node");
  assert.equal(loadedIdentity?.id, "loom://alice@persisted.node");
  assert.equal(store.nodeId, "persisted.node");
  assert.equal(store.getAuditEntries(1)[0].action, "identity.register");
});

test("store rejects cyclic thread DAG additions", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  const threadId = "thr_01ARZ3NDEKTSV4RRFFQ69G5FAX";

  const envA = signBaseEnvelope(privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAY",
    thread_id: threadId,
    parent_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAZ"
  });

  const envB = signBaseEnvelope(privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
    thread_id: threadId,
    parent_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAY"
  });

  store.ingestEnvelope(envA);
  assert.throws(() => store.ingestEnvelope(envB), (error) => error?.code === "ENVELOPE_INVALID");
});

test("thread retrieval uses canonical DAG rendering order", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  const threadId = "thr_01ARZ3NDEKTSV4RRFFQ69G5FB0";

  const root = signBaseEnvelope(privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FB1",
    thread_id: threadId,
    created_at: "2026-02-16T20:00:00Z"
  });

  const childLate = signBaseEnvelope(privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FB2",
    thread_id: threadId,
    parent_id: root.id,
    created_at: "2026-02-16T20:02:00Z"
  });

  const childEarly = signBaseEnvelope(privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FB3",
    thread_id: threadId,
    parent_id: root.id,
    created_at: "2026-02-16T20:01:00Z"
  });

  store.ingestEnvelope(root);
  store.ingestEnvelope(childLate);
  store.ingestEnvelope(childEarly);

  const ordered = store.getThreadEnvelopes(threadId);
  assert.deepEqual(
    ordered.map((envelope) => envelope.id),
    [root.id, childEarly.id, childLate.id]
  );
});

test("proof-of-key challenge and token exchange returns usable access token", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  const challenge = store.createAuthChallenge({
    identity: "loom://alice@node.test",
    key_id: "k_sign_alice_1"
  });

  const signature = signUtf8Message(privateKeyPem, challenge.nonce);

  const tokens = store.exchangeAuthToken({
    identity: "loom://alice@node.test",
    key_id: "k_sign_alice_1",
    challenge_id: challenge.challenge_id,
    signature
  });

  assert.equal(tokens.token_type, "Bearer");
  assert.equal(typeof tokens.access_token, "string");
  assert.equal(typeof tokens.refresh_token, "string");

  const session = store.authenticateAccessToken(tokens.access_token);
  assert.equal(session.identity, "loom://alice@node.test");
});

test("store rejects envelope submission when actor identity mismatches envelope sender", () => {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: publicKeyPem }]
  });

  const envelope = signBaseEnvelope(privateKeyPem);

  assert.throws(
    () => store.ingestEnvelope(envelope, { actorIdentity: "loom://mallory@node.test" }),
    (error) => error?.code === "CAPABILITY_DENIED"
  );
});

test("store rejects envelope signed by key not in sender identity keyset", () => {
  const aliceKeys = generateSigningKeyPair();
  const attackerKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FK0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FK1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_attacker_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:29:00Z",
      priority: "normal",
      content: {
        human: { text: "forged", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    attackerKeys.privateKeyPem,
    "k_sign_attacker_1"
  );

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "SIGNATURE_INVALID");
});

test("store rejects envelope when from.key_id and signature.key_id differ", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FK2",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FK3",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:29:30Z",
      priority: "normal",
      content: {
        human: { text: "mismatch", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_other_1"
  );

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "SIGNATURE_INVALID");
});

test("agent envelope with valid delegation chain is accepted", () => {
  const ownerKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_sign_owner_1", public_key_pem: ownerKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://assistant.owner@node.test",
    type: "agent",
    display_name: "Assistant",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  const delegationWithoutSignature = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FD9",
    delegator: "loom://owner@node.test",
    delegate: "loom://assistant.owner@node.test",
    scope: ["message.general@v1", "thread.resolve@v1"],
    created_at: "2026-02-16T20:30:00Z",
    expires_at: "2027-02-16T20:30:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_owner_1"
  };

  const delegation = {
    ...delegationWithoutSignature,
    signature: signUtf8Message(ownerKeys.privateKeyPem, canonicalizeDelegationLink(delegationWithoutSignature))
  };

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FE1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://assistant.owner@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [delegation]
      },
      to: [{ identity: "loom://target@node.test", role: "primary" }],
      created_at: "2026-02-16T20:31:00Z",
      priority: "normal",
      content: {
        human: { text: "Agent message", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  const stored = store.ingestEnvelope(envelope);
  assert.equal(stored.id, envelope.id);
});

test("agent identity cannot bypass delegation by mislabeling from.type", () => {
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://assistant.owner@node.test",
    type: "agent",
    display_name: "Assistant",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE2",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FE3",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://assistant.owner@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "human"
      },
      to: [{ identity: "loom://target@node.test", role: "primary" }],
      created_at: "2026-02-16T20:31:30Z",
      priority: "normal",
      content: {
        human: { text: "mislabel attempt", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "DELEGATION_INVALID");
});

test("agent envelope fails when delegation chain exceeds max_sub_delegation_depth", () => {
  const ownerKeys = generateSigningKeyPair();
  const delegateKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_sign_owner_1", public_key_pem: ownerKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://delegate@node.test",
    type: "agent",
    display_name: "Delegate",
    signing_keys: [{ key_id: "k_sign_delegate_1", public_key_pem: delegateKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://assistant.owner@node.test",
    type: "agent",
    display_name: "Assistant",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  const firstLinkUnsigned = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FD0",
    delegator: "loom://owner@node.test",
    delegate: "loom://delegate@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:30:00Z",
    expires_at: "2027-02-16T20:30:00Z",
    revocable: true,
    allow_sub_delegation: true,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_owner_1"
  };
  const firstLink = {
    ...firstLinkUnsigned,
    signature: signUtf8Message(ownerKeys.privateKeyPem, canonicalizeDelegationLink(firstLinkUnsigned))
  };

  const secondLinkUnsigned = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FD1",
    delegator: "loom://delegate@node.test",
    delegate: "loom://assistant.owner@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:30:10Z",
    expires_at: "2027-02-16T20:30:10Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_delegate_1"
  };
  const secondLink = {
    ...secondLinkUnsigned,
    signature: signUtf8Message(delegateKeys.privateKeyPem, canonicalizeDelegationLink(secondLinkUnsigned))
  };

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE9",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FF0",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://assistant.owner@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [firstLink, secondLink]
      },
      to: [{ identity: "loom://target@node.test", role: "primary" }],
      created_at: "2026-02-16T20:31:00Z",
      priority: "normal",
      content: {
        human: { text: "Too deep", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "DELEGATION_INVALID");
});

test("agent envelope fails when delegation is revoked", () => {
  const ownerKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_sign_owner_1", public_key_pem: ownerKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://assistant.owner@node.test",
    type: "agent",
    display_name: "Assistant",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  const delegationWithoutSignature = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FE2",
    delegator: "loom://owner@node.test",
    delegate: "loom://assistant.owner@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:32:00Z",
    expires_at: "2027-02-16T20:32:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_owner_1"
  };

  const delegation = {
    ...delegationWithoutSignature,
    signature: signUtf8Message(ownerKeys.privateKeyPem, canonicalizeDelegationLink(delegationWithoutSignature))
  };

  store.createDelegation(delegation, "loom://owner@node.test");
  store.revokeDelegation(delegation.id, "loom://owner@node.test");

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE3",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FE4",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://assistant.owner@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [delegation]
      },
      to: [{ identity: "loom://target@node.test", role: "primary" }],
      created_at: "2026-02-16T20:33:00Z",
      priority: "normal",
      content: {
        human: { text: "Agent message", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(() => store.ingestEnvelope(envelope), (error) => error?.code === "DELEGATION_INVALID");
});

test("thread_op requires capability token for non-owner and consumes single-use capability", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: bobKeys.publicKeyPem }]
  });

  const threadId = "thr_01ARZ3NDEKTSV4RRFFQ69G5FC0";

  const root = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC1",
      thread_id: threadId,
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:10:00Z",
      priority: "normal",
      content: {
        human: { text: "Initial thread", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(root);

  const resolveWithoutCapability = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC2",
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T20:11:00Z",
      priority: "normal",
      content: {
        structured: { intent: "thread.resolve@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_1"
  );

  assert.throws(
    () => store.ingestEnvelope(resolveWithoutCapability),
    (error) => error?.code === "CAPABILITY_DENIED"
  );

  const portableCapability = store.issueCapabilityToken(
    {
      thread_id: threadId,
      issued_to: "loom://bob@node.test",
      grants: ["label"],
      single_use: true
    },
    "loom://alice@node.test"
  );
  assert.equal(typeof portableCapability.presentation_token, "string");
  assert.equal(typeof portableCapability.portable_token, "object");
  const listedBefore = store.listCapabilities(threadId, "loom://alice@node.test");
  assert.equal(listedBefore[0].presentation_token, undefined);

  const resolveWithPayloadCapabilityToken = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC4",
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T20:12:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.update@v1",
          parameters: {
            subject: "portable token update",
            capability_token: portableCapability.portable_token
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_1"
  );
  store.ingestEnvelope(resolveWithPayloadCapabilityToken);

  const resolveCapability = store.issueCapabilityToken(
    {
      thread_id: threadId,
      issued_to: "loom://bob@node.test",
      grants: ["resolve"],
      single_use: true
    },
    "loom://alice@node.test"
  );

  const resolveWithCapability = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC3",
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T20:12:30Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_1"
  );

  store.ingestEnvelope(resolveWithCapability, {
    capabilityPresentationToken: resolveCapability.presentation_token
  });

  const thread = store.getThread(threadId);
  assert.equal(thread.subject, "portable token update");
  assert.equal(thread.state, "resolved");

  const listed = store.listCapabilities(threadId, "loom://alice@node.test");
  assert.equal(listed.length, 2);
  assert.equal(listed.every((token) => token.spent === true), true);
});

test("federated non-owner thread_op rejects legacy presentation capability tokens", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_legacy_cap_1", public_key_pem: aliceKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_legacy_cap_1", public_key_pem: bobKeys.publicKeyPem }]
  });

  const threadId = "thr_01ARZ3NDEKTSV4RRFFQ69G5FC9";
  const root = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC8",
      thread_id: threadId,
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_legacy_cap_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:40:00Z",
      priority: "normal",
      content: {
        human: { text: "Initial thread", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_legacy_cap_1"
  );
  store.ingestEnvelope(root);

  const capability = store.issueCapabilityToken(
    {
      thread_id: threadId,
      issued_to: "loom://bob@node.test",
      grants: ["resolve"],
      single_use: true
    },
    "loom://alice@node.test"
  );

  const op = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FCA",
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_legacy_cap_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T20:41:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {
            capability_id: capability.id
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_legacy_cap_1"
  );

  assert.throws(
    () =>
      store.ingestEnvelope(op, {
        actorIdentity: "loom://bob@node.test",
        federated: true,
        capabilityPresentationToken: capability.presentation_token
      }),
    (error) => error?.code === "CAPABILITY_DENIED"
  );
});

test("identity and timestamp validators enforce canonical protocol format", () => {
  assert.equal(isLoomIdentity("loom://alice@node.test"), true);
  assert.equal(isLoomIdentity("loom://Alice@node.test"), false);
  assert.equal(isLoomIdentity("loom://alice@-node.test"), false);

  assert.equal(isIsoDateTime("2026-02-16T20:00:00Z"), true);
  assert.equal(isIsoDateTime("2026-02-16T20:00:00.123Z"), true);
  assert.equal(isIsoDateTime("2026-02-16 20:00:00"), false);
  assert.equal(isIsoDateTime("2026-02-30T20:00:00Z"), false);
});

test("envelope validation enforces type-intent consistency and bcc audience mode", () => {
  const wrongIntent = makeEnvelope({
    type: "task",
    content: {
      human: { text: "bad intent", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    }
  });
  const wrongIntentErrors = validateEnvelopeShape(wrongIntent);
  assert.equal(
    wrongIntentErrors.some((error) => error.field === "content.structured.intent"),
    true
  );

  const bccWithoutAudience = makeEnvelope({
    to: [
      { identity: "loom://bob@node.test", role: "primary" },
      { identity: "loom://carol@node.test", role: "bcc" }
    ]
  });
  const bccErrors = validateEnvelopeShape(bccWithoutAudience);
  assert.equal(
    bccErrors.some((error) => error.field === "audience.mode"),
    true
  );

  const bccWithAudience = makeEnvelope({
    to: [
      { identity: "loom://bob@node.test", role: "primary" },
      { identity: "loom://carol@node.test", role: "bcc" }
    ],
    audience: {
      mode: "recipients"
    }
  });
  const bccAudienceErrors = validateEnvelopeShape(bccWithAudience);
  assert.equal(
    bccAudienceErrors.some((error) => error.field === "audience.mode"),
    false
  );
});

test("delegation authorization uses server-required action context", () => {
  const ownerKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_sign_owner_1", public_key_pem: ownerKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://assistant.owner@node.test",
    type: "agent",
    display_name: "Assistant",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  const delegationWithoutSignature = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FG0",
    delegator: "loom://owner@node.test",
    delegate: "loom://assistant.owner@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T21:30:00Z",
    expires_at: "2027-02-16T21:30:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_owner_1"
  };
  const delegation = {
    ...delegationWithoutSignature,
    signature: signUtf8Message(ownerKeys.privateKeyPem, canonicalizeDelegationLink(delegationWithoutSignature))
  };

  const rootEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG1",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FG2",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://owner@node.test",
        display: "Owner",
        key_id: "k_sign_owner_1",
        type: "human"
      },
      to: [{ identity: "loom://assistant.owner@node.test", role: "primary" }],
      created_at: "2026-02-16T21:31:00Z",
      priority: "normal",
      content: {
        human: { text: "root", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    ownerKeys.privateKeyPem,
    "k_sign_owner_1"
  );
  store.ingestEnvelope(rootEnvelope);

  const capability = store.issueCapabilityToken(
    {
      thread_id: rootEnvelope.thread_id,
      issued_to: "loom://assistant.owner@node.test",
      grants: ["resolve"]
    },
    "loom://owner@node.test"
  );

  const threadOp = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG3",
      thread_id: rootEnvelope.thread_id,
      parent_id: rootEnvelope.id,
      type: "thread_op",
      from: {
        identity: "loom://assistant.owner@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [delegation]
      },
      to: [{ identity: "loom://owner@node.test", role: "primary" }],
      created_at: "2026-02-16T21:32:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(
    () =>
      store.ingestEnvelope(threadOp, {
        requiredActions: ["thread.op.execute@v1"],
        capabilityPresentationToken: capability.presentation_token
      }),
    (error) => error?.code === "DELEGATION_INVALID"
  );
});

test("thread canonical order prioritizes rooted messages over orphaned pending-parent envelopes", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
  });

  const threadId = "thr_01ARZ3NDEKTSV4RRFFQ69G5FG4";
  const orphan = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG5",
      thread_id: threadId,
      parent_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG6",
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T21:39:00Z",
      priority: "normal",
      content: {
        human: { text: "orphan first", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_1"
  );

  const root = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG6",
      thread_id: threadId,
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T21:40:00Z",
      priority: "normal",
      content: {
        human: { text: "root second", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(orphan);
  store.ingestEnvelope(root);

  const ordered = store.getThreadEnvelopes(threadId);
  assert.equal(ordered[0].id, root.id);
  assert.equal(ordered[1].id, orphan.id);
});

test("email outbox processing honors persistence claim lock semantics", async () => {
  let claimAllowed = false;
  const claimCalls = [];
  const releaseCalls = [];
  const store = new LoomStore({
    nodeId: "node.test",
    persistenceAdapter: {
      loadStateAndAudit: async () => ({
        state: null,
        audit_entries: []
      }),
      persistSnapshotAndAudit: async () => {},
      claimOutboxItem: async (payload) => {
        claimCalls.push(payload);
        return {
          claimed: claimAllowed
        };
      },
      releaseOutboxClaim: async (payload) => {
        releaseCalls.push(payload);
        return {
          released: true
        };
      }
    }
  });

  const keys = generateSigningKeyPair();
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
  });

  const inbound = store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      text: "claim test"
    },
    "loom://alice@node.test"
  );

  const queued = store.queueEmailOutbox(
    {
      envelope_id: inbound.envelope_id,
      to_email: ["alice@node.test"],
      smtp_from: "no-reply@node.test"
    },
    "loom://alice@node.test"
  );

  let relaySendCalls = 0;
  const relay = {
    send: async () => {
      relaySendCalls += 1;
      return {
        provider_message_id: "mock-provider-id",
        accepted: ["alice@node.test"],
        rejected: [],
        response: "250 queued",
        relay_mode: "mock"
      };
    }
  };

  const skipped = await store.processEmailOutboxItem(queued.id, relay, "loom://alice@node.test");
  assert.equal(skipped.status, "queued");
  assert.equal(relaySendCalls, 0);
  assert.equal(claimCalls.length, 1);
  assert.equal(releaseCalls.length, 0);

  claimAllowed = true;
  const delivered = await store.processEmailOutboxItem(queued.id, relay, "loom://alice@node.test");
  assert.equal(delivered.status, "delivered");
  assert.equal(relaySendCalls, 1);
  assert.equal(claimCalls.length, 2);
  assert.equal(releaseCalls.length, 1);
  assert.equal(releaseCalls[0].kind, "email");
  assert.equal(releaseCalls[0].outboxId, queued.id);
});

test("maintenance sweep evicts expired access tokens and refresh tokens", () => {
  const store = new LoomStore({ nodeId: "node.test" });

  const pastDate = new Date(Date.now() - 60 * 1000).toISOString();
  const futureDate = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  store.accessTokens.set("at_expired_1", {
    access_token: "at_expired_1",
    identity: "loom://alice@node.test",
    key_id: "k_sign_alice_1",
    created_at: pastDate,
    expires_at: pastDate
  });
  store.accessTokens.set("at_expired_2", {
    access_token: "at_expired_2",
    identity: "loom://bob@node.test",
    key_id: "k_sign_bob_1",
    created_at: pastDate,
    expires_at: pastDate
  });
  store.accessTokens.set("at_valid", {
    access_token: "at_valid",
    identity: "loom://carol@node.test",
    key_id: "k_sign_carol_1",
    created_at: new Date().toISOString(),
    expires_at: futureDate
  });

  store.refreshTokens.set("rt_expired", {
    refresh_token: "rt_expired",
    identity: "loom://alice@node.test",
    key_id: "k_sign_alice_1",
    created_at: pastDate,
    expires_at: pastDate
  });
  store.refreshTokens.set("rt_valid", {
    refresh_token: "rt_valid",
    identity: "loom://bob@node.test",
    key_id: "k_sign_bob_1",
    created_at: new Date().toISOString(),
    expires_at: futureDate
  });

  assert.equal(store.accessTokens.size, 3);
  assert.equal(store.refreshTokens.size, 2);

  const result = store.runMaintenanceSweep();

  assert.equal(store.accessTokens.size, 1);
  assert.ok(store.accessTokens.has("at_valid"));
  assert.equal(store.accessTokens.has("at_expired_1"), false);
  assert.equal(store.accessTokens.has("at_expired_2"), false);

  assert.equal(store.refreshTokens.size, 1);
  assert.ok(store.refreshTokens.has("rt_valid"));
  assert.equal(store.refreshTokens.has("rt_expired"), false);

  assert.ok(result.swept >= 3);
});

test("maintenance sweep evicts used and expired auth challenges", () => {
  const store = new LoomStore({ nodeId: "node.test" });

  const pastDate = new Date(Date.now() - 60 * 1000).toISOString();
  const futureDate = new Date(Date.now() + 60 * 1000).toISOString();

  store.authChallenges.set("ch_expired", {
    challenge_id: "ch_expired",
    identity: "loom://alice@node.test",
    nonce: "nonce1",
    expires_at: pastDate,
    used: false,
    created_at: pastDate
  });
  store.authChallenges.set("ch_used", {
    challenge_id: "ch_used",
    identity: "loom://bob@node.test",
    nonce: "nonce2",
    expires_at: futureDate,
    used: true,
    created_at: new Date().toISOString()
  });
  store.authChallenges.set("ch_active", {
    challenge_id: "ch_active",
    identity: "loom://carol@node.test",
    nonce: "nonce3",
    expires_at: futureDate,
    used: false,
    created_at: new Date().toISOString()
  });

  assert.equal(store.authChallenges.size, 3);

  store.runMaintenanceSweep();

  assert.equal(store.authChallenges.size, 1);
  assert.ok(store.authChallenges.has("ch_active"));
  assert.equal(store.authChallenges.has("ch_expired"), false);
  assert.equal(store.authChallenges.has("ch_used"), false);
});

test("maintenance sweep evicts stale identity rate limit buckets", () => {
  const windowMs = 60 * 1000;
  const store = new LoomStore({ nodeId: "node.test", identityRateWindowMs: windowMs });

  const staleTime = Date.now() - windowMs * 3;
  const freshTime = Date.now() - windowMs / 2;

  store.identityRateByBucket.set("default:loom://stale@node.test", {
    count: 5,
    window_started_at: staleTime
  });
  store.identityRateByBucket.set("sensitive:loom://stale2@node.test", {
    count: 3,
    window_started_at: staleTime
  });
  store.identityRateByBucket.set("default:loom://fresh@node.test", {
    count: 2,
    window_started_at: freshTime
  });

  assert.equal(store.identityRateByBucket.size, 3);

  store.runMaintenanceSweep();

  assert.equal(store.identityRateByBucket.size, 1);
  assert.ok(store.identityRateByBucket.has("default:loom://fresh@node.test"));
  assert.equal(store.identityRateByBucket.has("default:loom://stale@node.test"), false);
  assert.equal(store.identityRateByBucket.has("sensitive:loom://stale2@node.test"), false);
});

test("maintenance sweep caps consumedPortableCapabilityIds to configured max", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    consumedCapabilityMaxEntries: 100
  });

  for (let i = 0; i < 150; i++) {
    store.consumedPortableCapabilityIds.add(`cap_${String(i).padStart(10, "0")}`);
  }

  assert.equal(store.consumedPortableCapabilityIds.size, 150);

  store.runMaintenanceSweep();

  assert.equal(store.consumedPortableCapabilityIds.size, 100);

  const remaining = Array.from(store.consumedPortableCapabilityIds);
  assert.ok(remaining.every((id) => id.startsWith("cap_")));
  assert.ok(remaining.includes("cap_0000000149"));
  assert.ok(remaining.includes("cap_0000000050"));
  assert.equal(remaining.includes("cap_0000000000"), false);
  assert.equal(remaining.includes("cap_0000000049"), false);
});

test("maintenance sweep caps revokedDelegationIds to configured max", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    revokedDelegationMaxEntries: 100
  });

  for (let i = 0; i < 130; i++) {
    store.revokedDelegationIds.add(`del_${String(i).padStart(10, "0")}`);
  }

  assert.equal(store.revokedDelegationIds.size, 130);

  store.runMaintenanceSweep();

  assert.equal(store.revokedDelegationIds.size, 100);

  const remaining = Array.from(store.revokedDelegationIds);
  assert.ok(remaining.includes("del_0000000129"));
  assert.ok(remaining.includes("del_0000000030"));
  assert.equal(remaining.includes("del_0000000000"), false);
  assert.equal(remaining.includes("del_0000000029"), false);
});

test("maintenance sweep does not remove entries that are still valid", () => {
  const store = new LoomStore({ nodeId: "node.test" });

  const futureDate = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const freshTime = Date.now();

  store.accessTokens.set("at_1", {
    access_token: "at_1",
    identity: "loom://a@node.test",
    expires_at: futureDate
  });
  store.refreshTokens.set("rt_1", {
    refresh_token: "rt_1",
    identity: "loom://a@node.test",
    expires_at: futureDate
  });
  store.authChallenges.set("ch_1", {
    challenge_id: "ch_1",
    expires_at: futureDate,
    used: false
  });
  store.identityRateByBucket.set("default:loom://a@node.test", {
    count: 1,
    window_started_at: freshTime
  });

  store.consumedPortableCapabilityIds.add("cap_a");
  store.consumedPortableCapabilityIds.add("cap_b");
  store.revokedDelegationIds.add("del_a");

  store.runMaintenanceSweep();

  assert.equal(store.accessTokens.size, 1);
  assert.equal(store.refreshTokens.size, 1);
  assert.equal(store.authChallenges.size, 1);
  assert.equal(store.identityRateByBucket.size, 1);
  assert.equal(store.consumedPortableCapabilityIds.size, 2);
  assert.equal(store.revokedDelegationIds.size, 1);
});

test("maintenance sweep delegates to existing federation nonce cleanup", () => {
  const store = new LoomStore({ nodeId: "node.test" });

  const oldMs = Date.now() - 20 * 60 * 1000;
  const freshMs = Date.now() - 1000;

  store.federationNonceCache.set("remote.test:nonce_old", oldMs);
  store.federationNonceCache.set("remote.test:nonce_fresh", freshMs);

  assert.equal(store.federationNonceCache.size, 2);

  store.runMaintenanceSweep();

  assert.equal(store.federationNonceCache.size, 1);
  assert.ok(store.federationNonceCache.has("remote.test:nonce_fresh"));
  assert.equal(store.federationNonceCache.has("remote.test:nonce_old"), false);
});

test("maintenance sweep returns swept count reflecting total evictions", () => {
  const store = new LoomStore({ nodeId: "node.test" });

  const pastDate = new Date(Date.now() - 60 * 1000).toISOString();

  store.accessTokens.set("at_exp", {
    access_token: "at_exp",
    identity: "loom://a@node.test",
    expires_at: pastDate
  });
  store.refreshTokens.set("rt_exp", {
    refresh_token: "rt_exp",
    identity: "loom://a@node.test",
    expires_at: pastDate
  });
  store.authChallenges.set("ch_exp", {
    challenge_id: "ch_exp",
    expires_at: pastDate,
    used: false
  });

  const result = store.runMaintenanceSweep();

  assert.ok(typeof result.swept === "number");
  assert.ok(result.swept >= 3);
});

test("bridge inbound ignores payload auth_results when disabled and sanitizes original headers", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    bridgeInboundAllowPayloadAuthResults: false,
    bridgeInboundRequireAuthResults: true
  });

  const result = store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      text: "bridge auth boundary",
      auth_results: {
        spf: "pass",
        dkim: "pass",
        dmarc: "pass"
      },
      headers: {
        Subject: "Bridge Boundary",
        "X-Not-Allowed": "secret",
        Date: new Date().toUTCString()
      }
    },
    "loom://alice@node.test"
  );

  assert.equal(result.quarantined, true);
  const envelope = store.getEnvelope(result.envelope_id);
  assert.equal(envelope?.meta?.bridge?.auth_results?.source, "none");
  assert.equal(envelope?.meta?.bridge?.original_headers?.Subject, "Bridge Boundary");
  assert.equal(Object.prototype.hasOwnProperty.call(envelope?.meta?.bridge?.original_headers || {}, "X-Not-Allowed"), false);
  assert.equal(envelope?.meta?.bridge?.auth_policy?.allow_payload_auth_results, false);
});

test("bridge sender envelopes cannot trigger automatic workflow actuation by default", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    mcpClientEnabled: false
  });

  const inbound = store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      text: "bridge baseline"
    },
    "loom://alice@node.test"
  );

  const unsignedWorkflowEnvelope = {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC1",
    thread_id: inbound.thread_id,
    parent_id: inbound.envelope_id,
    type: "workflow",
    from: {
      identity: "bridge://sender@example.net",
      display: "sender@example.net",
      key_id: store.systemSigningKeyId,
      type: "bridge"
    },
    to: [{ identity: "loom://alice@node.test", role: "primary" }],
    created_at: "2026-02-21T10:00:00Z",
    priority: "normal",
    content: {
      human: {
        text: "run workflow now",
        format: "plaintext"
      },
      structured: {
        intent: "workflow.execute@v1",
        parameters: {
          workflow_id: "wf_bridge_01",
          definition: {
            steps: [{ step_id: "step_1" }]
          }
        }
      },
      encrypted: false
    },
    attachments: []
  };

  const signed = signEnvelope(
    unsignedWorkflowEnvelope,
    store.systemSigningPrivateKeyPem,
    store.systemSigningKeyId
  );

  assert.throws(
    () => store.ingestEnvelope(signed, { actorIdentity: "bridge://sender@example.net" }),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      /non-authoritative/.test(String(error?.message || "")) &&
      error?.details?.field === "type"
  );
});

test("bridge sender workflow envelopes are allowed only with explicit opt-in", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    mcpClientEnabled: false,
    bridgeInboundAllowAutomaticActuation: true
  });

  const inbound = store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      text: "bridge baseline"
    },
    "loom://alice@node.test"
  );

  const unsignedWorkflowEnvelope = {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FC2",
    thread_id: inbound.thread_id,
    parent_id: inbound.envelope_id,
    type: "workflow",
    from: {
      identity: "bridge://sender@example.net",
      display: "sender@example.net",
      key_id: store.systemSigningKeyId,
      type: "bridge"
    },
    to: [{ identity: "loom://alice@node.test", role: "primary" }],
    created_at: "2026-02-21T10:05:00Z",
    priority: "normal",
    content: {
      human: {
        text: "run workflow now",
        format: "plaintext"
      },
      structured: {
        intent: "workflow.execute@v1",
        parameters: {
          workflow_id: "wf_bridge_02",
          definition: {
            steps: [{ step_id: "step_1" }]
          }
        }
      },
      encrypted: false
    },
    attachments: []
  };

  const signed = signEnvelope(
    unsignedWorkflowEnvelope,
    store.systemSigningPrivateKeyPem,
    store.systemSigningKeyId
  );

  const stored = store.ingestEnvelope(signed, { actorIdentity: "bridge://sender@example.net" });
  assert.equal(stored.type, "workflow");
  const thread = store.getThread(stored.thread_id);
  assert.equal(thread?.workflow?.workflow_id, "wf_bridge_02");
});

test("core protocol profile rejects workflow extension envelopes at ingest", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    protocolProfile: "loom-core-1"
  });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_core_workflow_1", public_key_pem: keys.publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD1",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FD2",
      parent_id: null,
      type: "workflow",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_core_workflow_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-22T10:00:00Z",
      priority: "normal",
      content: {
        human: { text: "execute core-blocked workflow", format: "plaintext" },
        structured: {
          intent: "workflow.execute@v1",
          parameters: {
            workflow_id: "wf_core_blocked_1",
            definition: { steps: [{ step_id: "step_1" }] }
          }
        },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_core_workflow_1"
  );

  assert.throws(
    () => store.ingestEnvelope(envelope),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      error?.details?.extension_id === "loom-ext-workflow-v1"
  );
});

test("core protocol profile rejects MCP runtime intents at ingest", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    protocolProfile: "loom-core-1"
  });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_core_mcp_1", public_key_pem: keys.publicKeyPem }]
  });

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD3",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FD4",
      parent_id: null,
      type: "workflow",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_core_mcp_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-22T10:05:00Z",
      priority: "normal",
      content: {
        human: { text: "invoke tool via workflow envelope", format: "plaintext" },
        structured: {
          intent: "mcp.tool_request@v1",
          parameters: {
            tool: "filesystem.read",
            args: { path: "/tmp/mock.txt" }
          }
        },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_core_mcp_1"
  );

  assert.throws(
    () => store.ingestEnvelope(envelope),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      error?.details?.extension_id === "loom-ext-mcp-runtime-v1"
  );
});

test("core protocol profile rejects E2EE extension envelopes at ingest", () => {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    protocolProfile: "loom-core-1"
  });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_core_e2ee_1", public_key_pem: keys.publicKeyPem }]
  });

  const encryptedEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD5",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FD6",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_core_e2ee_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-22T10:10:00Z",
      priority: "normal",
      content: {
        encrypted: true,
        profile: "loom-e2ee-1",
        epoch: 0,
        ciphertext: "YWJj",
        wrapped_keys: [
          {
            to: "loom://bob@node.test",
            algorithm: "X25519-HKDF-SHA256",
            key_id: "k_enc_bob_core_1",
            ciphertext: "ZGVm"
          }
        ]
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_core_e2ee_1"
  );

  assert.throws(
    () => store.ingestEnvelope(encryptedEnvelope),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      error?.details?.extension_id === "loom-ext-e2ee-x25519-v1" &&
      error?.details?.field === "content.encrypted"
  );

  const encryptionIntentEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD7",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FD8",
      parent_id: null,
      type: "thread_op",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_core_e2ee_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-22T10:11:00Z",
      priority: "normal",
      content: {
        human: { text: "rotate keys", format: "plaintext" },
        structured: {
          intent: "encryption.rotate@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_core_e2ee_1"
  );

  assert.throws(
    () => store.ingestEnvelope(encryptionIntentEnvelope),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      error?.details?.extension_id === "loom-ext-e2ee-x25519-v1" &&
      error?.details?.field === "content.structured.intent"
  );
});

test("core protocol profile rejects bridge sender envelopes at ingest", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    protocolProfile: "loom-core-1"
  });

  const bridgeEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD9",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FE0",
      parent_id: null,
      type: "message",
      from: {
        identity: "bridge://sender@example.net",
        display: "sender@example.net",
        key_id: store.systemSigningKeyId,
        type: "bridge"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-22T10:15:00Z",
      priority: "normal",
      content: {
        human: { text: "bridge content", format: "plaintext" },
        structured: {
          intent: "message.general@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    store.systemSigningPrivateKeyPem,
    store.systemSigningKeyId
  );

  assert.throws(
    () => store.ingestEnvelope(bridgeEnvelope, { actorIdentity: "bridge://sender@example.net" }),
    (error) =>
      error?.code === "CAPABILITY_DENIED" &&
      error?.details?.extension_id === "loom-ext-email-bridge-v1"
  );
});

test("bridge inbound content filter rejects risky executable attachments", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    inboundContentFilterEnabled: true,
    inboundContentFilterRejectMalware: true
  });

  assert.throws(
    () =>
      store.createBridgeInboundEnvelope(
        {
          smtp_from: "sender@example.net",
          rcpt_to: ["alice@node.test"],
          subject: "Invoice",
          text: "See attached invoice",
          attachments: [
            {
              filename: "invoice.pdf.exe",
              mime_type: "application/octet-stream"
            }
          ]
        },
        "loom://alice@node.test"
      ),
    (error) => error?.code === "CAPABILITY_DENIED"
  );

  const status = store.getInboundContentFilterStatus();
  assert.equal(status.rejected >= 1, true);
});

test("bridge inbound content filter can quarantine phishing-like content and expose metadata", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    inboundContentFilterEnabled: true
  });

  const result = store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      subject: "Notice",
      text: "Verify your account now: https://bit.ly/recover-account"
    },
    "loom://alice@node.test"
  );

  assert.equal(result.quarantined, true);

  const envelope = store.getEnvelope(result.envelope_id);
  assert.equal(envelope?.meta?.security?.content_filter?.action, "quarantine");
  assert.equal(Array.isArray(envelope?.meta?.security?.content_filter?.signal_codes), true);

  const thread = store.getThread(result.thread_id);
  assert.equal(thread?.labels?.includes("sys.quarantine"), true);
});

test("content filter tracks profile-labeled decision counters for calibration metrics", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    inboundContentFilterEnabled: true,
    inboundContentFilterProfileDefault: "balanced",
    inboundContentFilterProfileBridge: "strict",
    inboundContentFilterProfileFederation: "agent"
  });

  const allowed = store.evaluateInboundContentPolicy(
    {
      subject: "Pipeline digest",
      text: "Automated workflow summary for job-42. No operator action required."
    },
    {
      source: "federation"
    }
  );
  assert.equal(allowed.profile, "agent");
  assert.equal(allowed.action, "allow");

  const quarantined = store.evaluateInboundContentPolicy(
    {
      subject: "Login required",
      text: "Login required to review account state: https://bit.ly/session-check https://xn--billing-check-9ob.example/login"
    },
    {
      source: "federation"
    }
  );
  assert.equal(quarantined.profile, "agent");
  assert.equal(quarantined.action, "quarantine");

  const rejected = store.evaluateInboundContentPolicy(
    {
      subject: "Invoice attachment",
      text: "Please inspect attachment.",
      attachments: [
        {
          filename: "invoice.pdf.exe",
          mime_type: "application/octet-stream"
        }
      ]
    },
    {
      source: "bridge_email"
    }
  );
  assert.equal(rejected.profile, "strict");
  assert.equal(rejected.action, "reject");

  const status = store.getInboundContentFilterStatus();
  assert.equal(status.evaluated, 3);
  assert.equal(status.rejected, 1);
  assert.equal(status.quarantined, 1);
  assert.equal(status.decision_counts_by_profile.agent.evaluated, 2);
  assert.equal(status.decision_counts_by_profile.agent.allow, 1);
  assert.equal(status.decision_counts_by_profile.agent.quarantine, 1);
  assert.equal(status.decision_counts_by_profile.agent.reject, 0);
  assert.equal(status.decision_counts_by_profile.strict.evaluated, 1);
  assert.equal(status.decision_counts_by_profile.strict.reject, 1);
});

test("content filter decision counters persist across restart", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "loom-content-filter-persist-"));
  try {
    const storeA = new LoomStore({
      nodeId: "node.test",
      dataDir,
      inboundContentFilterEnabled: true
    });

    storeA.evaluateInboundContentPolicy(
      {
        subject: "Workflow digest",
        text: "Pipeline summary for run-123. no action needed."
      },
      {
        source: "federation",
        profile: "agent"
      }
    );
    storeA.evaluateInboundContentPolicy(
      {
        subject: "Security alert",
        text: "verify your account now: https://bit.ly/security-check"
      },
      {
        source: "bridge_email",
        profile: "strict"
      }
    );
    storeA.persistState();

    const storeB = new LoomStore({
      nodeId: "node.test",
      dataDir
    });
    const status = storeB.getInboundContentFilterStatus();
    assert.equal(status.evaluated, 2);
    assert.equal(status.decision_counts_by_profile.agent.evaluated, 1);
    assert.equal(status.decision_counts_by_profile.strict.evaluated, 1);
    assert.equal(status.quarantined >= 1 || status.rejected >= 1, true);
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("content filter config supports canary apply rollback workflow", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    inboundContentFilterEnabled: true
  });
  const before = store.getInboundContentFilterConfigStatus();

  const canary = store.updateInboundContentFilterConfig(
    {
      mode: "canary",
      config: {
        quarantine_threshold: 6,
        reject_threshold: 9,
        profile_federation: "strict"
      },
      note: "canary threshold hardening"
    },
    "admin"
  );
  assert.equal(canary.active.quarantine_threshold, before.active.quarantine_threshold);
  assert.equal(canary.canary?.config?.quarantine_threshold, 6);
  assert.equal(canary.canary?.config?.reject_threshold, 9);

  const applied = store.updateInboundContentFilterConfig(
    {
      mode: "apply"
    },
    "admin"
  );
  assert.equal(applied.active.quarantine_threshold, 6);
  assert.equal(applied.active.reject_threshold, 9);
  assert.equal(applied.active.profile_federation, "strict");
  assert.equal(applied.canary, null);
  assert.equal(applied.rollback?.config?.quarantine_threshold, before.active.quarantine_threshold);

  const rolledBack = store.updateInboundContentFilterConfig(
    {
      mode: "rollback"
    },
    "admin"
  );
  assert.equal(rolledBack.active.quarantine_threshold, before.active.quarantine_threshold);
  assert.equal(rolledBack.active.reject_threshold, before.active.reject_threshold);
});

test("content filter decision telemetry log writes anonymized profile decisions", () => {
  const workDir = mkdtempSync(join(tmpdir(), "loom-content-filter-log-"));
  const decisionLogFile = join(workDir, "content-filter-decisions.jsonl");

  try {
    const store = new LoomStore({
      nodeId: "node.test",
      inboundContentFilterEnabled: true,
      inboundContentFilterDecisionLogEnabled: true,
      inboundContentFilterDecisionLogFile: decisionLogFile,
      inboundContentFilterDecisionLogSalt: "test-salt",
      inboundContentFilterProfileDefault: "balanced",
      inboundContentFilterProfileFederation: "agent"
    });

    const result = store.evaluateInboundContentPolicy(
      {
        subject: "Agent digest",
        text: "Workflow summary for loom://ops@node.test see https://ops.example.net/runbooks/17"
      },
      {
        source: "federation",
        actor: "loom://ops@node.test",
        node_id: "remote.example"
      }
    );

    assert.equal(result.profile, "agent");
    const raw = readFileSync(decisionLogFile, "utf-8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    assert.equal(raw.length, 1);
    const entry = JSON.parse(raw[0]);
    assert.equal(entry.source, "federation");
    assert.equal(entry.profile, "agent");
    assert.equal(entry.action, "allow");
    assert.equal(typeof entry.subject_hash, "string");
    assert.equal(typeof entry.text_hash, "string");
    assert.equal(Object.prototype.hasOwnProperty.call(entry, "subject"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(entry, "text"), false);
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
});

test("federation protocol capabilities negotiation is fetched and recorded for known node", async () => {
  const keyPair = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test"
  });

  const node = store.registerFederationNode(
    {
      node_id: "remote.test",
      key_id: "k_node_remote_1",
      public_key_pem: keyPair.publicKeyPem,
      deliver_url: "https://remote.test/v1/federation/deliver",
      protocol_capabilities_url: "https://remote.test/v1/protocol/capabilities"
    },
    "admin"
  );

  store.fetchFederationJsonDocument = async () => ({
    url: "https://remote.test/v1/protocol/capabilities",
    payload: {
      loom_version: "1.1",
      node_id: "remote.test",
      federation_negotiation: {
        trust_anchor_mode: store.getFederationTrustAnchorMode(),
        trust_anchor_modes_supported: [store.getFederationTrustAnchorMode()],
        e2ee_profiles: ["loom-e2ee-x25519-xchacha20-v1"]
      }
    }
  });

  const refreshed = await store.ensureFederationNodeProtocolCapabilities(node, "admin", {
    forceRefresh: true,
    failOnMissing: true,
    failOnFetchError: true,
    persist: false
  });

  assert.equal(refreshed.protocol_capabilities_url, "https://remote.test/v1/protocol/capabilities");
  assert.deepEqual(refreshed.negotiated_e2ee_profiles, ["loom-e2ee-x25519-xchacha20-v1"]);
  assert.equal(refreshed.protocol_negotiated_trust_anchor_mode, store.getFederationTrustAnchorMode());
  assert.equal(refreshed.protocol_capabilities_fetch_error, null);
});

test("federation trust DNS proof enforces DNSSEC validation when required", async () => {
  const trustRecord =
    "v=loomfed1;keyset=https://remote.test/.well-known/loom-keyset.json;digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;revocations=https://remote.test/.well-known/loom-revocations.json;trust_epoch=1;version=1";

  const storeWithoutDnssec = new LoomStore({
    nodeId: "node.test",
    federationTrustMode: "public_dns_webpki",
    federationTrustRequireDnssec: true,
    federationTrustDnsTxtResolver: async () => [[trustRecord]]
  });

  await assert.rejects(
    async () => {
      await storeWithoutDnssec.resolveFederationTrustDnsProof("remote.test");
    },
    (error) => error?.code === "SIGNATURE_INVALID"
  );

  const storeWithDnssec = new LoomStore({
    nodeId: "node.test",
    federationTrustMode: "public_dns_webpki",
    federationTrustRequireDnssec: true,
    federationTrustDnsTxtResolver: async () => ({
      answers: [[trustRecord]],
      dnssec_validated: true,
      dnssec_source: "test-dnssec"
    })
  });

  const proof = await storeWithDnssec.resolveFederationTrustDnsProof("remote.test");
  assert.equal(proof.dnssec_validated, true);
  assert.equal(proof.dnssec_source, "test-dnssec");
});

test("federation trust transparency checkpoint chain advances deterministically", () => {
  const store = new LoomStore({ nodeId: "node.test" });
  const hashV1 = "a".repeat(64);
  const hashV2 = "b".repeat(64);

  const first = store.deriveFederationTrustTransparencyState("remote.test", 1, 1, hashV1);
  assert.equal(first.event_index, 0);
  assert.equal(typeof first.checkpoint, "string");
  assert.equal(first.mode, "local_append_only");

  const unchanged = store.deriveFederationTrustTransparencyState(
    "remote.test",
    1,
    1,
    hashV1,
    {
      node_id: "remote.test",
      trust_anchor_epoch: 1,
      trust_anchor_keyset_version: 1,
      trust_anchor_keyset_hash: hashV1,
      trust_anchor_transparency_log_id: first.log_id,
      trust_anchor_transparency_mode: first.mode,
      trust_anchor_transparency_checkpoint: first.checkpoint,
      trust_anchor_transparency_previous_checkpoint: first.previous_checkpoint,
      trust_anchor_transparency_event_index: first.event_index,
      trust_anchor_transparency_verified_at: first.verified_at
    }
  );
  assert.equal(unchanged.appended, false);
  assert.equal(unchanged.event_index, first.event_index);
  assert.equal(unchanged.checkpoint, first.checkpoint);

  const second = store.deriveFederationTrustTransparencyState(
    "remote.test",
    2,
    2,
    hashV2,
    {
      node_id: "remote.test",
      trust_anchor_epoch: 1,
      trust_anchor_keyset_version: 1,
      trust_anchor_keyset_hash: hashV1,
      trust_anchor_transparency_log_id: first.log_id,
      trust_anchor_transparency_mode: first.mode,
      trust_anchor_transparency_checkpoint: first.checkpoint,
      trust_anchor_transparency_previous_checkpoint: first.previous_checkpoint,
      trust_anchor_transparency_event_index: first.event_index,
      trust_anchor_transparency_verified_at: first.verified_at
    }
  );
  assert.equal(second.appended, true);
  assert.equal(second.event_index, 1);
  assert.equal(second.previous_checkpoint, first.checkpoint);
  assert.notEqual(second.checkpoint, first.checkpoint);
});

test("federation outbox compatibility rejects unsupported encrypted profile negotiation", () => {
  const store = new LoomStore({ nodeId: "node.test" });
  const node = {
    node_id: "remote.test",
    protocol_capabilities: {
      loom_version: "1.1",
      node_id: "remote.test",
      federation_negotiation: {
        trust_anchor_mode: store.getFederationTrustAnchorMode(),
        trust_anchor_modes_supported: [store.getFederationTrustAnchorMode()],
        e2ee_profiles: []
      }
    },
    negotiated_e2ee_profiles: [],
    protocol_negotiated_trust_anchor_mode: store.getFederationTrustAnchorMode()
  };
  const encryptedEnvelope = {
    id: "env_enc_1",
    content: {
      encrypted: true,
      profile: "loom-e2ee-x25519-xchacha20-v1"
    }
  };

  assert.throws(
    () => store.assertFederationOutboxNodeCompatibility(node, [encryptedEnvelope]),
    (error) => error?.code === "CAPABILITY_DENIED"
  );

  node.protocol_capabilities.federation_negotiation.e2ee_profiles = ["loom-e2ee-x25519-xchacha20-v1"];
  node.negotiated_e2ee_profiles = ["loom-e2ee-x25519-xchacha20-v1"];
  assert.doesNotThrow(() => store.assertFederationOutboxNodeCompatibility(node, [encryptedEnvelope]));
});

test("maintenance sweep message retention removes expired thread envelopes and scoped artifacts", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    messageRetentionDays: 1
  });

  const oldDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
  const threadId = "thr_retention_old";
  const envelopeId = "env_retention_old";

  store.envelopesById.set(envelopeId, {
    id: envelopeId,
    thread_id: threadId,
    created_at: oldDate,
    parent_id: null,
    meta: {}
  });
  store.threadsById.set(threadId, {
    id: threadId,
    root_envelope_id: envelopeId,
    subject: "Retention Subject",
    state: "active",
    created_at: oldDate,
    updated_at: oldDate,
    participants: [
      {
        identity: "loom://alice@node.test",
        role: "owner",
        joined_at: oldDate,
        left_at: null
      }
    ],
    labels: [],
    cap_epoch: 0,
    encryption: {
      enabled: false,
      profile: null,
      key_epoch: 0
    },
    envelope_ids: [envelopeId],
    pending_parent_count: 0
  });

  store.capabilitiesById.set("cap_retention_old", {
    id: "cap_retention_old",
    thread_id: threadId,
    secret_hash: "cap_retention_hash"
  });
  store.capabilityIdBySecretHash.set("cap_retention_hash", "cap_retention_old");
  store.delegationsById.set("del_retention_old", {
    id: "del_retention_old",
    thread_id: threadId
  });
  store.revokedDelegationIds.add("del_retention_old");

  const result = store.runMaintenanceSweep();
  assert.equal(store.envelopesById.has(envelopeId), false);
  assert.equal(store.threadsById.has(threadId), false);
  assert.equal(store.capabilitiesById.has("cap_retention_old"), false);
  assert.equal(store.capabilityIdBySecretHash.has("cap_retention_hash"), false);
  assert.equal(store.delegationsById.has("del_retention_old"), false);
  assert.equal(store.revokedDelegationIds.has("del_retention_old"), false);
  assert.ok(result.swept >= 1);
});

test("maintenance sweep blob retention scrubs referenced blobs and removes unreferenced blobs", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    blobRetentionDays: 1
  });
  const oldDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();

  store.envelopesById.set("env_blob_ref", {
    id: "env_blob_ref",
    thread_id: "thr_blob_ref",
    created_at: oldDate,
    attachments: [
      {
        blob_id: "blob_ref"
      }
    ],
    meta: {}
  });

  store.blobsById.set("blob_ref", {
    id: "blob_ref",
    created_by: "loom://alice@node.test",
    created_at: oldDate,
    completed_at: oldDate,
    status: "complete",
    data_base64: Buffer.from("hello", "utf-8").toString("base64"),
    size_bytes: 5,
    hash: "sha256:abc",
    quota_accounted_bytes: 5,
    parts: {
      "1": Buffer.from("hello", "utf-8").toString("base64")
    }
  });
  store.blobsById.set("blob_unreferenced", {
    id: "blob_unreferenced",
    created_by: "loom://alice@node.test",
    created_at: oldDate,
    completed_at: oldDate,
    status: "complete",
    data_base64: Buffer.from("bye", "utf-8").toString("base64"),
    size_bytes: 3,
    hash: "sha256:def",
    quota_accounted_bytes: 3,
    parts: {}
  });

  store.runMaintenanceSweep();

  const referenced = store.blobsById.get("blob_ref");
  assert.ok(referenced);
  assert.equal(referenced.status, "expired");
  assert.equal(referenced.data_base64, undefined);
  assert.equal(referenced.size_bytes, 0);
  assert.equal(store.blobsById.has("blob_unreferenced"), false);
});

test("outbox worker backoff formula doubles on consecutive failures and caps at 5 minutes", () => {
  let backoffMs = 0;

  function applyBackoff() {
    backoffMs = Math.min(300000, backoffMs === 0 ? 10000 : backoffMs * 2);
    return backoffMs;
  }

  function resetBackoff() {
    backoffMs = 0;
  }

  assert.equal(applyBackoff(), 10000);
  assert.equal(applyBackoff(), 20000);
  assert.equal(applyBackoff(), 40000);
  assert.equal(applyBackoff(), 80000);
  assert.equal(applyBackoff(), 160000);
  assert.equal(applyBackoff(), 300000);
  assert.equal(applyBackoff(), 300000);

  resetBackoff();
  assert.equal(backoffMs, 0);
  assert.equal(applyBackoff(), 10000);
});

test("persistState uses atomic write pattern and produces no leftover tmp file", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "loom-atomic-"));
  try {
    const { publicKeyPem } = generateSigningKeyPair();
    const store = new LoomStore({ nodeId: "node.test", dataDir });

    store.registerIdentity({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_atomic_1", public_key_pem: publicKeyPem }]
    });

    const stateFile = join(dataDir, "state.json");
    const tmpFile = `${stateFile}.tmp`;

    assert.ok(existsSync(stateFile), "state file should exist after registration");
    assert.ok(!existsSync(tmpFile), "tmp file should not remain after atomic write");

    const content = JSON.parse(readFileSync(stateFile, "utf-8"));
    assert.equal(content.identities.length, 1);
    assert.equal(content.identities[0].id, "loom://alice@node.test");
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("persistState survives reload after atomic write", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "loom-atomic-reload-"));
  try {
    const { publicKeyPem } = generateSigningKeyPair();
    const storeA = new LoomStore({ nodeId: "node.test", dataDir });

    storeA.registerIdentity({
      id: "loom://bob@node.test",
      display_name: "Bob",
      signing_keys: [{ key_id: "k_sign_bob_atom_1", public_key_pem: publicKeyPem }]
    });

    const storeB = new LoomStore({ nodeId: "node.test", dataDir });
    const identity = storeB.resolveIdentity("loom://bob@node.test");
    assert.ok(identity, "reloaded store should find the persisted identity");
    assert.equal(identity.display_name, "Bob");
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("registerIdentity enforces maxLocalIdentities limit", () => {
  const store = new LoomStore({ nodeId: "node.test", maxLocalIdentities: 2 });

  for (let i = 0; i < 2; i++) {
    const { publicKeyPem } = generateSigningKeyPair();
    store.registerIdentity({
      id: `loom://user${i}@node.test`,
      display_name: `User ${i}`,
      signing_keys: [{ key_id: `k_local_lim_${i}`, public_key_pem: publicKeyPem }]
    });
  }

  const { publicKeyPem: extraKey } = generateSigningKeyPair();
  assert.throws(
    () => store.registerIdentity({
      id: "loom://overflow@node.test",
      display_name: "Overflow",
      signing_keys: [{ key_id: "k_local_lim_overflow", public_key_pem: extraKey }]
    }),
    (error) => error?.code === "RESOURCE_LIMIT" && error.message.includes("local")
  );
});

test("registerIdentity enforces maxRemoteIdentities limit", () => {
  const store = new LoomStore({ nodeId: "node.test", maxRemoteIdentities: 2 });

  for (let i = 0; i < 2; i++) {
    const { publicKeyPem } = generateSigningKeyPair();
    store.registerIdentity(
      {
        id: `loom://remote${i}@other.test`,
        display_name: `Remote ${i}`,
        signing_keys: [{ key_id: `k_remote_lim_${i}`, public_key_pem: publicKeyPem }]
      },
      { importedRemote: true, allowRemoteDomain: true, skipRegistrationProof: true }
    );
  }

  const { publicKeyPem: extraKey } = generateSigningKeyPair();
  assert.throws(
    () => store.registerIdentity(
      {
        id: "loom://overflow@other.test",
        display_name: "Overflow",
        signing_keys: [{ key_id: "k_remote_lim_overflow", public_key_pem: extraKey }]
      },
      { importedRemote: true, allowRemoteDomain: true, skipRegistrationProof: true }
    ),
    (error) => error?.code === "RESOURCE_LIMIT" && error.message.includes("remote")
  );
});

test("registerIdentity allows overwrite even at limit (does not block updates)", () => {
  const store = new LoomStore({ nodeId: "node.test", maxLocalIdentities: 1 });

  const { publicKeyPem } = generateSigningKeyPair();
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice v1",
    signing_keys: [{ key_id: "k_overwrite_1", public_key_pem: publicKeyPem }]
  });

  const { publicKeyPem: newKey } = generateSigningKeyPair();
  const updated = store.registerIdentity(
    {
      id: "loom://alice@node.test",
      display_name: "Alice v2",
      signing_keys: [{ key_id: "k_overwrite_2", public_key_pem: newKey }]
    },
    { allowOverwrite: true }
  );
  assert.equal(updated.display_name, "Alice v2");
});

test("createDelegation enforces maxDelegationsTotal limit", () => {
  const ownerKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test", maxDelegationsTotal: 2 });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_dlg_total_owner", public_key_pem: ownerKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://agent@node.test",
    type: "agent",
    display_name: "Agent",
    signing_keys: [{ key_id: "k_dlg_total_agent", public_key_pem: agentKeys.publicKeyPem }]
  });

  for (let i = 0; i < 2; i++) {
    const dlgPayload = {
      id: `dlg_total_${i}`,
      delegator: "loom://owner@node.test",
      delegate: "loom://agent@node.test",
      scope: ["message.general@v1"],
      created_at: "2026-02-16T20:32:00Z",
      expires_at: "2027-02-16T20:32:00Z",
      revocable: true,
      allow_sub_delegation: false,
      max_sub_delegation_depth: 0,
      key_id: "k_dlg_total_owner"
    };
    dlgPayload.signature = signUtf8Message(
      ownerKeys.privateKeyPem,
      canonicalizeDelegationLink(dlgPayload)
    );
    store.createDelegation(dlgPayload, "loom://owner@node.test");
  }

  const overflowPayload = {
    id: "dlg_total_overflow",
    delegator: "loom://owner@node.test",
    delegate: "loom://agent@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:32:00Z",
    expires_at: "2027-02-16T20:32:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_dlg_total_owner"
  };
  overflowPayload.signature = signUtf8Message(
    ownerKeys.privateKeyPem,
    canonicalizeDelegationLink(overflowPayload)
  );
  assert.throws(
    () => store.createDelegation(overflowPayload, "loom://owner@node.test"),
    (error) => error?.code === "RESOURCE_LIMIT" && error.message.includes("total")
  );
});

test("createDelegation enforces maxDelegationsPerIdentity limit", () => {
  const ownerKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test", maxDelegationsPerIdentity: 1 });

  store.registerIdentity({
    id: "loom://owner@node.test",
    display_name: "Owner",
    signing_keys: [{ key_id: "k_dlg_per_owner", public_key_pem: ownerKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://agent@node.test",
    type: "agent",
    display_name: "Agent",
    signing_keys: [{ key_id: "k_dlg_per_agent", public_key_pem: agentKeys.publicKeyPem }]
  });

  const firstPayload = {
    id: "dlg_per_first",
    delegator: "loom://owner@node.test",
    delegate: "loom://agent@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:32:00Z",
    expires_at: "2027-02-16T20:32:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_dlg_per_owner"
  };
  firstPayload.signature = signUtf8Message(
    ownerKeys.privateKeyPem,
    canonicalizeDelegationLink(firstPayload)
  );
  store.createDelegation(firstPayload, "loom://owner@node.test");

  const secondPayload = {
    id: "dlg_per_second",
    delegator: "loom://owner@node.test",
    delegate: "loom://agent@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:33:00Z",
    expires_at: "2027-02-16T20:33:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_dlg_per_owner"
  };
  secondPayload.signature = signUtf8Message(
    ownerKeys.privateKeyPem,
    canonicalizeDelegationLink(secondPayload)
  );
  assert.throws(
    () => store.createDelegation(secondPayload, "loom://owner@node.test"),
    (error) => error?.code === "RESOURCE_LIMIT" && error.message.includes("per identity")
  );
});
