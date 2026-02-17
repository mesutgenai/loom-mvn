import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalizeEnvelope } from "../src/protocol/canonical.js";
import {
  generateSigningKeyPair,
  signEnvelope,
  signUtf8Message,
  verifyEnvelopeSignature
} from "../src/protocol/crypto.js";
import { canonicalizeDelegationLink } from "../src/protocol/delegation.js";
import { validateEnvelopeShape } from "../src/protocol/envelope.js";
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

  const adapter = {
    async loadStateAndAudit() {
      return {
        state: seedStore.toSerializableState(),
        audit_entries: seedStore.auditEntries
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

  const capability = store.issueCapabilityToken(
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
      created_at: "2026-02-16T20:12:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: { capability_token: capability.id }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_1"
  );

  store.ingestEnvelope(resolveWithCapability);

  const thread = store.getThread(threadId);
  assert.equal(thread.state, "resolved");

  const listed = store.listCapabilities(threadId, "loom://alice@node.test");
  assert.equal(listed[0].spent, true);
});
