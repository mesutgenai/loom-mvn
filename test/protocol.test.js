import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
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
