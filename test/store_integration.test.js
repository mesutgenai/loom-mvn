import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { encryptE2eePayload, generateE2eeX25519KeyPair } from "../src/protocol/e2ee.js";
import { createCapabilityPoP } from "../src/protocol/capability_pop.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";

const WRAPPED_KEY_ALGORITHM = "X25519-HKDF-SHA256";

function envId() {
  return `env_${generateUlid()}`;
}
function thrId() {
  return `thr_${generateUlid()}`;
}

function makeEnvelope(overrides = {}) {
  return {
    loom: "1.1",
    id: envId(),
    thread_id: thrId(),
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_int_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-20T10:00:00Z",
    priority: "normal",
    content: {
      human: { text: "hello", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    ...overrides
  };
}

function signBase(privateKeyPem, keyId, overrides = {}) {
  const envelope = makeEnvelope(overrides);
  return signEnvelope(envelope, privateKeyPem, keyId);
}

function encryptContent({ profile = "loom-e2ee-x25519-xchacha20-v1", epoch, replayCounter = 0, plaintext, recipients }) {
  return encryptE2eePayload({
    profile,
    epoch,
    replayCounter,
    plaintext,
    recipients: recipients.map((r) => ({
      to: r.to,
      key_id: r.key_id,
      public_key: r.public_key,
      algorithm: WRAPPED_KEY_ALGORITHM
    }))
  });
}

function registerIdentity(store, { id, displayName, signingKeyId, signingPublicKeyPem, encryptionKeyId, encryptionPublicKey }) {
  const identity = {
    id,
    display_name: displayName,
    signing_keys: [{ key_id: signingKeyId, public_key_pem: signingPublicKeyPem }]
  };
  if (encryptionKeyId && encryptionPublicKey) {
    identity.encryption_keys = [
      { key_id: encryptionKeyId, algorithm: "X25519", public_key: encryptionPublicKey, status: "active" }
    ];
  }
  store.registerIdentity(identity);
}

// ─── Sliding Window Replay Integration Tests ───────────────────────────────

test("store: sliding_window replay mode accepts out-of-order counters", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test", replayMode: "sliding_window" });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  // Root envelope (counter 0)
  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  store.ingestEnvelope(root);

  // Counter 5 (jump ahead)
  const msg5 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: root.id,
    content: encryptContent({ epoch: 0, replayCounter: 5, plaintext: { m: "five" }, recipients: [recipients[1]] })
  });
  store.ingestEnvelope(msg5);

  // Counter 3 (out-of-order, within window) — should succeed in sliding_window mode
  const msg3 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg5.id,
    content: encryptContent({ epoch: 0, replayCounter: 3, plaintext: { m: "three" }, recipients: [recipients[1]] })
  });
  store.ingestEnvelope(msg3);

  // Counter 3 duplicate — should fail even in sliding_window
  const msg3dup = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg3.id,
    content: encryptContent({ epoch: 0, replayCounter: 3, plaintext: { m: "dup" }, recipients: [recipients[1]] })
  });
  assert.throws(
    () => store.ingestEnvelope(msg3dup),
    (err) => err?.code === "STATE_TRANSITION_INVALID"
  );
});

test("store: strict replay mode (default) rejects out-of-order counters", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" }); // default = strict

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  store.ingestEnvelope(root);

  // Counter 5 (jump ahead — allowed in strict mode, just needs to increase)
  const msg5 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: root.id,
    content: encryptContent({ epoch: 0, replayCounter: 5, plaintext: { m: "five" }, recipients: [recipients[1]] })
  });
  store.ingestEnvelope(msg5);

  // Counter 3 (out-of-order) — should FAIL in strict mode
  const msg3 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg5.id,
    content: encryptContent({ epoch: 0, replayCounter: 3, plaintext: { m: "three" }, recipients: [recipients[1]] })
  });
  assert.throws(
    () => store.ingestEnvelope(msg3),
    (err) => err?.code === "STATE_TRANSITION_INVALID"
  );
});

test("store: replayMode can be overridden per-ingest via context", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" }); // default = strict

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  // Override to sliding_window at ingest time
  store.ingestEnvelope(root, { replayMode: "sliding_window" });

  const msg5 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: root.id,
    content: encryptContent({ epoch: 0, replayCounter: 5, plaintext: { m: "five" }, recipients: [recipients[1]] })
  });
  store.ingestEnvelope(msg5, { replayMode: "sliding_window" });

  // Out-of-order should succeed because context overrides to sliding_window
  const msg3 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg5.id,
    content: encryptContent({ epoch: 0, replayCounter: 3, plaintext: { m: "three" }, recipients: [recipients[1]] })
  });
  store.ingestEnvelope(msg3, { replayMode: "sliding_window" });

  const envelopes = store.getThreadEnvelopes(threadId);
  assert.equal(envelopes.length, 3);
});

// ─── Thread Limits Integration Tests ────────────────────────────────────────

test("store: thread limits reject envelope when thread exceeds max_envelopes_per_thread", () => {
  const aliceKeys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    threadMaxEnvelopesPerThread: 3
  });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem
  });

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId
  });
  store.ingestEnvelope(root);

  const msg2 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: root.id
  });
  store.ingestEnvelope(msg2);

  const msg3 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg2.id
  });
  store.ingestEnvelope(msg3);

  // Fourth envelope should be rejected (thread has 3 envelopes, limit is 3)
  const msg4 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg3.id
  });
  assert.throws(
    () => store.ingestEnvelope(msg4),
    (err) => err?.code === "ENVELOPE_INVALID"
  );
});

test("store: thread limits can be overridden per-ingest via context", () => {
  const aliceKeys = generateSigningKeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    threadMaxEnvelopesPerThread: 2
  });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem
  });

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId
  });
  store.ingestEnvelope(root);

  const msg2 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: root.id
  });
  store.ingestEnvelope(msg2);

  // Should fail with store-level limit of 2
  const msg3 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    parent_id: msg2.id
  });
  assert.throws(
    () => store.ingestEnvelope(msg3),
    (err) => err?.code === "ENVELOPE_INVALID"
  );

  // Should succeed with overridden higher limit via context
  store.ingestEnvelope(msg3, { threadLimits: { max_envelopes_per_thread: 100, max_pending_parents: 500 } });
  const envelopes = store.getThreadEnvelopes(threadId);
  assert.equal(envelopes.length, 3);
});

// ─── PoP Integration Tests ─────────────────────────────────────────────────

test("store: PoP-required intent with cnf-bound token succeeds with valid PoP signature", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  // Create encrypted root thread
  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  store.ingestEnvelope(root);

  // Issue capability to bob for key rotation (a PoP-required intent)
  const cap = store.issueCapabilityToken(
    { thread_id: threadId, issued_to: "loom://bob@node.test", grants: ["admin"], single_use: false },
    "loom://alice@node.test"
  );

  // Directly bind a cnf key to the internal token for PoP testing
  const internalToken = store.capabilitiesById.get(cap.id);
  internalToken.cnf = { key_id: "k_sign_bob_int_1" };

  // Create a PoP signature for the rotate operation
  const rotateEnvelopeId = envId();
  const popTimestamp = new Date().toISOString();
  const popSignature = createCapabilityPoP({
    capabilityId: internalToken.id,
    envelopeId: rotateEnvelopeId,
    timestamp: popTimestamp,
    privateKeyPem: bobKeys.privateKeyPem
  });

  // Bob performs epoch rotation with valid PoP
  const rotateOp = signEnvelope(
    {
      loom: "1.1",
      id: rotateEnvelopeId,
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: { identity: "loom://bob@node.test", display: "Bob", key_id: "k_sign_bob_int_1", type: "human" },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: popTimestamp,
      priority: "normal",
      content: {
        structured: {
          intent: "encryption.rotate@v1",
          parameters: {
            epoch: 1,
            wrapped_keys: encryptContent({
              epoch: 1,
              replayCounter: 0,
              plaintext: { op: "rotate" },
              recipients
            }).wrapped_keys,
            capability_token: cap.portable_token,
            pop_signature: popSignature,
            pop_timestamp: popTimestamp
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_int_1"
  );

  store.ingestEnvelope(rotateOp);
  const thread = store.getThread(threadId);
  assert.equal(thread.encryption.key_epoch, 1);
});

test("store: PoP-required intent with cnf-bound token fails with wrong key", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const wrongKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  store.ingestEnvelope(root);

  const cap = store.issueCapabilityToken(
    { thread_id: threadId, issued_to: "loom://bob@node.test", grants: ["admin"], single_use: false },
    "loom://alice@node.test"
  );

  const internalToken = store.capabilitiesById.get(cap.id);
  internalToken.cnf = { key_id: "k_sign_bob_int_1" };

  const rotateEnvelopeId = envId();
  const popTimestamp = new Date().toISOString();

  // Sign with WRONG key
  const popSignature = createCapabilityPoP({
    capabilityId: internalToken.id,
    envelopeId: rotateEnvelopeId,
    timestamp: popTimestamp,
    privateKeyPem: wrongKeys.privateKeyPem
  });

  const rotateOp = signEnvelope(
    {
      loom: "1.1",
      id: rotateEnvelopeId,
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: { identity: "loom://bob@node.test", display: "Bob", key_id: "k_sign_bob_int_1", type: "human" },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: popTimestamp,
      priority: "normal",
      content: {
        structured: {
          intent: "encryption.rotate@v1",
          parameters: {
            epoch: 1,
            wrapped_keys: encryptContent({
              epoch: 1,
              replayCounter: 0,
              plaintext: { op: "rotate" },
              recipients
            }).wrapped_keys,
            capability_token: cap.portable_token,
            pop_signature: popSignature,
            pop_timestamp: popTimestamp
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_int_1"
  );

  assert.throws(
    () => store.ingestEnvelope(rotateOp),
    (err) => err?.code === "CAPABILITY_DENIED"
  );
});

test("store: PoP-required intent with cnf-bound token fails when PoP signature is missing", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEnc = generateE2eeX25519KeyPair();
  const bobEnc = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: "k_sign_alice_int_1",
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: "k_enc_alice_int_1",
    encryptionPublicKey: aliceEnc.public_key
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: "k_sign_bob_int_1",
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: "k_enc_bob_int_1",
    encryptionPublicKey: bobEnc.public_key
  });

  const recipients = [
    { to: "loom://alice@node.test", key_id: "k_enc_alice_int_1", public_key: aliceEnc.public_key },
    { to: "loom://bob@node.test", key_id: "k_enc_bob_int_1", public_key: bobEnc.public_key }
  ];

  const threadId = thrId();

  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_int_1", {
    thread_id: threadId,
    content: encryptContent({ epoch: 0, replayCounter: 0, plaintext: { m: "root" }, recipients })
  });
  store.ingestEnvelope(root);

  const cap = store.issueCapabilityToken(
    { thread_id: threadId, issued_to: "loom://bob@node.test", grants: ["admin"], single_use: false },
    "loom://alice@node.test"
  );

  const internalToken = store.capabilitiesById.get(cap.id);
  internalToken.cnf = { key_id: "k_sign_bob_int_1" };

  // Omit pop_signature and pop_timestamp
  const rotateOp = signEnvelope(
    {
      loom: "1.1",
      id: envId(),
      thread_id: threadId,
      parent_id: root.id,
      type: "thread_op",
      from: { identity: "loom://bob@node.test", display: "Bob", key_id: "k_sign_bob_int_1", type: "human" },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: new Date().toISOString(),
      priority: "normal",
      content: {
        structured: {
          intent: "encryption.rotate@v1",
          parameters: {
            epoch: 1,
            wrapped_keys: encryptContent({
              epoch: 1,
              replayCounter: 0,
              plaintext: { op: "rotate" },
              recipients
            }).wrapped_keys,
            capability_token: cap.portable_token
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_int_1"
  );

  assert.throws(
    () => store.ingestEnvelope(rotateOp),
    (err) => err?.code === "CAPABILITY_DENIED"
  );
});
