import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { generateSigningKeyPair, signEnvelope, toBase64Url } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import {
  resolveE2eeProfile,
  listSupportedE2eeProfiles,
  generateE2eeX25519KeyPair,
  encryptE2eePayload
} from "../src/protocol/e2ee.js";
import {
  generateMlsLeafKeyPair,
  createMlsGroupState,
  computePathSecrets,
  encryptPathSecrets,
  computeTreeHash,
  encryptMlsPayload,
  validateMlsWelcome,
  validateMlsCommit,
  MLS_PROFILE_ID
} from "../src/protocol/mls.js";
import { LoomStore } from "../src/node/store.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

const ALICE_SIGNING_KEY_ID = "k_sign_alice_mls_1";
const BOB_SIGNING_KEY_ID = "k_sign_bob_mls_1";

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
      key_id: ALICE_SIGNING_KEY_ID,
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
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

function signBaseEnvelope(privateKeyPem, overrides = {}) {
  const unsigned = makeEnvelope(overrides);
  delete unsigned.signature;
  return signEnvelope(unsigned, privateKeyPem, unsigned.from.key_id);
}

function registerIdentity(store, { id, displayName, signingKeyId, signingPublicKeyPem }) {
  store.registerIdentity({
    id,
    display_name: displayName,
    signing_keys: [{ key_id: signingKeyId, public_key_pem: signingPublicKeyPem }],
    encryption_keys: []
  });
}

function setupAliceBobStore() {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentity(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem
  });
  registerIdentity(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem
  });

  return { store, aliceKeys, bobKeys };
}

function createRootEnvelope(store, alicePrivateKeyPem) {
  const threadId = thrId();
  const root = signBaseEnvelope(alicePrivateKeyPem, {
    id: envId(),
    thread_id: threadId
  });
  store.ingestEnvelope(root);
  return root;
}

function buildMlsWelcomeParameters(participants) {
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_test",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  return {
    mls_welcome: {
      tree: groupState.tree,
      group_secrets: groupSecrets,
      tree_hash: groupState.tree_hash,
      retained_epoch_limit: groupState.retained_epoch_limit
    },
    groupState
  };
}

// ─── Profile Activation ─────────────────────────────────────────────────────

test("resolveE2eeProfile resolves loom-e2ee-mls-1 to non-null", () => {
  const profile = resolveE2eeProfile("loom-e2ee-mls-1");
  assert.ok(profile, "MLS profile should be resolvable");
  assert.equal(profile.id, "loom-e2ee-mls-1");
  assert.equal(profile.requires_mls_metadata, true);
  assert.equal(profile.requires_wrapped_keys, false);
  assert.equal(profile.replay_counter_required, false);
  assert.equal(profile.profile_commitment_required, false);
});

test("resolveE2eeProfile resolves loom-mls-1 alias", () => {
  const profile = resolveE2eeProfile("loom-mls-1");
  assert.ok(profile);
  assert.equal(profile.id, "loom-e2ee-mls-1");
});

test("listSupportedE2eeProfiles includes loom-e2ee-mls-1", () => {
  const profiles = listSupportedE2eeProfiles();
  assert.ok(profiles.includes("loom-e2ee-mls-1"), "MLS profile should be in supported list");
});

test("MLS profile has forward secrecy and post-compromise security properties", () => {
  const profile = resolveE2eeProfile("loom-e2ee-mls-1");
  assert.equal(profile.security_properties.forward_secrecy, true);
  assert.equal(profile.security_properties.post_compromise_security, true);
  assert.equal(profile.security_properties.confidentiality, "mls_grade");
});

// ─── MLS Migration via encryption.epoch@v1 ──────────────────────────────────

test("encryption.epoch@v1 enables MLS profile on thread with mls_welcome", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });

  store.ingestEnvelope(enable);

  const thread = store.getThread(root.thread_id);
  assert.equal(thread.encryption.enabled, true);
  assert.equal(thread.encryption.profile, "loom-e2ee-mls-1");
  assert.equal(thread.encryption.key_epoch, 0);
  assert.ok(thread.encryption.mls_state, "thread should have mls_state");
  assert.equal(thread.encryption.mls_state.group_id, root.thread_id);
  assert.equal(thread.encryption.mls_state.epoch, 0);
  assert.equal(thread.encryption.mls_state.tree.length, 2);
});

test("encryption.epoch@v1 rejects MLS profile without mls_welcome", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0
          // no mls_welcome
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(enable),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("encryption.epoch@v1 rejects MLS welcome missing participant group_secret", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  // Only create secrets for Alice, not Bob
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);
  // Remove Bob's group secret
  mls_welcome.group_secrets = mls_welcome.group_secrets.filter(
    (gs) => gs.to !== "loom://bob@node.test"
  );

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(enable),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

// ─── MLS Encrypted Envelopes ────────────────────────────────────────────────

test("MLS encrypted envelope accepted with valid mls_metadata", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  // Enable MLS on thread
  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome, groupState } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  // Send encrypted message with MLS metadata
  const { ciphertext, mls_metadata } = encryptMlsPayload({
    groupState,
    senderLeafIndex: 0,
    plaintext: "Hello from Alice!"
  });

  const encrypted = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: enable.id,
    type: "message",
    content: {
      encrypted: true,
      profile: "loom-e2ee-mls-1",
      epoch: 0,
      ciphertext,
      mls_metadata
    }
  });

  const stored = store.ingestEnvelope(encrypted);
  assert.ok(stored.id);
  assert.equal(stored.thread_id, root.thread_id);
});

test("MLS encrypted envelope rejected without mls_metadata", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  // Enable MLS on thread
  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  // Try encrypted message without mls_metadata (only ciphertext)
  const encrypted = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: enable.id,
    type: "message",
    content: {
      encrypted: true,
      profile: "loom-e2ee-mls-1",
      epoch: 0,
      ciphertext: toBase64Url(randomBytes(48))
      // no mls_metadata
    }
  });

  assert.throws(
    () => store.ingestEnvelope(encrypted),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

// ─── Epoch Rotation via encryption.rotate@v1 ────────────────────────────────

test("encryption.rotate@v1 with mls_commit advances epoch and updates tree", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  // Enable MLS on thread
  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome, groupState } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  // Alice rotates key
  const newAliceKp = generateMlsLeafKeyPair();
  const pathSecrets = computePathSecrets(groupState.tree, 0, aliceMlsKp.private_key);
  const encryptedPathSecrets = encryptPathSecrets(pathSecrets, groupState.tree);
  const newTree = groupState.tree.map((l) => (l ? { ...l } : null));
  newTree[0] = { ...newTree[0], public_key: newAliceKp.public_key, generation: 1 };
  const newTreeHash = toBase64Url(computeTreeHash(newTree));

  const rotate = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: enable.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.rotate@v1",
        parameters: {
          epoch: 1,
          mls_commit: {
            sender_leaf_index: 0,
            new_leaf_public_key: newAliceKp.public_key,
            path_secrets: encryptedPathSecrets,
            tree_hash: newTreeHash
          }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(rotate);

  const thread = store.getThread(root.thread_id);
  assert.equal(thread.encryption.key_epoch, 1);
  assert.equal(thread.encryption.mls_state.epoch, 1);
  assert.equal(thread.encryption.mls_state.tree[0].public_key, newAliceKp.public_key);
  assert.equal(thread.encryption.mls_state.tree[0].generation, 1);
  assert.equal(thread.encryption.mls_state.tree_hash, newTreeHash);
});

test("encryption.rotate@v1 rejects MLS without mls_commit", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  const rotate = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: enable.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.rotate@v1",
        parameters: {
          epoch: 1
          // no mls_commit
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(rotate),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

// ─── MLS Profile Migration ─────────────────────────────────────────────────

test("MLS migration from v2 is auto-allowed (rank 300 > 200)", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncKp = generateE2eeX25519KeyPair();
  const bobEncKp = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  // Register identities with both signing and encryption keys
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: ALICE_SIGNING_KEY_ID, public_key_pem: aliceKeys.publicKeyPem }],
    encryption_keys: [{
      key_id: "k_enc_alice_1",
      algorithm: "X25519",
      public_key: aliceEncKp.public_key,
      status: "active"
    }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: BOB_SIGNING_KEY_ID, public_key_pem: bobKeys.publicKeyPem }],
    encryption_keys: [{
      key_id: "k_enc_bob_1",
      algorithm: "X25519",
      public_key: bobEncKp.public_key,
      status: "active"
    }]
  });

  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  // Enable v2 encryption first
  const v2content = encryptE2eePayload({
    profile: "loom-e2ee-x25519-xchacha20-v2",
    epoch: 0,
    plaintext: { setup: true },
    recipients: [
      { to: "loom://alice@node.test", key_id: "k_enc_alice_1", public_key: aliceEncKp.public_key },
      { to: "loom://bob@node.test", key_id: "k_enc_bob_1", public_key: bobEncKp.public_key }
    ]
  });

  const enableV2 = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v2",
          epoch: 0,
          wrapped_keys: v2content.wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enableV2);

  const threadAfterV2 = store.getThread(root.thread_id);
  assert.equal(threadAfterV2.encryption.profile, "loom-e2ee-x25519-xchacha20-v2");

  // Now migrate to MLS
  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);

  const enableMls = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: enableV2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 1,
          mls_welcome
        }
      },
      encrypted: false
    }
  });

  // This should succeed — MLS rank (300) > v2 rank (200)
  store.ingestEnvelope(enableMls);

  const threadAfterMls = store.getThread(root.thread_id);
  assert.equal(threadAfterMls.encryption.profile, "loom-e2ee-mls-1");
  assert.equal(threadAfterMls.encryption.key_epoch, 1);
  assert.ok(threadAfterMls.encryption.mls_state);
});

// ─── MLS Encrypted Thread Bootstrap ─────────────────────────────────────────

test("new thread with MLS encrypted content is accepted", () => {
  const { store, aliceKeys } = setupAliceBobStore();

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { groupState } = createMlsGroupState({
    groupId: "thr_bootstrap",
    participants
  });

  const { ciphertext, mls_metadata } = encryptMlsPayload({
    groupState,
    senderLeafIndex: 0,
    plaintext: "Bootstrap message"
  });

  const bootstrapEnvelope = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: thrId(),
    type: "message",
    content: {
      encrypted: true,
      profile: "loom-e2ee-mls-1",
      epoch: 0,
      ciphertext,
      mls_metadata
    }
  });

  const stored = store.ingestEnvelope(bootstrapEnvelope);
  assert.ok(stored.id);

  const thread = store.getThread(stored.thread_id);
  assert.equal(thread.encryption.enabled, true);
  assert.equal(thread.encryption.profile, "loom-e2ee-mls-1");
});

// ─── Forward Secrecy Properties ─────────────────────────────────────────────

test("multiple MLS epoch rotations track state correctly", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome, groupState } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  let parentId = enable.id;
  let currentTree = groupState.tree.map((l) => ({ ...l }));
  let currentPrivKey = aliceMlsKp.private_key;

  // Perform 3 rotations
  for (let i = 1; i <= 3; i++) {
    const newKp = generateMlsLeafKeyPair();
    const pathSecrets = computePathSecrets(currentTree, 0, currentPrivKey);
    const encryptedSecrets = encryptPathSecrets(pathSecrets, currentTree);
    const newTree = currentTree.map((l) => (l ? { ...l } : null));
    newTree[0] = { ...newTree[0], public_key: newKp.public_key, generation: i };
    const treeHash = toBase64Url(computeTreeHash(newTree));

    const rotate = signBaseEnvelope(aliceKeys.privateKeyPem, {
      id: envId(),
      thread_id: root.thread_id,
      parent_id: parentId,
      type: "thread_op",
      content: {
        structured: {
          intent: "encryption.rotate@v1",
          parameters: {
            epoch: i,
            mls_commit: {
              sender_leaf_index: 0,
              new_leaf_public_key: newKp.public_key,
              path_secrets: encryptedSecrets,
              tree_hash: treeHash
            }
          }
        },
        encrypted: false
      }
    });
    store.ingestEnvelope(rotate);
    parentId = rotate.id;
    currentTree = newTree;
    currentPrivKey = newKp.private_key;
  }

  const thread = store.getThread(root.thread_id);
  assert.equal(thread.encryption.key_epoch, 3);
  assert.equal(thread.encryption.mls_state.epoch, 3);
  assert.equal(thread.encryption.mls_state.tree[0].generation, 3);
});

// ─── State Persistence ──────────────────────────────────────────────────────

test("MLS thread state survives save/load cycle", () => {
  const { store, aliceKeys } = setupAliceBobStore();
  const root = createRootEnvelope(store, aliceKeys.privateKeyPem);

  const aliceMlsKp = generateMlsLeafKeyPair();
  const bobMlsKp = generateMlsLeafKeyPair();
  const participants = [
    { identity: "loom://alice@node.test", public_key: aliceMlsKp.public_key },
    { identity: "loom://bob@node.test", public_key: bobMlsKp.public_key }
  ];
  const { mls_welcome } = buildMlsWelcomeParameters(participants);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: envId(),
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-mls-1",
          epoch: 0,
          mls_welcome
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  // Serialize and restore
  const state = store.toSerializableState();
  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const thread = store2.getThread(root.thread_id);
  assert.equal(thread.encryption.enabled, true);
  assert.equal(thread.encryption.profile, "loom-e2ee-mls-1");
  assert.ok(thread.encryption.mls_state);
  assert.equal(thread.encryption.mls_state.group_id, root.thread_id);
  assert.equal(thread.encryption.mls_state.tree.length, 2);
  assert.equal(thread.encryption.mls_state.tree[0].identity, "loom://alice@node.test");
});

// ─── Validation ─────────────────────────────────────────────────────────────

test("validateMlsWelcome and validateMlsCommit are accessible from mls.js", () => {
  // Smoke test that the exports are correct
  assert.equal(typeof validateMlsWelcome, "function");
  assert.equal(typeof validateMlsCommit, "function");

  const welcomeErrors = validateMlsWelcome({});
  assert.ok(welcomeErrors.length > 0);

  const commitErrors = validateMlsCommit({});
  assert.ok(commitErrors.length > 0);
});

// ─── Security Rank ──────────────────────────────────────────────────────────

test("MLS profile security rank is highest (300)", () => {
  const { store } = setupAliceBobStore();
  const mlsRank = store.getE2eeProfileSecurityRank("loom-e2ee-mls-1");
  const v2Rank = store.getE2eeProfileSecurityRank("loom-e2ee-x25519-xchacha20-v2");
  const v1Rank = store.getE2eeProfileSecurityRank("loom-e2ee-x25519-xchacha20-v1");
  assert.equal(mlsRank, 300);
  assert.equal(v2Rank, 200);
  assert.equal(v1Rank, 100);
  assert.ok(mlsRank > v2Rank);
  assert.ok(v2Rank > v1Rank);
});
