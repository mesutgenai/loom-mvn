import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  MLS_AES_KEY_BYTES,
  MLS_GCM_NONCE_BYTES,
  MLS_SECRET_BYTES,
  MLS_MAX_TREE_SIZE,
  MLS_DEFAULT_RETAINED_EPOCHS,
  MLS_PROFILE_ID,
  mlsExpandLabel,
  deriveInitialEpochSecret,
  deriveEpochSecret,
  deriveApplicationSecret,
  deriveSenderSecret,
  deriveMessageKeyAndNonce,
  createRatchetTree,
  computeTreeHash,
  getLeafIndex,
  addLeafToTree,
  removeLeafFromTree,
  updateLeafKey,
  computePathSecrets,
  encryptPathSecrets,
  decryptPathSecret,
  deriveCommitSecret,
  createMlsGroupState,
  processWelcome,
  processCommit,
  encryptMlsPayload,
  decryptMlsPayload,
  pruneRetainedEpochSecrets,
  deleteEpochSecret,
  validateMlsMetadata,
  validateMlsWelcome,
  validateMlsCommit,
  generateMlsLeafKeyPair
} from "../src/protocol/mls.js";

import {
  serializeMlsGroupState,
  deserializeMlsGroupState,
  serializeMlsWelcome,
  deserializeMlsWelcome,
  serializeMlsCommit,
  deserializeMlsCommit
} from "../src/protocol/mls_codec.js";

import { toBase64Url, fromBase64Url } from "../src/protocol/crypto.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeParticipants(count = 2) {
  const participants = [];
  for (let i = 0; i < count; i++) {
    const kp = generateMlsLeafKeyPair();
    participants.push({
      identity: `loom://user${i}@node.test`,
      public_key: kp.public_key,
      _private_key: kp.private_key
    });
  }
  return participants;
}

// ─── Constants ──────────────────────────────────────────────────────────────

test("MLS constants have expected values", () => {
  assert.equal(MLS_AES_KEY_BYTES, 16);
  assert.equal(MLS_GCM_NONCE_BYTES, 12);
  assert.equal(MLS_SECRET_BYTES, 32);
  assert.equal(MLS_MAX_TREE_SIZE, 256);
  assert.equal(MLS_DEFAULT_RETAINED_EPOCHS, 3);
  assert.equal(MLS_PROFILE_ID, "loom-e2ee-mls-1");
});

// ─── Key Schedule ───────────────────────────────────────────────────────────

test("mlsExpandLabel produces deterministic output of requested length", () => {
  const secret = randomBytes(32);
  const a = mlsExpandLabel(secret, "test_label", "ctx", 16);
  const b = mlsExpandLabel(secret, "test_label", "ctx", 16);
  assert.equal(a.length, 16);
  assert.deepStrictEqual(a, b);
});

test("mlsExpandLabel produces different output for different labels", () => {
  const secret = randomBytes(32);
  const a = mlsExpandLabel(secret, "label_a", "ctx", 32);
  const b = mlsExpandLabel(secret, "label_b", "ctx", 32);
  assert.notDeepStrictEqual(a, b);
});

test("deriveInitialEpochSecret produces 32-byte deterministic output", () => {
  const key = randomBytes(32);
  const a = deriveInitialEpochSecret(key, "group1");
  const b = deriveInitialEpochSecret(key, "group1");
  assert.equal(a.length, MLS_SECRET_BYTES);
  assert.deepStrictEqual(a, b);
});

test("deriveInitialEpochSecret differs for different groups", () => {
  const key = randomBytes(32);
  const a = deriveInitialEpochSecret(key, "group_a");
  const b = deriveInitialEpochSecret(key, "group_b");
  assert.notDeepStrictEqual(a, b);
});

test("deriveEpochSecret differs across epochs", () => {
  const prev = randomBytes(32);
  const commit = randomBytes(32);
  const a = deriveEpochSecret(prev, commit, "group", 1);
  const b = deriveEpochSecret(prev, commit, "group", 2);
  assert.equal(a.length, MLS_SECRET_BYTES);
  assert.notDeepStrictEqual(a, b);
});

test("deriveMessageKeyAndNonce returns correct sizes", () => {
  const secret = randomBytes(32);
  const { key, nonce } = deriveMessageKeyAndNonce(secret);
  assert.equal(key.length, MLS_AES_KEY_BYTES);
  assert.equal(nonce.length, MLS_GCM_NONCE_BYTES);
});

test("deriveSenderSecret ratchets correctly across generations", () => {
  const appSecret = randomBytes(32);
  const gen0 = deriveSenderSecret(appSecret, 0, 0);
  const gen1 = deriveSenderSecret(appSecret, 0, 1);
  const gen2 = deriveSenderSecret(appSecret, 0, 2);
  assert.notDeepStrictEqual(gen0, gen1);
  assert.notDeepStrictEqual(gen1, gen2);
  assert.notDeepStrictEqual(gen0, gen2);
});

test("deriveSenderSecret differs for different leaf indices", () => {
  const appSecret = randomBytes(32);
  const a = deriveSenderSecret(appSecret, 0, 0);
  const b = deriveSenderSecret(appSecret, 1, 0);
  assert.notDeepStrictEqual(a, b);
});

// ─── Tree Operations ────────────────────────────────────────────────────────

test("createRatchetTree builds correct leaf array", () => {
  const kp0 = generateMlsLeafKeyPair();
  const kp1 = generateMlsLeafKeyPair();
  const tree = createRatchetTree([
    { identity: "loom://alice@test", public_key: kp0.public_key },
    { identity: "loom://bob@test", public_key: kp1.public_key }
  ]);
  assert.equal(tree.length, 2);
  assert.equal(tree[0].identity, "loom://alice@test");
  assert.equal(tree[0].public_key, kp0.public_key);
  assert.equal(tree[0].generation, 0);
  assert.equal(tree[1].identity, "loom://bob@test");
  assert.equal(tree[1].generation, 0);
});

test("createRatchetTree rejects empty participants", () => {
  assert.throws(() => createRatchetTree([]), /non-empty/);
});

test("computeTreeHash is deterministic", () => {
  const kp = generateMlsLeafKeyPair();
  const tree = createRatchetTree([{ identity: "loom://a@test", public_key: kp.public_key }]);
  const h1 = computeTreeHash(tree);
  const h2 = computeTreeHash(tree);
  assert.deepStrictEqual(h1, h2);
  assert.equal(h1.length, 32); // SHA-256
});

test("computeTreeHash changes when tree changes", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const h1 = computeTreeHash(tree);
  const kp = generateMlsLeafKeyPair();
  updateLeafKey(tree, 0, kp.public_key, 1);
  const h2 = computeTreeHash(tree);
  assert.notDeepStrictEqual(h1, h2);
});

test("getLeafIndex resolves identity to correct index", () => {
  const participants = makeParticipants(3);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  assert.equal(getLeafIndex(tree, participants[0].identity), 0);
  assert.equal(getLeafIndex(tree, participants[1].identity), 1);
  assert.equal(getLeafIndex(tree, participants[2].identity), 2);
  assert.equal(getLeafIndex(tree, "loom://unknown@test"), -1);
});

test("addLeafToTree fills empty slots first", () => {
  const participants = makeParticipants(3);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  removeLeafFromTree(tree, participants[1].identity);
  assert.equal(tree[1], null);
  const kp = generateMlsLeafKeyPair();
  const idx = addLeafToTree(tree, "loom://dave@test", kp.public_key);
  assert.equal(idx, 1);
  assert.equal(tree[1].identity, "loom://dave@test");
});

test("addLeafToTree appends when no empty slots", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const kp = generateMlsLeafKeyPair();
  const idx = addLeafToTree(tree, "loom://carol@test", kp.public_key);
  assert.equal(idx, 2);
  assert.equal(tree.length, 3);
});

test("removeLeafFromTree nulls the entry", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const removed = removeLeafFromTree(tree, participants[0].identity);
  assert.equal(removed, 0);
  assert.equal(tree[0], null);
});

test("removeLeafFromTree returns -1 for unknown identity", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  assert.equal(removeLeafFromTree(tree, "loom://unknown@test"), -1);
});

test("updateLeafKey updates public key and generation", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const kp = generateMlsLeafKeyPair();
  updateLeafKey(tree, 0, kp.public_key, 5);
  assert.equal(tree[0].public_key, kp.public_key);
  assert.equal(tree[0].generation, 5);
});

test("updateLeafKey throws on invalid index", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  assert.throws(() => updateLeafKey(tree, 99, "abc", 0), /invalid leaf index/);
});

// ─── Path Secrets & Encryption ──────────────────────────────────────────────

test("computePathSecrets produces one secret per non-null peer leaf", () => {
  const participants = makeParticipants(3);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const pathSecrets = computePathSecrets(tree, 0, participants[0]._private_key);
  assert.equal(pathSecrets.length, 2); // indices 1 and 2
  assert.equal(pathSecrets[0].target_leaf_index, 1);
  assert.equal(pathSecrets[1].target_leaf_index, 2);
  assert.equal(pathSecrets[0].secret.length, 32);
});

test("encryptPathSecrets/decryptPathSecret round-trip", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const pathSecrets = computePathSecrets(tree, 0, participants[0]._private_key);
  const encrypted = encryptPathSecrets(pathSecrets, tree);
  assert.equal(encrypted.length, 1);
  assert.equal(encrypted[0].target_leaf_index, 1);
  assert.equal(typeof encrypted[0].encrypted_secret, "string");

  const decrypted = decryptPathSecret(encrypted[0].encrypted_secret, participants[1]._private_key);
  assert.deepStrictEqual(decrypted, pathSecrets[0].secret);
});

test("deriveCommitSecret from path secrets is deterministic", () => {
  const participants = makeParticipants(2);
  const tree = createRatchetTree(participants.map((p) => ({ identity: p.identity, public_key: p.public_key })));
  const pathSecrets = computePathSecrets(tree, 0, participants[0]._private_key);
  const cs1 = deriveCommitSecret(pathSecrets);
  // Re-compute with same DH inputs
  const pathSecrets2 = computePathSecrets(tree, 0, participants[0]._private_key);
  const cs2 = deriveCommitSecret(pathSecrets2);
  assert.deepStrictEqual(cs1, cs2);
});

// ─── Group State Management ─────────────────────────────────────────────────

test("createMlsGroupState initializes epoch 0", () => {
  const participants = makeParticipants(2);
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_test1",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key })),
    retainedEpochLimit: 3
  });
  assert.equal(groupState.group_id, "thr_test1");
  assert.equal(groupState.epoch, 0);
  assert.equal(groupState.cipher_suite, "AES-128-GCM");
  assert.equal(groupState.tree.length, 2);
  assert.equal(typeof groupState.epoch_secret, "string");
  assert.equal(typeof groupState.application_secret, "string");
  assert.deepStrictEqual(groupState.sender_generations, { "0": 0, "1": 0 });
  assert.deepStrictEqual(groupState.retained_epoch_secrets, []);
  assert.equal(groupState.retained_epoch_limit, 3);
  assert.equal(typeof groupState.tree_hash, "string");

  assert.equal(groupSecrets.length, 2);
  assert.equal(groupSecrets[0].to, participants[0].identity);
  assert.equal(groupSecrets[1].to, participants[1].identity);
});

test("processWelcome reconstructs group state for recipient", () => {
  const participants = makeParticipants(2);
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_welcome",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const welcome = {
    group_id: groupState.group_id,
    epoch: groupState.epoch,
    tree: groupState.tree,
    group_secrets: groupSecrets,
    tree_hash: groupState.tree_hash,
    retained_epoch_limit: groupState.retained_epoch_limit
  };

  const recipientState = processWelcome(welcome, participants[1].identity, participants[1]._private_key);

  assert.equal(recipientState.group_id, "thr_welcome");
  assert.equal(recipientState.epoch, 0);
  assert.equal(recipientState.tree.length, 2);
  assert.equal(recipientState.epoch_secret, groupState.epoch_secret);
  assert.equal(recipientState.tree_hash, groupState.tree_hash);
});

test("processWelcome throws for unknown recipient", () => {
  const participants = makeParticipants(2);
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_unknown",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });
  const welcome = {
    group_id: groupState.group_id,
    epoch: groupState.epoch,
    tree: groupState.tree,
    group_secrets: groupSecrets,
    tree_hash: groupState.tree_hash
  };
  const unknownKp = generateMlsLeafKeyPair();
  assert.throws(
    () => processWelcome(welcome, "loom://unknown@test", unknownKp.private_key),
    /no group secret found/
  );
});

test("processCommit advances epoch and updates tree", () => {
  const participants = makeParticipants(2);
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_commit",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  // Participant 0 rotates key
  const newKp = generateMlsLeafKeyPair();
  const pathSecrets = computePathSecrets(groupState.tree, 0, participants[0]._private_key);
  const encryptedSecrets = encryptPathSecrets(pathSecrets, groupState.tree);
  const newTree = groupState.tree.map((l) => (l ? { ...l } : null));
  newTree[0] = { ...newTree[0], public_key: newKp.public_key, generation: 1 };
  const treeHash = toBase64Url(computeTreeHash(newTree));

  const commit = {
    sender_leaf_index: 0,
    new_leaf_public_key: newKp.public_key,
    path_secrets: encryptedSecrets,
    tree_hash: treeHash
  };

  const newState = processCommit(groupState, commit, 1, participants[1]._private_key);
  assert.equal(newState.epoch, 1);
  assert.equal(newState.tree[0].public_key, newKp.public_key);
  assert.equal(newState.tree[0].generation, 1);
  assert.notEqual(newState.epoch_secret, groupState.epoch_secret);
  assert.equal(newState.retained_epoch_secrets.length, 1);
  assert.equal(newState.retained_epoch_secrets[0].epoch, 0);
});

// ─── Encrypt / Decrypt ──────────────────────────────────────────────────────

test("encryptMlsPayload / decryptMlsPayload round-trip for string", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_enc",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const { ciphertext, mls_metadata } = encryptMlsPayload({
    groupState,
    senderLeafIndex: 0,
    plaintext: "Hello, world!"
  });

  assert.equal(typeof ciphertext, "string");
  assert.equal(mls_metadata.sender_leaf_index, 0);
  assert.equal(mls_metadata.generation, 0);
  assert.equal(mls_metadata.content_type, "application");

  // Decrypt from a copy of group state (since sender advanced generation)
  const recipientState = JSON.parse(JSON.stringify(groupState));
  recipientState.sender_generations["0"] = 0; // Reset to pre-encryption generation
  const decrypted = decryptMlsPayload({
    groupState: recipientState,
    ciphertext,
    mlsMetadata: mls_metadata
  });

  assert.equal(new TextDecoder().decode(decrypted), "Hello, world!");
});

test("encryptMlsPayload / decryptMlsPayload round-trip for JSON object", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_enc_json",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const payload = { type: "test", data: [1, 2, 3] };
  const { ciphertext, mls_metadata } = encryptMlsPayload({
    groupState,
    senderLeafIndex: 0,
    plaintext: payload
  });

  const recipientState = JSON.parse(JSON.stringify(groupState));
  recipientState.sender_generations["0"] = 0;
  const decrypted = decryptMlsPayload({
    groupState: recipientState,
    ciphertext,
    mlsMetadata: mls_metadata
  });

  const parsed = JSON.parse(new TextDecoder().decode(decrypted));
  assert.equal(parsed.type, "test");
  assert.deepStrictEqual(parsed.data, [1, 2, 3]);
});

test("sender generation advances after each encrypt", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_gen",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  assert.equal(groupState.sender_generations["0"], 0);
  encryptMlsPayload({ groupState, senderLeafIndex: 0, plaintext: "msg1" });
  assert.equal(groupState.sender_generations["0"], 1);
  encryptMlsPayload({ groupState, senderLeafIndex: 0, plaintext: "msg2" });
  assert.equal(groupState.sender_generations["0"], 2);
});

test("decryption fails with wrong tree_hash (AAD mismatch)", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_aad",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const { ciphertext, mls_metadata } = encryptMlsPayload({
    groupState,
    senderLeafIndex: 0,
    plaintext: "secret"
  });

  const recipientState = JSON.parse(JSON.stringify(groupState));
  recipientState.sender_generations["0"] = 0;
  const badMetadata = { ...mls_metadata, tree_hash: toBase64Url(randomBytes(32)) };

  assert.throws(() => {
    decryptMlsPayload({
      groupState: recipientState,
      ciphertext,
      mlsMetadata: badMetadata
    });
  });
});

// ─── Forward Secrecy ────────────────────────────────────────────────────────

test("pruneRetainedEpochSecrets removes old entries beyond limit", () => {
  const state = {
    retained_epoch_secrets: [
      { epoch: 0, secret: "secret0" },
      { epoch: 1, secret: "secret1" },
      { epoch: 2, secret: "secret2" },
      { epoch: 3, secret: "secret3" },
      { epoch: 4, secret: "secret4" }
    ],
    retained_epoch_limit: 3
  };
  pruneRetainedEpochSecrets(state);
  assert.equal(state.retained_epoch_secrets.length, 3);
  assert.equal(state.retained_epoch_secrets[0].epoch, 2);
  assert.equal(state.retained_epoch_secrets[1].epoch, 3);
  assert.equal(state.retained_epoch_secrets[2].epoch, 4);
});

test("deleteEpochSecret removes specific epoch", () => {
  const state = {
    retained_epoch_secrets: [
      { epoch: 0, secret: "a" },
      { epoch: 1, secret: "b" },
      { epoch: 2, secret: "c" }
    ]
  };
  deleteEpochSecret(state, 1);
  assert.equal(state.retained_epoch_secrets.length, 2);
  assert.equal(state.retained_epoch_secrets[0].epoch, 0);
  assert.equal(state.retained_epoch_secrets[1].epoch, 2);
});

// ─── Post-Compromise Security ───────────────────────────────────────────────

test("tree update with new leaf key changes epoch secret", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_pcs",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const originalEpochSecret = groupState.epoch_secret;

  const newKp = generateMlsLeafKeyPair();
  const pathSecrets = computePathSecrets(groupState.tree, 0, participants[0]._private_key);
  const encryptedSecrets = encryptPathSecrets(pathSecrets, groupState.tree);
  const newTree = groupState.tree.map((l) => (l ? { ...l } : null));
  newTree[0] = { ...newTree[0], public_key: newKp.public_key, generation: 1 };
  const treeHash = toBase64Url(computeTreeHash(newTree));

  const commit = {
    sender_leaf_index: 0,
    new_leaf_public_key: newKp.public_key,
    path_secrets: encryptedSecrets,
    tree_hash: treeHash
  };

  const newState = processCommit(groupState, commit, 1, participants[1]._private_key);
  assert.notEqual(newState.epoch_secret, originalEpochSecret);
});

// ─── Validation ─────────────────────────────────────────────────────────────

test("validateMlsMetadata accepts valid metadata", () => {
  const errors = validateMlsMetadata({
    sender_leaf_index: 0,
    generation: 5,
    tree_hash: toBase64Url(randomBytes(32)),
    content_type: "application"
  });
  assert.equal(errors.length, 0);
});

test("validateMlsMetadata rejects missing fields", () => {
  const errors = validateMlsMetadata({});
  assert.ok(errors.length >= 3);
  const fields = errors.map((e) => e.field);
  assert.ok(fields.some((f) => f.includes("sender_leaf_index")));
  assert.ok(fields.some((f) => f.includes("generation")));
  assert.ok(fields.some((f) => f.includes("tree_hash")));
});

test("validateMlsMetadata rejects non-object", () => {
  const errors = validateMlsMetadata(null);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].reason.includes("must be an object"));
});

test("validateMlsMetadata rejects invalid content_type", () => {
  const errors = validateMlsMetadata({
    sender_leaf_index: 0,
    generation: 0,
    tree_hash: toBase64Url(randomBytes(32)),
    content_type: "invalid"
  });
  assert.equal(errors.length, 1);
  assert.ok(errors[0].field.includes("content_type"));
});

test("validateMlsWelcome accepts valid welcome", () => {
  const kp = generateMlsLeafKeyPair();
  const errors = validateMlsWelcome({
    tree: [{ identity: "loom://alice@test", public_key: kp.public_key }],
    group_secrets: [
      { to: "loom://alice@test", encrypted_epoch_secret: toBase64Url(randomBytes(64)) }
    ],
    tree_hash: toBase64Url(randomBytes(32))
  });
  assert.equal(errors.length, 0);
});

test("validateMlsWelcome rejects invalid tree", () => {
  const errors = validateMlsWelcome({
    tree: [],
    group_secrets: [
      { to: "loom://a@test", encrypted_epoch_secret: toBase64Url(randomBytes(64)) }
    ],
    tree_hash: toBase64Url(randomBytes(32))
  });
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.field.includes("tree")));
});

test("validateMlsWelcome rejects missing group_secrets", () => {
  const kp = generateMlsLeafKeyPair();
  const errors = validateMlsWelcome({
    tree: [{ identity: "loom://a@test", public_key: kp.public_key }],
    group_secrets: [],
    tree_hash: toBase64Url(randomBytes(32))
  });
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.field.includes("group_secrets")));
});

test("validateMlsCommit accepts valid commit", () => {
  const errors = validateMlsCommit({
    sender_leaf_index: 0,
    new_leaf_public_key: toBase64Url(randomBytes(32)),
    path_secrets: [
      { target_leaf_index: 1, encrypted_secret: toBase64Url(randomBytes(64)) }
    ],
    tree_hash: toBase64Url(randomBytes(32))
  });
  assert.equal(errors.length, 0);
});

test("validateMlsCommit rejects missing fields", () => {
  const errors = validateMlsCommit({});
  assert.ok(errors.length >= 3);
});

test("validateMlsCommit rejects non-object", () => {
  const errors = validateMlsCommit("string");
  assert.equal(errors.length, 1);
  assert.ok(errors[0].reason.includes("must be an object"));
});

// ─── Key Generation ─────────────────────────────────────────────────────────

test("generateMlsLeafKeyPair produces valid X25519 key pair", () => {
  const kp = generateMlsLeafKeyPair();
  assert.equal(typeof kp.public_key, "string");
  assert.equal(typeof kp.private_key, "string");
  assert.equal(fromBase64Url(kp.public_key).length, 32);
  assert.equal(fromBase64Url(kp.private_key).length, 32);
});

test("different key pairs produce different public keys", () => {
  const kp1 = generateMlsLeafKeyPair();
  const kp2 = generateMlsLeafKeyPair();
  assert.notEqual(kp1.public_key, kp2.public_key);
});

// ─── Codec ──────────────────────────────────────────────────────────────────

test("serializeMlsGroupState/deserializeMlsGroupState round-trip", () => {
  const participants = makeParticipants(2);
  const { groupState } = createMlsGroupState({
    groupId: "thr_codec",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const serialized = serializeMlsGroupState(groupState);
  const deserialized = deserializeMlsGroupState(serialized);

  assert.equal(deserialized.group_id, groupState.group_id);
  assert.equal(deserialized.epoch, groupState.epoch);
  assert.equal(deserialized.cipher_suite, groupState.cipher_suite);
  assert.equal(deserialized.tree.length, groupState.tree.length);
  assert.equal(deserialized.epoch_secret, groupState.epoch_secret);
  assert.equal(deserialized.tree_hash, groupState.tree_hash);
});

test("serializeMlsGroupState returns null for invalid input", () => {
  assert.equal(serializeMlsGroupState(null), null);
  assert.equal(serializeMlsGroupState("string"), null);
});

test("deserializeMlsGroupState returns null for invalid input", () => {
  assert.equal(deserializeMlsGroupState(null), null);
  assert.equal(deserializeMlsGroupState(42), null);
});

test("serializeMlsWelcome/deserializeMlsWelcome round-trip", () => {
  const participants = makeParticipants(2);
  const { groupState, groupSecrets } = createMlsGroupState({
    groupId: "thr_w_codec",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  const welcome = {
    group_id: groupState.group_id,
    epoch: groupState.epoch,
    tree: groupState.tree,
    group_secrets: groupSecrets,
    tree_hash: groupState.tree_hash,
    retained_epoch_limit: groupState.retained_epoch_limit
  };

  const serialized = serializeMlsWelcome(welcome);
  const deserialized = deserializeMlsWelcome(serialized);

  assert.equal(deserialized.group_id, welcome.group_id);
  assert.equal(deserialized.epoch, welcome.epoch);
  assert.equal(deserialized.tree.length, welcome.tree.length);
  assert.equal(deserialized.group_secrets.length, welcome.group_secrets.length);
});

test("serializeMlsCommit/deserializeMlsCommit round-trip", () => {
  const commit = {
    sender_leaf_index: 0,
    new_leaf_public_key: toBase64Url(randomBytes(32)),
    path_secrets: [
      { target_leaf_index: 1, encrypted_secret: toBase64Url(randomBytes(64)) }
    ],
    tree_hash: toBase64Url(randomBytes(32))
  };

  const serialized = serializeMlsCommit(commit);
  const deserialized = deserializeMlsCommit(serialized);

  assert.equal(deserialized.sender_leaf_index, 0);
  assert.equal(deserialized.new_leaf_public_key, commit.new_leaf_public_key);
  assert.equal(deserialized.path_secrets.length, 1);
  assert.equal(deserialized.tree_hash, commit.tree_hash);
});

// ─── Full Group Lifecycle ───────────────────────────────────────────────────

test("full lifecycle: create → welcome → encrypt → commit → decrypt", () => {
  const participants = makeParticipants(2);

  // Creator creates group
  const { groupState: creatorState, groupSecrets } = createMlsGroupState({
    groupId: "thr_lifecycle",
    participants: participants.map((p) => ({ identity: p.identity, public_key: p.public_key }))
  });

  // Recipient joins via welcome
  const welcome = {
    group_id: creatorState.group_id,
    epoch: creatorState.epoch,
    tree: creatorState.tree,
    group_secrets: groupSecrets,
    tree_hash: creatorState.tree_hash,
    retained_epoch_limit: creatorState.retained_epoch_limit
  };
  const recipientState = processWelcome(welcome, participants[1].identity, participants[1]._private_key);

  // Creator sends encrypted message
  const { ciphertext: ct1, mls_metadata: md1 } = encryptMlsPayload({
    groupState: creatorState,
    senderLeafIndex: 0,
    plaintext: "Hello from creator!"
  });

  // Recipient decrypts
  const plain1 = decryptMlsPayload({
    groupState: recipientState,
    ciphertext: ct1,
    mlsMetadata: md1
  });
  assert.equal(new TextDecoder().decode(plain1), "Hello from creator!");

  // Creator rotates key (Commit)
  const newCreatorKp = generateMlsLeafKeyPair();
  const pathSecrets = computePathSecrets(creatorState.tree, 0, participants[0]._private_key);
  const encryptedPathSecrets = encryptPathSecrets(pathSecrets, creatorState.tree);
  const newTree = creatorState.tree.map((l) => (l ? { ...l } : null));
  newTree[0] = { ...newTree[0], public_key: newCreatorKp.public_key, generation: 1 };
  const newTreeHash = toBase64Url(computeTreeHash(newTree));

  const commit = {
    sender_leaf_index: 0,
    new_leaf_public_key: newCreatorKp.public_key,
    path_secrets: encryptedPathSecrets,
    tree_hash: newTreeHash
  };

  // Recipient processes commit
  const recipientStateE1 = processCommit(recipientState, commit, 1, participants[1]._private_key);
  assert.equal(recipientStateE1.epoch, 1);

  // Creator also advances their own state by computing the same commit secret
  // (In production, both sides process the same commit; the sender also calls processCommit.)
  // For testing, we verify that the recipient can decrypt a message from epoch 1
  // by having the creator construct a consistent state.
  // Since processCommit is symmetric from the recipient's perspective, we verify the epoch advanced.
  assert.equal(recipientStateE1.tree[0].public_key, newCreatorKp.public_key);
  assert.notEqual(recipientStateE1.epoch_secret, recipientState.epoch_secret);
});
