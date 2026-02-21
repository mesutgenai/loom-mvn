// ─── MLS (RFC 9420 Subset) — Key Schedule, Ratchet Tree, Encrypt/Decrypt ────
// LOOM-specific MLS integration layer providing forward secrecy and
// post-compromise security via a simplified TreeKEM-inspired ratchet tree,
// HKDF-SHA-256 key schedule, and AES-128-GCM encryption.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes
} from "node:crypto";

import { gcm } from "@noble/ciphers/aes.js";

import { canonicalizeJson } from "./canonical.js";
import { fromBase64Url, toBase64Url } from "./crypto.js";
import { isIdentity } from "./ids.js";

// ─── Constants ──────────────────────────────────────────────────────────────

export const MLS_AES_KEY_BYTES = 16;
export const MLS_GCM_NONCE_BYTES = 12;
export const MLS_GCM_TAG_BYTES = 16;
export const MLS_SECRET_BYTES = 32;
export const MLS_X25519_KEY_BYTES = 32;
export const MLS_MAX_TREE_SIZE = 256;
export const MLS_DEFAULT_RETAINED_EPOCHS = 3;
export const MLS_PROFILE_ID = "loom-e2ee-mls-1";

const TEXT_ENCODER = new TextEncoder();
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const LABEL_SALT = createHash("sha256").update("loom.mls.v1", "utf-8").digest();

// ─── Key Schedule ───────────────────────────────────────────────────────────

export function mlsExpandLabel(secret, label, context, length) {
  const info = `loom.mls.${label}|${context}`;
  return new Uint8Array(Buffer.from(hkdfSync("sha256", secret, LABEL_SALT, info, length)));
}

export function deriveInitialEpochSecret(initialGroupKey, groupId) {
  return mlsExpandLabel(initialGroupKey, "epoch_secret", `${groupId}|0`, MLS_SECRET_BYTES);
}

export function deriveEpochSecret(previousSecret, commitSecret, groupId, epoch) {
  const extracted = new Uint8Array(
    Buffer.from(hkdfSync("sha256", commitSecret, previousSecret, "", MLS_SECRET_BYTES))
  );
  return mlsExpandLabel(extracted, "epoch_secret", `${groupId}|${epoch}`, MLS_SECRET_BYTES);
}

export function deriveApplicationSecret(epochSecret, groupId, epoch) {
  return mlsExpandLabel(epochSecret, "app_secret", `${groupId}|${epoch}`, MLS_SECRET_BYTES);
}

export function deriveSenderSecret(applicationSecret, senderLeafIndex, generation) {
  return mlsExpandLabel(applicationSecret, "sender", `${senderLeafIndex}|${generation}`, MLS_SECRET_BYTES);
}

export function deriveMessageKeyAndNonce(senderSecret) {
  const key = mlsExpandLabel(senderSecret, "key", "", MLS_AES_KEY_BYTES);
  const nonce = mlsExpandLabel(senderSecret, "nonce", "", MLS_GCM_NONCE_BYTES);
  return { key, nonce };
}

// ─── Tree Operations ────────────────────────────────────────────────────────

export function createRatchetTree(participants) {
  if (!Array.isArray(participants) || participants.length === 0) {
    throw new Error("participants must be a non-empty array");
  }
  if (participants.length > MLS_MAX_TREE_SIZE) {
    throw new Error(`participants exceed maximum tree size (${MLS_MAX_TREE_SIZE})`);
  }
  return participants.map((p) => ({
    identity: p.identity,
    public_key: p.public_key,
    generation: 0
  }));
}

export function computeTreeHash(tree) {
  const serialized = canonicalizeJson(
    tree.map((leaf) =>
      leaf
        ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation }
        : null
    )
  );
  return new Uint8Array(createHash("sha256").update(serialized, "utf-8").digest());
}

export function getLeafIndex(tree, identity) {
  for (let i = 0; i < tree.length; i++) {
    if (tree[i] && tree[i].identity === identity) {
      return i;
    }
  }
  return -1;
}

export function addLeafToTree(tree, identity, publicKey) {
  if (tree.length >= MLS_MAX_TREE_SIZE) {
    throw new Error(`tree is full (max ${MLS_MAX_TREE_SIZE})`);
  }
  // Fill first empty slot
  for (let i = 0; i < tree.length; i++) {
    if (tree[i] === null) {
      tree[i] = { identity, public_key: publicKey, generation: 0 };
      return i;
    }
  }
  // Append
  tree.push({ identity, public_key: publicKey, generation: 0 });
  return tree.length - 1;
}

export function removeLeafFromTree(tree, identity) {
  const index = getLeafIndex(tree, identity);
  if (index < 0) {
    return -1;
  }
  tree[index] = null;
  return index;
}

export function updateLeafKey(tree, leafIndex, newPublicKey, newGeneration) {
  if (leafIndex < 0 || leafIndex >= tree.length || !tree[leafIndex]) {
    throw new Error(`invalid leaf index: ${leafIndex}`);
  }
  tree[leafIndex].public_key = newPublicKey;
  tree[leafIndex].generation = newGeneration;
}

// ─── Simplified TreeKEM Path Secret Computation ─────────────────────────────
// Binary tree layout: N leaves at indices 0..N-1.
// For the simplified version we compute pairwise DH between the updating
// leaf and each other non-null leaf. This gives O(N) work per Commit
// (vs O(log N) for full TreeKEM) but is much simpler to implement correctly.
// Each path secret is encrypted to the co-path participant's X25519 public key.

function resolveX25519PublicKeyFromBase64(publicKeyBase64Url) {
  const raw = fromBase64Url(publicKeyBase64Url);
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b656e032100", "hex"), // X25519 SPKI prefix
      raw
    ]),
    format: "der",
    type: "spki"
  });
}

function resolveX25519PrivateKeyFromBase64(privateKeyBase64Url) {
  const raw = fromBase64Url(privateKeyBase64Url);
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"), // X25519 PKCS8 prefix
      raw
    ]),
    format: "der",
    type: "pkcs8"
  });
}

function performDH(privateKeyBase64Url, recipientPublicKeyBase64Url) {
  const privKey = resolveX25519PrivateKeyFromBase64(privateKeyBase64Url);
  const pubKey = resolveX25519PublicKeyFromBase64(recipientPublicKeyBase64Url);
  return new Uint8Array(diffieHellman({ privateKey: privKey, publicKey: pubKey }));
}

function encryptWithX25519(plaintext, recipientPublicKeyBase64Url) {
  // Generate ephemeral X25519 key pair
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublicRaw = new Uint8Array(
    ephemeral.publicKey.export({ type: "spki", format: "der" }).subarray(12)
  );
  const ephemeralPrivateRaw = new Uint8Array(
    ephemeral.privateKey.export({ type: "pkcs8", format: "der" }).subarray(16)
  );

  const recipientPublic = resolveX25519PublicKeyFromBase64(recipientPublicKeyBase64Url);
  const sharedSecret = new Uint8Array(
    diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPublic })
  );

  // Derive encryption key from shared secret
  const encKey = new Uint8Array(
    Buffer.from(hkdfSync("sha256", sharedSecret, LABEL_SALT, "loom.mls.path_encrypt", MLS_AES_KEY_BYTES))
  );
  const nonce = randomBytes(MLS_GCM_NONCE_BYTES);

  const ciphertext = gcm(encKey, new Uint8Array(nonce)).encrypt(plaintext);

  // Zero out ephemeral private key
  ephemeralPrivateRaw.fill(0);
  encKey.fill(0);

  // Package: ephemeral_public(32) + nonce(12) + ciphertext(variable)
  const result = new Uint8Array(MLS_X25519_KEY_BYTES + MLS_GCM_NONCE_BYTES + ciphertext.length);
  result.set(ephemeralPublicRaw, 0);
  result.set(nonce, MLS_X25519_KEY_BYTES);
  result.set(ciphertext, MLS_X25519_KEY_BYTES + MLS_GCM_NONCE_BYTES);
  return result;
}

function decryptWithX25519(packageBytes, recipientPrivateKeyBase64Url) {
  if (packageBytes.length < MLS_X25519_KEY_BYTES + MLS_GCM_NONCE_BYTES + MLS_GCM_TAG_BYTES) {
    throw new Error("encrypted package too short");
  }

  const ephemeralPublicRaw = packageBytes.subarray(0, MLS_X25519_KEY_BYTES);
  const nonce = packageBytes.subarray(MLS_X25519_KEY_BYTES, MLS_X25519_KEY_BYTES + MLS_GCM_NONCE_BYTES);
  const ciphertext = packageBytes.subarray(MLS_X25519_KEY_BYTES + MLS_GCM_NONCE_BYTES);

  const ephemeralPublicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b656e032100", "hex"),
      ephemeralPublicRaw
    ]),
    format: "der",
    type: "spki"
  });

  const recipientPrivateKey = resolveX25519PrivateKeyFromBase64(recipientPrivateKeyBase64Url);
  const sharedSecret = new Uint8Array(
    diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublicKey })
  );

  const decKey = new Uint8Array(
    Buffer.from(hkdfSync("sha256", sharedSecret, LABEL_SALT, "loom.mls.path_encrypt", MLS_AES_KEY_BYTES))
  );

  const plaintext = gcm(decKey, new Uint8Array(nonce)).decrypt(ciphertext);
  decKey.fill(0);
  return plaintext;
}

export function computePathSecrets(tree, senderLeafIndex, senderPrivateKeyBase64Url) {
  const pathSecrets = [];
  for (let i = 0; i < tree.length; i++) {
    if (i === senderLeafIndex || !tree[i]) continue;
    const dhSecret = performDH(senderPrivateKeyBase64Url, tree[i].public_key);
    pathSecrets.push({
      target_leaf_index: i,
      secret: dhSecret
    });
  }
  return pathSecrets;
}

export function encryptPathSecrets(pathSecrets, tree) {
  return pathSecrets.map((ps) => {
    const leaf = tree[ps.target_leaf_index];
    const encrypted = encryptWithX25519(ps.secret, leaf.public_key);
    return {
      target_leaf_index: ps.target_leaf_index,
      encrypted_secret: toBase64Url(encrypted)
    };
  });
}

export function decryptPathSecret(encryptedSecretBase64Url, recipientPrivateKeyBase64Url) {
  const packageBytes = fromBase64Url(encryptedSecretBase64Url);
  return decryptWithX25519(packageBytes, recipientPrivateKeyBase64Url);
}

export function deriveCommitSecret(pathSecrets) {
  if (pathSecrets.length === 0) {
    return new Uint8Array(randomBytes(MLS_SECRET_BYTES));
  }
  // Combine all pairwise DH secrets into a single commit secret
  const combined = createHash("sha256");
  for (const ps of pathSecrets) {
    combined.update(ps.secret);
  }
  const hash = new Uint8Array(combined.digest());
  return mlsExpandLabel(hash, "commit", "", MLS_SECRET_BYTES);
}

// ─── Group State Management ─────────────────────────────────────────────────

export function createMlsGroupState({ groupId, participants, retainedEpochLimit }) {
  if (!Array.isArray(participants) || participants.length === 0) {
    throw new Error("participants must be a non-empty array");
  }

  const tree = createRatchetTree(participants);
  const initialGroupKey = new Uint8Array(randomBytes(MLS_SECRET_BYTES));
  const epochSecret = deriveInitialEpochSecret(initialGroupKey, groupId);
  const applicationSecret = deriveApplicationSecret(epochSecret, groupId, 0);
  const treeHash = computeTreeHash(tree);

  const senderGenerations = {};
  for (let i = 0; i < tree.length; i++) {
    senderGenerations[String(i)] = 0;
  }

  const groupState = {
    group_id: groupId,
    epoch: 0,
    cipher_suite: "AES-128-GCM",
    tree,
    epoch_secret: toBase64Url(epochSecret),
    application_secret: toBase64Url(applicationSecret),
    sender_generations: senderGenerations,
    retained_epoch_secrets: [],
    retained_epoch_limit: retainedEpochLimit || MLS_DEFAULT_RETAINED_EPOCHS,
    tree_hash: toBase64Url(treeHash)
  };

  // Encrypt initial epoch secret to each participant's public key
  const groupSecrets = participants.map((p, i) => {
    const encrypted = encryptWithX25519(epochSecret, p.public_key);
    return {
      to: p.identity,
      encrypted_epoch_secret: toBase64Url(encrypted)
    };
  });

  // Zero ephemeral material
  initialGroupKey.fill(0);

  return { groupState, groupSecrets };
}

export function processWelcome(welcome, recipientIdentity, recipientPrivateKeyBase64Url) {
  const entry = welcome.group_secrets.find((gs) => gs.to === recipientIdentity);
  if (!entry) {
    throw new Error(`no group secret found for recipient ${recipientIdentity}`);
  }

  const epochSecret = decryptWithX25519(
    fromBase64Url(entry.encrypted_epoch_secret),
    recipientPrivateKeyBase64Url
  );

  const tree = welcome.tree.map((leaf) =>
    leaf ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation || 0 } : null
  );

  const groupId = welcome.group_id;
  const epoch = welcome.epoch || 0;
  const applicationSecret = deriveApplicationSecret(epochSecret, groupId, epoch);
  const treeHash = computeTreeHash(tree);

  const senderGenerations = {};
  for (let i = 0; i < tree.length; i++) {
    if (tree[i]) {
      senderGenerations[String(i)] = 0;
    }
  }

  return {
    group_id: groupId,
    epoch,
    cipher_suite: "AES-128-GCM",
    tree,
    epoch_secret: toBase64Url(epochSecret),
    application_secret: toBase64Url(applicationSecret),
    sender_generations: senderGenerations,
    retained_epoch_secrets: [],
    retained_epoch_limit: welcome.retained_epoch_limit || MLS_DEFAULT_RETAINED_EPOCHS,
    tree_hash: toBase64Url(treeHash)
  };
}

export function processCommit(groupState, commit, recipientLeafIndex, recipientPrivateKeyBase64Url) {
  const senderIndex = commit.sender_leaf_index;

  // Update tree with sender's new leaf key
  const newTree = groupState.tree.map((leaf) =>
    leaf ? { ...leaf } : null
  );

  if (senderIndex >= 0 && senderIndex < newTree.length && newTree[senderIndex]) {
    newTree[senderIndex] = {
      ...newTree[senderIndex],
      public_key: commit.new_leaf_public_key,
      generation: (newTree[senderIndex].generation || 0) + 1
    };
  }

  // Find the path secret encrypted for this recipient
  const myPathSecret = commit.path_secrets.find(
    (ps) => ps.target_leaf_index === recipientLeafIndex
  );
  if (!myPathSecret) {
    throw new Error(`no path secret found for leaf index ${recipientLeafIndex}`);
  }

  // Decrypt the DH shared secret
  const dhSecret = decryptWithX25519(
    fromBase64Url(myPathSecret.encrypted_secret),
    recipientPrivateKeyBase64Url
  );

  // Derive commit secret from the DH shared secret
  const commitSecretInput = createHash("sha256").update(dhSecret).digest();
  const commitSecret = mlsExpandLabel(new Uint8Array(commitSecretInput), "commit", "", MLS_SECRET_BYTES);

  // Derive new epoch secret
  const previousEpochSecret = fromBase64Url(groupState.epoch_secret);
  const newEpoch = groupState.epoch + 1;
  const newEpochSecret = deriveEpochSecret(previousEpochSecret, commitSecret, groupState.group_id, newEpoch);
  const newApplicationSecret = deriveApplicationSecret(newEpochSecret, groupState.group_id, newEpoch);
  const newTreeHash = computeTreeHash(newTree);

  // Retain old epoch secret
  const retained = [...groupState.retained_epoch_secrets];
  retained.push({
    epoch: groupState.epoch,
    secret: groupState.epoch_secret
  });

  // Reset sender generations for new epoch
  const senderGenerations = {};
  for (let i = 0; i < newTree.length; i++) {
    if (newTree[i]) {
      senderGenerations[String(i)] = 0;
    }
  }

  // Zero intermediate material
  dhSecret.fill(0);
  commitSecret.fill(0);

  const newState = {
    group_id: groupState.group_id,
    epoch: newEpoch,
    cipher_suite: "AES-128-GCM",
    tree: newTree,
    epoch_secret: toBase64Url(newEpochSecret),
    application_secret: toBase64Url(newApplicationSecret),
    sender_generations: senderGenerations,
    retained_epoch_secrets: retained,
    retained_epoch_limit: groupState.retained_epoch_limit,
    tree_hash: toBase64Url(newTreeHash)
  };

  pruneRetainedEpochSecrets(newState);
  return newState;
}

// ─── Encrypt / Decrypt ──────────────────────────────────────────────────────

export function encryptMlsPayload({ groupState, senderLeafIndex, plaintext }) {
  const generation = groupState.sender_generations[String(senderLeafIndex)] || 0;

  const appSecret = fromBase64Url(groupState.application_secret);
  const senderSecret = deriveSenderSecret(appSecret, senderLeafIndex, generation);
  const { key, nonce } = deriveMessageKeyAndNonce(senderSecret);

  const treeHashStr = groupState.tree_hash;
  const aad = TEXT_ENCODER.encode(canonicalizeJson({
    type: "loom.e2ee.payload@v1",
    profile: MLS_PROFILE_ID,
    epoch: groupState.epoch,
    sender_leaf_index: senderLeafIndex,
    generation,
    tree_hash: treeHashStr
  }));

  const plaintextBytes = typeof plaintext === "string"
    ? TEXT_ENCODER.encode(plaintext)
    : plaintext instanceof Uint8Array
      ? plaintext
      : TEXT_ENCODER.encode(canonicalizeJson(plaintext));

  const ciphertextBytes = gcm(key, nonce, aad).encrypt(plaintextBytes);

  // Forward secrecy: zero out derived secrets
  senderSecret.fill(0);
  key.fill(0);
  nonce.fill(0);

  // Advance sender generation
  groupState.sender_generations[String(senderLeafIndex)] = generation + 1;

  return {
    ciphertext: toBase64Url(ciphertextBytes),
    mls_metadata: {
      sender_leaf_index: senderLeafIndex,
      generation,
      tree_hash: treeHashStr,
      content_type: "application"
    }
  };
}

export function decryptMlsPayload({ groupState, ciphertext, mlsMetadata }) {
  const { sender_leaf_index, generation, tree_hash } = mlsMetadata;

  // Determine which epoch secret to use
  let appSecretBytes;
  if (groupState.tree_hash === tree_hash) {
    appSecretBytes = fromBase64Url(groupState.application_secret);
  } else {
    // Look in retained epoch secrets
    let found = false;
    for (const retained of groupState.retained_epoch_secrets) {
      const retainedApp = deriveApplicationSecret(
        fromBase64Url(retained.secret),
        groupState.group_id,
        retained.epoch
      );
      // Try to derive and decrypt with this epoch's secret
      appSecretBytes = retainedApp;
      found = true;
      break;
    }
    if (!found) {
      appSecretBytes = fromBase64Url(groupState.application_secret);
    }
  }

  const senderSecret = deriveSenderSecret(appSecretBytes, sender_leaf_index, generation);
  const { key, nonce } = deriveMessageKeyAndNonce(senderSecret);

  const aad = TEXT_ENCODER.encode(canonicalizeJson({
    type: "loom.e2ee.payload@v1",
    profile: MLS_PROFILE_ID,
    epoch: groupState.epoch,
    sender_leaf_index,
    generation,
    tree_hash
  }));

  const ciphertextBytes = fromBase64Url(ciphertext);
  const plaintext = gcm(key, nonce, aad).decrypt(ciphertextBytes);

  // Forward secrecy: zero out derived secrets
  senderSecret.fill(0);
  key.fill(0);
  nonce.fill(0);

  return plaintext;
}

// ─── Forward Secrecy Maintenance ────────────────────────────────────────────

export function pruneRetainedEpochSecrets(groupState) {
  while (groupState.retained_epoch_secrets.length > groupState.retained_epoch_limit) {
    const removed = groupState.retained_epoch_secrets.shift();
    // The secret string in removed.secret cannot be zeroed (it's a base64 string),
    // but we remove the reference so it can be garbage-collected.
    if (removed) {
      removed.secret = null;
    }
  }
}

export function deleteEpochSecret(groupState, epoch) {
  groupState.retained_epoch_secrets = groupState.retained_epoch_secrets.filter(
    (entry) => entry.epoch !== epoch
  );
}

// ─── Validation ─────────────────────────────────────────────────────────────

function isBase64UrlValue(value) {
  return typeof value === "string" && value.length > 0 && BASE64URL_PATTERN.test(value);
}

export function validateMlsMetadata(mlsMetadata) {
  const errors = [];

  if (!mlsMetadata || typeof mlsMetadata !== "object" || Array.isArray(mlsMetadata)) {
    errors.push({ field: "content.mls_metadata", reason: "must be an object" });
    return errors;
  }

  if (
    typeof mlsMetadata.sender_leaf_index !== "number" ||
    !Number.isInteger(mlsMetadata.sender_leaf_index) ||
    mlsMetadata.sender_leaf_index < 0
  ) {
    errors.push({
      field: "content.mls_metadata.sender_leaf_index",
      reason: "must be a non-negative integer"
    });
  }

  if (
    typeof mlsMetadata.generation !== "number" ||
    !Number.isInteger(mlsMetadata.generation) ||
    mlsMetadata.generation < 0
  ) {
    errors.push({
      field: "content.mls_metadata.generation",
      reason: "must be a non-negative integer"
    });
  }

  if (!isBase64UrlValue(mlsMetadata.tree_hash)) {
    errors.push({
      field: "content.mls_metadata.tree_hash",
      reason: "must be a non-empty base64url string"
    });
  }

  if (mlsMetadata.content_type !== "application" && mlsMetadata.content_type !== "handshake") {
    errors.push({
      field: "content.mls_metadata.content_type",
      reason: "must be 'application' or 'handshake'"
    });
  }

  return errors;
}

export function validateMlsWelcome(welcome) {
  const errors = [];

  if (!welcome || typeof welcome !== "object" || Array.isArray(welcome)) {
    errors.push({ field: "mls_welcome", reason: "must be an object" });
    return errors;
  }

  if (!Array.isArray(welcome.tree) || welcome.tree.length === 0) {
    errors.push({ field: "mls_welcome.tree", reason: "must be a non-empty array of leaf nodes" });
  } else {
    if (welcome.tree.length > MLS_MAX_TREE_SIZE) {
      errors.push({ field: "mls_welcome.tree", reason: `must not exceed ${MLS_MAX_TREE_SIZE} leaves` });
    }
    for (let i = 0; i < welcome.tree.length; i++) {
      const leaf = welcome.tree[i];
      if (leaf === null) continue;
      if (!leaf || typeof leaf !== "object") {
        errors.push({ field: `mls_welcome.tree[${i}]`, reason: "must be an object or null" });
        continue;
      }
      if (!leaf.identity || !isIdentity(leaf.identity)) {
        errors.push({ field: `mls_welcome.tree[${i}].identity`, reason: "must be a valid loom:// identity" });
      }
      if (!isBase64UrlValue(leaf.public_key)) {
        errors.push({ field: `mls_welcome.tree[${i}].public_key`, reason: "must be a non-empty base64url string" });
      }
    }
  }

  if (!Array.isArray(welcome.group_secrets) || welcome.group_secrets.length === 0) {
    errors.push({ field: "mls_welcome.group_secrets", reason: "must be a non-empty array" });
  } else {
    for (let i = 0; i < welcome.group_secrets.length; i++) {
      const gs = welcome.group_secrets[i];
      if (!gs || typeof gs !== "object") {
        errors.push({ field: `mls_welcome.group_secrets[${i}]`, reason: "must be an object" });
        continue;
      }
      if (!gs.to || !isIdentity(gs.to)) {
        errors.push({ field: `mls_welcome.group_secrets[${i}].to`, reason: "must be a valid identity" });
      }
      if (!isBase64UrlValue(gs.encrypted_epoch_secret)) {
        errors.push({
          field: `mls_welcome.group_secrets[${i}].encrypted_epoch_secret`,
          reason: "must be a non-empty base64url string"
        });
      }
    }
  }

  if (!isBase64UrlValue(welcome.tree_hash)) {
    errors.push({ field: "mls_welcome.tree_hash", reason: "must be a non-empty base64url string" });
  }

  return errors;
}

export function validateMlsCommit(commit) {
  const errors = [];

  if (!commit || typeof commit !== "object" || Array.isArray(commit)) {
    errors.push({ field: "mls_commit", reason: "must be an object" });
    return errors;
  }

  if (
    typeof commit.sender_leaf_index !== "number" ||
    !Number.isInteger(commit.sender_leaf_index) ||
    commit.sender_leaf_index < 0
  ) {
    errors.push({
      field: "mls_commit.sender_leaf_index",
      reason: "must be a non-negative integer"
    });
  }

  if (!isBase64UrlValue(commit.new_leaf_public_key)) {
    errors.push({
      field: "mls_commit.new_leaf_public_key",
      reason: "must be a non-empty base64url string"
    });
  }

  if (!Array.isArray(commit.path_secrets) || commit.path_secrets.length === 0) {
    errors.push({ field: "mls_commit.path_secrets", reason: "must be a non-empty array" });
  } else {
    for (let i = 0; i < commit.path_secrets.length; i++) {
      const ps = commit.path_secrets[i];
      if (!ps || typeof ps !== "object") {
        errors.push({ field: `mls_commit.path_secrets[${i}]`, reason: "must be an object" });
        continue;
      }
      if (
        typeof ps.target_leaf_index !== "number" ||
        !Number.isInteger(ps.target_leaf_index) ||
        ps.target_leaf_index < 0
      ) {
        errors.push({
          field: `mls_commit.path_secrets[${i}].target_leaf_index`,
          reason: "must be a non-negative integer"
        });
      }
      if (!isBase64UrlValue(ps.encrypted_secret)) {
        errors.push({
          field: `mls_commit.path_secrets[${i}].encrypted_secret`,
          reason: "must be a non-empty base64url string"
        });
      }
    }
  }

  if (!isBase64UrlValue(commit.tree_hash)) {
    errors.push({ field: "mls_commit.tree_hash", reason: "must be a non-empty base64url string" });
  }

  return errors;
}

// ─── Key Generation ─────────────────────────────────────────────────────────

export function generateMlsLeafKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const publicRaw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  const privateRaw = privateKey.export({ type: "pkcs8", format: "der" }).subarray(16);
  return {
    public_key: toBase64Url(publicRaw),
    private_key: toBase64Url(privateRaw)
  };
}
