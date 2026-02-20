import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes
} from "node:crypto";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import { canonicalizeJson } from "./canonical.js";
import { fromBase64Url, toBase64Url } from "./crypto.js";
import { isIdentity } from "./ids.js";

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const WRAPPED_KEY_ID_PATTERN = /^k_enc_[A-Za-z0-9][A-Za-z0-9._:-]{1,126}$/;
const ENCRYPTION_RECIPIENT_KEY_ID_PATTERN = /^k_enc_[A-Za-z0-9][A-Za-z0-9._:-]{1,126}$/;
const TEXT_ENCODER = new TextEncoder();

const E2EE_PAYLOAD_CIPHERTEXT_VERSION = 1;
const E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION = 1;
const E2EE_PAYLOAD_AAD_TYPE = "loom.e2ee.payload@v1";
const E2EE_ATTACHMENT_AAD_TYPE = "loom.e2ee.attachment@v1";
const E2EE_WRAPPED_KEY_AAD_TYPE = "loom.e2ee.wrapped_key@v1";
const E2EE_PROFILE_COMMITMENT_TYPE = "loom.e2ee.profile_commitment@v1";
const X25519_KEY_BYTES = 32;
const XCHACHA20_NONCE_BYTES = 24;
const XCHACHA20_TAG_BYTES = 16;
const CONTENT_ENCRYPTION_KEY_BYTES = 32;
const PAYLOAD_CIPHERTEXT_MIN_BYTES = 1 + XCHACHA20_NONCE_BYTES + XCHACHA20_TAG_BYTES;
const WRAPPED_KEY_CIPHERTEXT_MIN_BYTES =
  1 + X25519_KEY_BYTES + XCHACHA20_NONCE_BYTES + CONTENT_ENCRYPTION_KEY_BYTES + XCHACHA20_TAG_BYTES;

const E2EE_PROFILES = [
  {
    id: "loom-e2ee-x25519-xchacha20-v1",
    aliases: ["loom-e2ee-1"],
    key_agreement: "X25519",
    cipher: "XChaCha20-Poly1305",
    kdf: "HKDF-SHA-256",
    wrapped_key_algorithms: ["X25519-HKDF-SHA256"],
    recipient_key_algorithm: "X25519",
    payload_aad_type: E2EE_PAYLOAD_AAD_TYPE,
    attachment_aad_type: E2EE_ATTACHMENT_AAD_TYPE,
    wrapped_key_aad_type: E2EE_WRAPPED_KEY_AAD_TYPE,
    payload_ciphertext_package_version: E2EE_PAYLOAD_CIPHERTEXT_VERSION,
    wrapped_key_ciphertext_package_version: E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION,
    replay_counter_required: true,
    profile_commitment_required: true,
    requires_wrapped_keys: true,
    security_properties: {
      forward_secrecy: false,
      post_compromise_security: false,
      confidentiality: "best_effort",
      description: "Per-epoch key wrapping without FS/PCS. Suitable for stored-message confidentiality."
    }
  },
  {
    id: "loom-e2ee-x25519-xchacha20-v2",
    aliases: ["loom-e2ee-2"],
    key_agreement: "X25519",
    cipher: "XChaCha20-Poly1305",
    kdf: "HKDF-SHA-256",
    wrapped_key_algorithms: ["X25519-HKDF-SHA256"],
    recipient_key_algorithm: "X25519",
    payload_aad_type: E2EE_PAYLOAD_AAD_TYPE,
    attachment_aad_type: E2EE_ATTACHMENT_AAD_TYPE,
    wrapped_key_aad_type: E2EE_WRAPPED_KEY_AAD_TYPE,
    payload_ciphertext_package_version: E2EE_PAYLOAD_CIPHERTEXT_VERSION,
    wrapped_key_ciphertext_package_version: E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION,
    replay_counter_required: true,
    profile_commitment_required: true,
    requires_wrapped_keys: true,
    security_properties: {
      forward_secrecy: false,
      post_compromise_security: false,
      confidentiality: "best_effort",
      description: "Per-epoch key wrapping without FS/PCS. Suitable for stored-message confidentiality."
    }
  },
  {
    id: "loom-e2ee-mls-1",
    aliases: [],
    status: "reserved",
    key_agreement: "MLS-TreeKEM",
    cipher: "AES-128-GCM",
    kdf: "HKDF-SHA-256",
    wrapped_key_algorithms: [],
    recipient_key_algorithm: null,
    payload_aad_type: E2EE_PAYLOAD_AAD_TYPE,
    attachment_aad_type: E2EE_ATTACHMENT_AAD_TYPE,
    wrapped_key_aad_type: null,
    payload_ciphertext_package_version: null,
    wrapped_key_ciphertext_package_version: null,
    replay_counter_required: false,
    profile_commitment_required: false,
    requires_wrapped_keys: false,
    security_properties: {
      forward_secrecy: true,
      post_compromise_security: true,
      confidentiality: "mls_grade",
      description: "MLS (RFC 9420) based profile. Reserved for future implementation."
    }
  }
];

const PROFILE_ALIAS_TO_ID = new Map();
for (const profile of E2EE_PROFILES) {
  PROFILE_ALIAS_TO_ID.set(profile.id, profile.id);
  for (const alias of profile.aliases) {
    PROFILE_ALIAS_TO_ID.set(alias, profile.id);
  }
}

const WRAPPED_KEY_ALGORITHM_ALIAS_TO_ID = new Map([
  ["x25519-hkdf-sha256", "X25519-HKDF-SHA256"],
  ["x25519-hkdf-sha-256", "X25519-HKDF-SHA256"],
  ["x25519+hkdf-sha256", "X25519-HKDF-SHA256"],
  ["x25519+hkdf-sha-256", "X25519-HKDF-SHA256"]
]);

const RECIPIENT_KEY_ALGORITHM_ALIAS_TO_ID = new Map([["x25519", "X25519"]]);

const WRAPPED_KEY_ALGORITHMS_BY_RECIPIENT_KEY = new Map([["X25519", ["X25519-HKDF-SHA256"]]]);

function normalizeProfileId(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  return normalized || null;
}

function normalizeWrappedKeyAlgorithm(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  return WRAPPED_KEY_ALGORITHM_ALIAS_TO_ID.get(normalized) || null;
}

function normalizeRecipientKeyAlgorithm(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  return RECIPIENT_KEY_ALGORITHM_ALIAS_TO_ID.get(normalized) || null;
}

function toNonNegativeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${field} must be a non-negative integer`);
  }
  return parsed;
}

function resolveProfileOrThrow(profileId, field = "profile") {
  const resolved = resolveE2eeProfile(profileId);
  if (!resolved) {
    throw new Error(`${field} must be one of: ${listSupportedE2eeProfiles().join(", ")}`);
  }
  return resolved;
}

function buildProfileCommitmentPayload(profile, epoch) {
  return {
    type: E2EE_PROFILE_COMMITMENT_TYPE,
    profile: profile.id,
    epoch,
    key_agreement: profile.key_agreement,
    cipher: profile.cipher,
    kdf: profile.kdf,
    wrapped_key_algorithms: [...(profile.wrapped_key_algorithms || [])],
    recipient_key_algorithm: profile.recipient_key_algorithm,
    payload_aad_type: profile.payload_aad_type,
    attachment_aad_type: profile.attachment_aad_type,
    wrapped_key_aad_type: profile.wrapped_key_aad_type,
    payload_ciphertext_package_version: profile.payload_ciphertext_package_version,
    wrapped_key_ciphertext_package_version: profile.wrapped_key_ciphertext_package_version,
    replay_counter_required: profile.replay_counter_required === true,
    profile_commitment_required: profile.profile_commitment_required === true
  };
}

export function computeE2eeProfileCommitment(profileId, epoch) {
  const profile = resolveProfileOrThrow(profileId, "profile");
  const normalizedEpoch = toNonNegativeInteger(epoch, "epoch");
  const digest = createHash("sha256")
    .update(canonicalizeJson(buildProfileCommitmentPayload(profile, normalizedEpoch)), "utf-8")
    .digest();
  return toBase64Url(digest);
}

export function isBase64UrlValue(value) {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  return BASE64URL_PATTERN.test(value);
}

function ensureUint8Array(value, field) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${field} must be a Uint8Array or Buffer`);
}

function parseBase64UrlBytes(value, field, expectedLength = null) {
  const normalized = String(value || "").trim();
  if (!isBase64UrlValue(normalized)) {
    throw new Error(`${field} must be base64url`);
  }
  const bytes = fromBase64Url(normalized);
  if (expectedLength != null && bytes.length !== expectedLength) {
    throw new Error(`${field} must decode to ${expectedLength} bytes`);
  }
  return new Uint8Array(bytes);
}

function normalizeFixedLengthBytes(value, field, expectedLength) {
  if (value == null) {
    return null;
  }

  if (typeof value === "string") {
    return parseBase64UrlBytes(value, field, expectedLength);
  }

  const bytes = ensureUint8Array(value, field);
  if (bytes.length !== expectedLength) {
    throw new Error(`${field} must be ${expectedLength} bytes`);
  }
  return bytes;
}

function encodePackage(version, parts = []) {
  const buffers = [Buffer.from([version]), ...parts.map((part) => Buffer.from(part))];
  return toBase64Url(Buffer.concat(buffers));
}

export function parseE2eeCiphertextPackage(ciphertext) {
  const bytes = parseBase64UrlBytes(ciphertext, "content.ciphertext");
  if (bytes.length < PAYLOAD_CIPHERTEXT_MIN_BYTES) {
    throw new Error(
      `content.ciphertext package must be at least ${PAYLOAD_CIPHERTEXT_MIN_BYTES} bytes for v${E2EE_PAYLOAD_CIPHERTEXT_VERSION}`
    );
  }

  const version = bytes[0];
  if (version !== E2EE_PAYLOAD_CIPHERTEXT_VERSION) {
    throw new Error(
      `content.ciphertext version ${version} is unsupported (expected ${E2EE_PAYLOAD_CIPHERTEXT_VERSION})`
    );
  }

  const nonceOffset = 1;
  const ciphertextOffset = nonceOffset + XCHACHA20_NONCE_BYTES;
  return {
    version,
    nonce: bytes.slice(nonceOffset, ciphertextOffset),
    ciphertext: bytes.slice(ciphertextOffset)
  };
}

export function parseWrappedKeyCiphertextPackage(ciphertext) {
  const bytes = parseBase64UrlBytes(ciphertext, "wrapped_key.ciphertext");
  if (bytes.length < WRAPPED_KEY_CIPHERTEXT_MIN_BYTES) {
    throw new Error(
      `wrapped_key.ciphertext package must be at least ${WRAPPED_KEY_CIPHERTEXT_MIN_BYTES} bytes for v${E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION}`
    );
  }

  const version = bytes[0];
  if (version !== E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION) {
    throw new Error(
      `wrapped_key.ciphertext version ${version} is unsupported (expected ${E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION})`
    );
  }

  const ephemeralOffset = 1;
  const nonceOffset = ephemeralOffset + X25519_KEY_BYTES;
  const wrappedCiphertextOffset = nonceOffset + XCHACHA20_NONCE_BYTES;

  return {
    version,
    ephemeral_public_key: bytes.slice(ephemeralOffset, nonceOffset),
    nonce: bytes.slice(nonceOffset, wrappedCiphertextOffset),
    wrapped_key_ciphertext: bytes.slice(wrappedCiphertextOffset)
  };
}

function resolveX25519PublicKeyObject(input, field) {
  if (input && typeof input === "object" && input.type === "public" && typeof input.export === "function") {
    if (input.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 public key`);
    }
    return input;
  }

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new Error(`${field} is required`);
    }
    if (trimmed.includes("BEGIN")) {
      const key = createPublicKey(trimmed);
      if (key.asymmetricKeyType !== "x25519") {
        throw new Error(`${field} must be an X25519 public key`);
      }
      return key;
    }
    const raw = parseBase64UrlBytes(trimmed, field, X25519_KEY_BYTES);
    return createPublicKey({
      key: {
        kty: "OKP",
        crv: "X25519",
        x: toBase64Url(raw)
      },
      format: "jwk"
    });
  }

  if (!input || typeof input !== "object") {
    throw new Error(`${field} is required`);
  }

  const publicKeyPem = String(input.public_key_pem || "").trim();
  if (publicKeyPem) {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 public key`);
    }
    return key;
  }

  const publicKeyRaw = String(input.public_key || "").trim();
  if (publicKeyRaw) {
    return resolveX25519PublicKeyObject(publicKeyRaw, field);
  }

  if (input.jwk && typeof input.jwk === "object") {
    const key = createPublicKey({
      key: input.jwk,
      format: "jwk"
    });
    if (key.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 public key`);
    }
    return key;
  }

  throw new Error(`${field} must include public_key or public_key_pem`);
}

function resolveX25519PrivateKeyObject(input, field) {
  if (input && typeof input === "object" && input.type === "private" && typeof input.export === "function") {
    if (input.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 private key`);
    }
    return input;
  }

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new Error(`${field} is required`);
    }
    if (!trimmed.includes("BEGIN")) {
      throw new Error(`${field} must be PEM unless private_key_jwk or private_key+public_key is provided`);
    }
    const key = createPrivateKey(trimmed);
    if (key.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 private key`);
    }
    return key;
  }

  if (!input || typeof input !== "object") {
    throw new Error(`${field} is required`);
  }

  const privateKeyPem = String(input.private_key_pem || "").trim();
  if (privateKeyPem) {
    return resolveX25519PrivateKeyObject(privateKeyPem, field);
  }

  if (input.private_key_jwk && typeof input.private_key_jwk === "object") {
    const key = createPrivateKey({
      key: input.private_key_jwk,
      format: "jwk"
    });
    if (key.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 private key`);
    }
    return key;
  }

  const privateKeyRaw = String(input.private_key || "").trim();
  const publicKeyRaw = String(input.public_key || "").trim();
  if (privateKeyRaw && publicKeyRaw) {
    const privateBytes = parseBase64UrlBytes(`${privateKeyRaw}`, `${field}.private_key`, X25519_KEY_BYTES);
    const publicBytes = parseBase64UrlBytes(`${publicKeyRaw}`, `${field}.public_key`, X25519_KEY_BYTES);
    const key = createPrivateKey({
      key: {
        kty: "OKP",
        crv: "X25519",
        d: toBase64Url(privateBytes),
        x: toBase64Url(publicBytes)
      },
      format: "jwk"
    });
    if (key.asymmetricKeyType !== "x25519") {
      throw new Error(`${field} must be an X25519 private key`);
    }
    return key;
  }

  throw new Error(
    `${field} must include private_key_pem, private_key_jwk, or private_key + public_key`
  );
}

function exportX25519PublicRawBytes(publicKeyObject, field) {
  if (!publicKeyObject || publicKeyObject.asymmetricKeyType !== "x25519") {
    throw new Error(`${field} must be an X25519 public key`);
  }
  const jwk = publicKeyObject.export({ format: "jwk" });
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "X25519" || !jwk.x) {
    throw new Error(`${field} export failed: expected X25519 JWK with x`);
  }
  const bytes = parseBase64UrlBytes(jwk.x, `${field}.x`, X25519_KEY_BYTES);
  return bytes;
}

function buildPayloadAad({ aadType, profileId, epoch, replayCounter, profileCommitment }) {
  return TEXT_ENCODER.encode(
    canonicalizeJson({
      type: aadType,
      profile: profileId,
      epoch,
      replay_counter: replayCounter,
      profile_commitment: profileCommitment
    })
  );
}

function buildWrappedKeyAad({ profileId, epoch, toIdentity, keyId, algorithm }) {
  return TEXT_ENCODER.encode(
    canonicalizeJson({
      type: E2EE_WRAPPED_KEY_AAD_TYPE,
      profile: profileId,
      epoch,
      to: toIdentity,
      key_id: keyId,
      algorithm
    })
  );
}

function deriveWrappedKeyEncryptionKey(sharedSecret, { profileId, epoch, toIdentity, keyId, algorithm }) {
  const salt = createHash("sha256")
    .update(`loom.e2ee.wrap.salt.v1|${profileId}|${epoch}|${algorithm}`, "utf-8")
    .digest();
  const info = buildWrappedKeyAad({ profileId, epoch, toIdentity, keyId, algorithm });
  return new Uint8Array(Buffer.from(hkdfSync("sha256", sharedSecret, salt, info, CONTENT_ENCRYPTION_KEY_BYTES)));
}

function normalizeRecipientEntry(entry, index, profile) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`recipients[${index}] must be an object`);
  }

  const toIdentity = String(entry.to || "").trim();
  if (!isIdentity(toIdentity)) {
    throw new Error(`recipients[${index}].to must be a loom:// or bridge:// identity`);
  }

  const keyId = String(entry.key_id || "").trim();
  if (!ENCRYPTION_RECIPIENT_KEY_ID_PATTERN.test(keyId)) {
    throw new Error(`recipients[${index}].key_id must match ${ENCRYPTION_RECIPIENT_KEY_ID_PATTERN}`);
  }

  const algorithm =
    normalizeWrappedKeyAlgorithm(entry.algorithm || profile?.wrapped_key_algorithms?.[0]) || null;
  if (!algorithm) {
    throw new Error(`recipients[${index}].algorithm must be one of ${profile.wrapped_key_algorithms.join(", ")}`);
  }

  if (!profile.wrapped_key_algorithms.includes(algorithm)) {
    throw new Error(
      `recipients[${index}].algorithm must be one of profile algorithms: ${profile.wrapped_key_algorithms.join(", ")}`
    );
  }

  const publicKeyObject = resolveX25519PublicKeyObject(entry, `recipients[${index}]`);
  let ephemeralPrivateKeyObject = null;
  if (entry.ephemeral_private_key != null) {
    ephemeralPrivateKeyObject = resolveX25519PrivateKeyObject(
      entry.ephemeral_private_key,
      `recipients[${index}].ephemeral_private_key`
    );
  }
  const wrapNonce = normalizeFixedLengthBytes(
    entry.wrap_nonce,
    `recipients[${index}].wrap_nonce`,
    XCHACHA20_NONCE_BYTES
  );
  return {
    to: toIdentity,
    key_id: keyId,
    algorithm,
    publicKeyObject,
    ephemeralPrivateKeyObject,
    wrapNonce
  };
}

function normalizePlaintextBytes(plaintext) {
  if (typeof plaintext === "string") {
    return TEXT_ENCODER.encode(plaintext);
  }
  if (plaintext instanceof Uint8Array || Buffer.isBuffer(plaintext)) {
    return ensureUint8Array(plaintext, "plaintext");
  }
  if (plaintext && typeof plaintext === "object") {
    return TEXT_ENCODER.encode(canonicalizeJson(plaintext));
  }
  throw new TypeError("plaintext must be a string, Uint8Array, Buffer, or object");
}

function resolveReplayMetadata({ profile, epoch, replayCounter, profileCommitment }) {
  const normalizedReplayCounter =
    replayCounter == null ? 0 : toNonNegativeInteger(replayCounter, "replayCounter");
  const expectedCommitment = computeE2eeProfileCommitment(profile.id, epoch);
  if (profileCommitment == null) {
    return {
      replayCounter: normalizedReplayCounter,
      profileCommitment: expectedCommitment
    };
  }

  const normalizedCommitment = String(profileCommitment).trim();
  if (!isBase64UrlValue(normalizedCommitment)) {
    throw new Error("profileCommitment must be base64url");
  }
  if (normalizedCommitment !== expectedCommitment) {
    throw new Error("profileCommitment does not match profile/epoch commitment");
  }
  return {
    replayCounter: normalizedReplayCounter,
    profileCommitment: normalizedCommitment
  };
}

export function generateE2eeX25519KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });

  return {
    algorithm: "X25519",
    public_key: publicJwk.x,
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    private_key: privateJwk.d,
    private_key_pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    private_key_jwk: {
      kty: "OKP",
      crv: "X25519",
      x: publicJwk.x,
      d: privateJwk.d
    }
  };
}

function encryptE2eeMaterial({
  aadType,
  profile,
  epoch,
  replayCounter = 0,
  profileCommitment = null,
  plaintext,
  recipients,
  contentEncryptionKey = null,
  payloadNonce = null
} = {}) {
  const resolvedProfile = resolveProfileOrThrow(profile, "profile");
  const normalizedEpoch = toNonNegativeInteger(epoch, "epoch");
  const replayMetadata = resolveReplayMetadata({
    profile: resolvedProfile,
    epoch: normalizedEpoch,
    replayCounter,
    profileCommitment
  });

  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("recipients must include at least one recipient key");
  }

  const normalizedRecipients = recipients.map((entry, index) =>
    normalizeRecipientEntry(entry, index, resolvedProfile)
  );
  const seenRecipients = new Set();
  for (const recipient of normalizedRecipients) {
    if (seenRecipients.has(recipient.to)) {
      throw new Error(`Duplicate recipient is not allowed: ${recipient.to}`);
    }
    seenRecipients.add(recipient.to);
  }

  const plaintextBytes = normalizePlaintextBytes(plaintext);
  const cek =
    normalizeFixedLengthBytes(contentEncryptionKey, "contentEncryptionKey", CONTENT_ENCRYPTION_KEY_BYTES) ||
    randomBytes(CONTENT_ENCRYPTION_KEY_BYTES);
  const nonce =
    normalizeFixedLengthBytes(payloadNonce, "payloadNonce", XCHACHA20_NONCE_BYTES) ||
    randomBytes(XCHACHA20_NONCE_BYTES);
  const payloadAad = buildPayloadAad({
    aadType,
    profileId: resolvedProfile.id,
    epoch: normalizedEpoch,
    replayCounter: replayMetadata.replayCounter,
    profileCommitment: replayMetadata.profileCommitment
  });
  const payloadCiphertext = xchacha20poly1305(cek, nonce, payloadAad).encrypt(plaintextBytes);

  const wrappedKeys = normalizedRecipients.map((recipient) => {
    const ephemeralPrivateKey =
      recipient.ephemeralPrivateKeyObject || generateKeyPairSync("x25519").privateKey;
    const ephemeralPublicKey = createPublicKey(ephemeralPrivateKey);
    const sharedSecret = diffieHellman({
      privateKey: ephemeralPrivateKey,
      publicKey: recipient.publicKeyObject
    });

    const wrappingKey = deriveWrappedKeyEncryptionKey(sharedSecret, {
      profileId: resolvedProfile.id,
      epoch: normalizedEpoch,
      toIdentity: recipient.to,
      keyId: recipient.key_id,
      algorithm: recipient.algorithm
    });

    const wrapNonce = recipient.wrapNonce || randomBytes(XCHACHA20_NONCE_BYTES);
    const wrappedKeyCiphertext = xchacha20poly1305(
      wrappingKey,
      wrapNonce,
      buildWrappedKeyAad({
        profileId: resolvedProfile.id,
        epoch: normalizedEpoch,
        toIdentity: recipient.to,
        keyId: recipient.key_id,
        algorithm: recipient.algorithm
      })
    ).encrypt(cek);

    const ephemeralPublicRaw = exportX25519PublicRawBytes(ephemeralPublicKey, "ephemeral_public_key");
    return {
      to: recipient.to,
      algorithm: recipient.algorithm,
      key_id: recipient.key_id,
      ciphertext: encodePackage(E2EE_WRAPPED_KEY_CIPHERTEXT_VERSION, [
        ephemeralPublicRaw,
        wrapNonce,
        wrappedKeyCiphertext
      ])
    };
  });

  return {
    encrypted: true,
    profile: resolvedProfile.id,
    epoch: normalizedEpoch,
    replay_counter: replayMetadata.replayCounter,
    profile_commitment: replayMetadata.profileCommitment,
    ciphertext: encodePackage(E2EE_PAYLOAD_CIPHERTEXT_VERSION, [nonce, payloadCiphertext]),
    wrapped_keys: wrappedKeys
  };
}

export function encryptE2eePayload({
  profile,
  epoch,
  replayCounter = 0,
  profileCommitment = null,
  plaintext,
  recipients,
  contentEncryptionKey = null,
  payloadNonce = null
} = {}) {
  return encryptE2eeMaterial({
    aadType: E2EE_PAYLOAD_AAD_TYPE,
    profile,
    epoch,
    replayCounter,
    profileCommitment,
    plaintext,
    recipients,
    contentEncryptionKey,
    payloadNonce
  });
}

export function encryptE2eeAttachment({
  profile,
  epoch,
  replayCounter = 0,
  profileCommitment = null,
  plaintext,
  recipients,
  contentEncryptionKey = null,
  payloadNonce = null
} = {}) {
  return encryptE2eeMaterial({
    aadType: E2EE_ATTACHMENT_AAD_TYPE,
    profile,
    epoch,
    replayCounter,
    profileCommitment,
    plaintext,
    recipients,
    contentEncryptionKey,
    payloadNonce
  });
}

function resolveWrappedKeyEntry(content, recipientIdentity, recipientKeyId) {
  const wrappedKeys = Array.isArray(content?.wrapped_keys) ? content.wrapped_keys : [];
  const normalizedRecipientIdentity = recipientIdentity == null ? null : String(recipientIdentity).trim();
  const normalizedRecipientKeyId = recipientKeyId == null ? null : String(recipientKeyId).trim();

  let matches = wrappedKeys;
  if (normalizedRecipientIdentity) {
    matches = matches.filter((entry) => String(entry?.to || "").trim() === normalizedRecipientIdentity);
  }
  if (normalizedRecipientKeyId) {
    matches = matches.filter((entry) => String(entry?.key_id || "").trim() === normalizedRecipientKeyId);
  }

  if (matches.length === 0) {
    throw new Error("No wrapped key entry matched recipient identity/key_id");
  }

  if (matches.length > 1) {
    throw new Error("Multiple wrapped key entries matched recipient identity/key_id");
  }

  return matches[0];
}

function decryptE2eeMaterial({
  aadType,
  content,
  recipientIdentity,
  recipientKeyId,
  recipientPrivateKey
} = {}) {
  if (!content || typeof content !== "object") {
    throw new Error("content is required");
  }

  const profile = resolveE2eeProfile(content.profile);
  if (!profile) {
    throw new Error(`content.profile must be one of: ${listSupportedE2eeProfiles().join(", ")}`);
  }

  if (!Number.isInteger(content.epoch) || content.epoch < 0) {
    throw new Error("content.epoch must be a non-negative integer");
  }

  if (!Object.prototype.hasOwnProperty.call(content, "replay_counter")) {
    throw new Error("content.replay_counter is required");
  }
  if (!Object.prototype.hasOwnProperty.call(content, "profile_commitment")) {
    throw new Error("content.profile_commitment is required");
  }
  const replayMetadata = resolveReplayMetadata({
    profile,
    epoch: content.epoch,
    replayCounter: content.replay_counter,
    profileCommitment: content.profile_commitment
  });

  const wrappedKeyEntry = resolveWrappedKeyEntry(content, recipientIdentity, recipientKeyId);
  const wrappedAlgorithm = normalizeWrappedKeyAlgorithm(wrappedKeyEntry.algorithm);
  if (!wrappedAlgorithm || !profile.wrapped_key_algorithms.includes(wrappedAlgorithm)) {
    throw new Error("Wrapped key entry algorithm is invalid for profile");
  }

  const recipientPrivateKeyObject = resolveX25519PrivateKeyObject(
    recipientPrivateKey,
    "recipientPrivateKey"
  );
  const payloadPackage = parseE2eeCiphertextPackage(content.ciphertext);
  const wrappedKeyPackage = parseWrappedKeyCiphertextPackage(wrappedKeyEntry.ciphertext);

  const ephemeralPublicKeyObject = resolveX25519PublicKeyObject(
    toBase64Url(wrappedKeyPackage.ephemeral_public_key),
    "wrapped_key.ephemeral_public_key"
  );
  const sharedSecret = diffieHellman({
    privateKey: recipientPrivateKeyObject,
    publicKey: ephemeralPublicKeyObject
  });
  const wrappingKey = deriveWrappedKeyEncryptionKey(sharedSecret, {
    profileId: profile.id,
    epoch: content.epoch,
    toIdentity: String(wrappedKeyEntry.to || "").trim(),
    keyId: String(wrappedKeyEntry.key_id || "").trim(),
    algorithm: wrappedAlgorithm
  });

  let contentEncryptionKey;
  try {
    contentEncryptionKey = xchacha20poly1305(
      wrappingKey,
      wrappedKeyPackage.nonce,
      buildWrappedKeyAad({
        profileId: profile.id,
        epoch: content.epoch,
        toIdentity: String(wrappedKeyEntry.to || "").trim(),
        keyId: String(wrappedKeyEntry.key_id || "").trim(),
        algorithm: wrappedAlgorithm
      })
    ).decrypt(wrappedKeyPackage.wrapped_key_ciphertext);
  } catch (error) {
    throw new Error(`Unable to unwrap content encryption key: ${error?.message || String(error)}`);
  }

  if (contentEncryptionKey.length !== CONTENT_ENCRYPTION_KEY_BYTES) {
    throw new Error(
      `Wrapped content encryption key length is invalid (expected ${CONTENT_ENCRYPTION_KEY_BYTES} bytes, got ${contentEncryptionKey.length})`
    );
  }

  let plaintext;
  try {
    plaintext = xchacha20poly1305(
      contentEncryptionKey,
      payloadPackage.nonce,
      buildPayloadAad({
        aadType,
        profileId: profile.id,
        epoch: content.epoch,
        replayCounter: replayMetadata.replayCounter,
        profileCommitment: replayMetadata.profileCommitment
      })
    ).decrypt(payloadPackage.ciphertext);
  } catch (error) {
    throw new Error(`Unable to decrypt payload ciphertext: ${error?.message || String(error)}`);
  }

  return {
    profile: profile.id,
    epoch: content.epoch,
    replay_counter: replayMetadata.replayCounter,
    profile_commitment: replayMetadata.profileCommitment,
    wrapped_key: {
      to: String(wrappedKeyEntry.to || "").trim(),
      key_id: String(wrappedKeyEntry.key_id || "").trim(),
      algorithm: wrappedAlgorithm
    },
    plaintext: new Uint8Array(plaintext),
    plaintext_utf8: Buffer.from(plaintext).toString("utf-8")
  };
}

export function decryptE2eePayload({
  content,
  recipientIdentity,
  recipientKeyId,
  recipientPrivateKey
} = {}) {
  return decryptE2eeMaterial({
    aadType: E2EE_PAYLOAD_AAD_TYPE,
    content,
    recipientIdentity,
    recipientKeyId,
    recipientPrivateKey
  });
}

export function decryptE2eeAttachment({
  content,
  recipientIdentity,
  recipientKeyId,
  recipientPrivateKey
} = {}) {
  return decryptE2eeMaterial({
    aadType: E2EE_ATTACHMENT_AAD_TYPE,
    content,
    recipientIdentity,
    recipientKeyId,
    recipientPrivateKey
  });
}

export function decryptE2eePayloadJson(input) {
  const decrypted = decryptE2eePayload(input);
  try {
    return {
      ...decrypted,
      plaintext_json: JSON.parse(decrypted.plaintext_utf8)
    };
  } catch (error) {
    throw new Error(`Decrypted payload is not valid JSON: ${error?.message || String(error)}`);
  }
}

export function resolveE2eeProfile(profileId) {
  const normalized = normalizeProfileId(profileId);
  if (!normalized) {
    return null;
  }

  const canonicalId = PROFILE_ALIAS_TO_ID.get(normalized);
  if (!canonicalId) {
    return null;
  }

  const found = E2EE_PROFILES.find((profile) => profile.id === canonicalId) || null;
  if (found?.status === "reserved") {
    return null;
  }
  return found;
}

export function listAllE2eeProfiles() {
  return E2EE_PROFILES.map((profile) => ({
    id: profile.id,
    status: profile.status || "active",
    security_properties: { ...profile.security_properties }
  }));
}

export function listSupportedE2eeProfiles() {
  return E2EE_PROFILES.filter((profile) => profile.status !== "reserved").map((profile) => profile.id);
}

export function listSupportedE2eeProfileCapabilities() {
  return E2EE_PROFILES.filter((profile) => profile.status !== "reserved").map((profile) => ({
    id: profile.id,
    aliases: [...profile.aliases],
    key_agreement: profile.key_agreement,
    cipher: profile.cipher,
    kdf: profile.kdf,
    wrapped_key_algorithms: [...(profile.wrapped_key_algorithms || [])],
    recipient_key_algorithm: profile.recipient_key_algorithm,
    payload_aad_type: profile.payload_aad_type,
    attachment_aad_type: profile.attachment_aad_type,
    wrapped_key_aad_type: profile.wrapped_key_aad_type,
    payload_ciphertext_package_version: profile.payload_ciphertext_package_version,
    wrapped_key_ciphertext_package_version: profile.wrapped_key_ciphertext_package_version,
    replay_counter_required: profile.replay_counter_required === true,
    profile_commitment_required: profile.profile_commitment_required === true
  }));
}

function validateWrappedKeyEntries({
  wrappedKeys,
  fieldPrefix,
  profile,
  pushError,
  resolveRecipientEncryptionKey = null,
  verifyWrappedKeyPayloadStructure = false
}) {
  if (wrappedKeys == null) {
    return {
      seenRecipients: new Set()
    };
  }

  if (!Array.isArray(wrappedKeys)) {
    pushError(fieldPrefix, "must be an array when present");
    return {
      seenRecipients: new Set()
    };
  }

  const seenWrappedKeyRecipients = new Set();
  for (let idx = 0; idx < wrappedKeys.length; idx += 1) {
    const entry = wrappedKeys[idx];
    const entryFieldPrefix = `${fieldPrefix}[${idx}]`;
    if (!entry || typeof entry !== "object") {
      pushError(entryFieldPrefix, "must be an object");
      continue;
    }

    const toIdentity = String(entry.to || "").trim();
    if (!isIdentity(toIdentity)) {
      pushError(`${entryFieldPrefix}.to`, "must be a loom:// or bridge:// identity");
    } else if (seenWrappedKeyRecipients.has(toIdentity)) {
      pushError(`${entryFieldPrefix}.to`, "duplicate wrapped key recipient is not allowed");
    } else {
      seenWrappedKeyRecipients.add(toIdentity);
    }

    if (!isBase64UrlValue(entry.ciphertext)) {
      pushError(`${entryFieldPrefix}.ciphertext`, "must be base64url");
    } else if (verifyWrappedKeyPayloadStructure === true) {
      try {
        parseWrappedKeyCiphertextPackage(entry.ciphertext);
      } catch (error) {
        pushError(`${entryFieldPrefix}.ciphertext`, error?.message || "invalid wrapped key ciphertext package");
      }
    }

    const algorithm = normalizeWrappedKeyAlgorithm(entry.algorithm);
    if (!algorithm) {
      const allowedAlgorithms = profile?.wrapped_key_algorithms?.length
        ? profile.wrapped_key_algorithms.join(", ")
        : "profile-supported wrapped-key algorithm";
      pushError(`${entryFieldPrefix}.algorithm`, `must be one of: ${allowedAlgorithms}`);
    } else if (profile?.wrapped_key_algorithms && !profile.wrapped_key_algorithms.includes(algorithm)) {
      pushError(
        `${entryFieldPrefix}.algorithm`,
        `must be one of profile algorithms: ${profile.wrapped_key_algorithms.join(", ")}`
      );
    }

    const keyId = String(entry.key_id || "").trim();
    if (!keyId) {
      pushError(`${entryFieldPrefix}.key_id`, "is required for wrapped key routing and recipient key binding");
    } else if (!WRAPPED_KEY_ID_PATTERN.test(keyId)) {
      pushError(
        `${entryFieldPrefix}.key_id`,
        "must match /^k_enc_[A-Za-z0-9][A-Za-z0-9._:-]{1,126}$/"
      );
    }

    if (
      resolveRecipientEncryptionKey &&
      keyId &&
      toIdentity &&
      toIdentity.startsWith("loom://")
    ) {
      const recipientEncryptionKey = resolveRecipientEncryptionKey(toIdentity, keyId, {
        profile,
        wrapped_key_algorithm: algorithm
      });
      if (!recipientEncryptionKey) {
        pushError(
          `${entryFieldPrefix}.key_id`,
          "must reference an active recipient encryption key published by target identity"
        );
        continue;
      }

      const recipientKeyAlgorithm = normalizeRecipientKeyAlgorithm(recipientEncryptionKey.algorithm);
      if (!recipientKeyAlgorithm) {
        pushError(
          `${entryFieldPrefix}.key_id`,
          "recipient encryption key algorithm is unsupported by this node"
        );
        continue;
      }

      if (profile?.recipient_key_algorithm && recipientKeyAlgorithm !== profile.recipient_key_algorithm) {
        pushError(
          `${entryFieldPrefix}.key_id`,
          `recipient key algorithm must be ${profile.recipient_key_algorithm} for profile ${profile.id}`
        );
      }

      const algorithmFamily = WRAPPED_KEY_ALGORITHMS_BY_RECIPIENT_KEY.get(recipientKeyAlgorithm) || [];
      if (algorithm && algorithmFamily.length > 0 && !algorithmFamily.includes(algorithm)) {
        pushError(
          `${entryFieldPrefix}.algorithm`,
          `must be one of ${algorithmFamily.join(", ")} for recipient key algorithm ${recipientKeyAlgorithm}`
        );
      }
    }
  }

  return {
    seenRecipients: seenWrappedKeyRecipients
  };
}

export function validateEncryptedContentShape(content, options = {}) {
  const errors = [];
  const pushError = (field, reason) => {
    errors.push({ field, reason });
  };
  const enforceReplayMetadata = options.enforceReplayMetadata === true;

  const profile = resolveE2eeProfile(content?.profile);
  if (!profile) {
    pushError(
      "content.profile",
      `must be one of: ${listSupportedE2eeProfiles().join(", ")} (loom-e2ee-1 alias is accepted)`
    );
  }

  if (!Number.isInteger(content?.epoch) || content.epoch < 0) {
    pushError("content.epoch", "must be a non-negative integer when encrypted");
  }

  const hasReplayCounter = Object.prototype.hasOwnProperty.call(content || {}, "replay_counter");
  if (!hasReplayCounter && enforceReplayMetadata) {
    pushError("content.replay_counter", "is required when encrypted");
  } else if (hasReplayCounter && (!Number.isInteger(content?.replay_counter) || content.replay_counter < 0)) {
    pushError("content.replay_counter", "must be a non-negative integer when encrypted");
  }

  const hasProfileCommitment = Object.prototype.hasOwnProperty.call(content || {}, "profile_commitment");
  const profileCommitmentValue =
    content?.profile_commitment == null ? "" : String(content.profile_commitment).trim();
  if (!hasProfileCommitment && enforceReplayMetadata) {
    pushError("content.profile_commitment", "is required when encrypted");
  } else if (hasProfileCommitment) {
    if (!profileCommitmentValue) {
      pushError("content.profile_commitment", "must be a non-empty base64url string when encrypted");
    } else if (!isBase64UrlValue(profileCommitmentValue)) {
      pushError("content.profile_commitment", "must be a non-empty base64url string when encrypted");
    } else if (profile && Number.isInteger(content?.epoch) && content.epoch >= 0) {
      const expectedProfileCommitment = computeE2eeProfileCommitment(profile.id, content.epoch);
      if (profileCommitmentValue !== expectedProfileCommitment) {
        pushError("content.profile_commitment", "must match profile/epoch cryptographic commitment");
      }
    }
  }

  if (!isBase64UrlValue(content?.ciphertext)) {
    pushError("content.ciphertext", "must be a base64url string when encrypted");
  } else if (options.verifyPayloadCiphertextStructure === true) {
    try {
      parseE2eeCiphertextPackage(content.ciphertext);
    } catch (error) {
      pushError("content.ciphertext", error?.message || "invalid encrypted payload ciphertext package");
    }
  }

  if (content?.human != null) {
    pushError("content.human", "must be omitted when content.encrypted=true");
  }

  if (content?.structured != null) {
    pushError("content.structured", "must be omitted when content.encrypted=true");
  }

  const wrappedKeys = content?.wrapped_keys;
  if (profile?.requires_wrapped_keys) {
    if (!Array.isArray(wrappedKeys) || wrappedKeys.length === 0) {
      pushError("content.wrapped_keys", "must include at least one wrapped key entry for encrypted content");
      return errors;
    }
  }

  if (wrappedKeys == null) {
    return errors;
  }

  validateWrappedKeyEntries({
    wrappedKeys,
    fieldPrefix: "content.wrapped_keys",
    profile,
    pushError,
    verifyWrappedKeyPayloadStructure: options.verifyWrappedKeyPayloadStructure === true,
    resolveRecipientEncryptionKey:
      typeof options.resolveRecipientEncryptionKey === "function"
        ? options.resolveRecipientEncryptionKey
        : null
  });

  return errors;
}

export function validateEncryptionEpochParameters(parameters, options = {}) {
  const errors = [];
  const pushError = (field, reason) => {
    errors.push({ field, reason });
  };

  const profile = resolveE2eeProfile(parameters?.profile);
  if (!profile) {
    pushError(
      "content.structured.parameters.profile",
      `must be one of: ${listSupportedE2eeProfiles().join(", ")} (loom-e2ee-1 alias is accepted)`
    );
  }

  if (!Number.isInteger(parameters?.epoch) || parameters.epoch < 0) {
    pushError(
      "content.structured.parameters.epoch",
      "must be a non-negative integer for encryption.epoch@v1"
    );
  }

  const wrappedKeys = parameters?.wrapped_keys;
  if (!Array.isArray(wrappedKeys) || wrappedKeys.length === 0) {
    pushError(
      "content.structured.parameters.wrapped_keys",
      "must include at least one wrapped key entry for encryption.epoch@v1"
    );
    return errors;
  }

  const wrappedKeyValidation = validateWrappedKeyEntries({
    wrappedKeys,
    fieldPrefix: "content.structured.parameters.wrapped_keys",
    profile,
    pushError,
    verifyWrappedKeyPayloadStructure: options.verifyWrappedKeyPayloadStructure === true,
    resolveRecipientEncryptionKey:
      typeof options.resolveRecipientEncryptionKey === "function"
        ? options.resolveRecipientEncryptionKey
        : null
  });
  const seenRecipients = wrappedKeyValidation.seenRecipients;

  const requiredRecipients = Array.from(
    new Set((Array.isArray(options.requiredRecipients) ? options.requiredRecipients : []).map((value) => String(value || "").trim()).filter(Boolean))
  );
  for (const requiredRecipient of requiredRecipients) {
    if (!seenRecipients.has(requiredRecipient)) {
      pushError(
        "content.structured.parameters.wrapped_keys",
        `missing wrapped key for active participant ${requiredRecipient}`
      );
    }
  }

  return errors;
}
