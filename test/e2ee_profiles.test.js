import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { validateEnvelopeShape } from "../src/protocol/envelope.js";
import {
  decryptE2eeAttachment,
  decryptE2eePayloadJson,
  encryptE2eeAttachment,
  encryptE2eePayload,
  generateE2eeX25519KeyPair
} from "../src/protocol/e2ee.js";
import { LoomStore } from "../src/node/store.js";

const WRAPPED_KEY_ALGORITHM = "X25519-HKDF-SHA256";
const ALICE_SIGNING_KEY_ID = "k_sign_alice_e2ee_1";
const BOB_SIGNING_KEY_ID = "k_sign_bob_e2ee_1";
const ALICE_ENCRYPTION_KEY_ID = "k_enc_alice_e2ee_1";
const BOB_ENCRYPTION_KEY_ID = "k_enc_bob_e2ee_1";

function makeEnvelope(overrides = {}) {
  return {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE0",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EE1",
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: ALICE_SIGNING_KEY_ID,
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-19T13:00:00Z",
    priority: "normal",
    content: {
      human: {
        text: "hello",
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
      key_id: ALICE_SIGNING_KEY_ID,
      value: "placeholderplaceholder"
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

function wrappedKey(to, keyId, ciphertext) {
  return {
    to,
    algorithm: WRAPPED_KEY_ALGORITHM,
    key_id: keyId,
    ciphertext
  };
}

function registerIdentityWithE2eeKeys(
  store,
  { id, displayName, signingKeyId, signingPublicKeyPem, encryptionKeyId, encryptionPublicKey }
) {
  store.registerIdentity({
    id,
    display_name: displayName,
    signing_keys: [{ key_id: signingKeyId, public_key_pem: signingPublicKeyPem }],
    encryption_keys: [
      {
        key_id: encryptionKeyId,
        algorithm: "X25519",
        public_key: encryptionPublicKey,
        status: "active"
      }
    ]
  });
}

function encryptContent({ profile = "loom-e2ee-x25519-xchacha20-v1", epoch, replayCounter = 0, plaintext, recipients }) {
  return encryptE2eePayload({
    profile,
    epoch,
    replayCounter,
    plaintext,
    recipients: recipients.map((recipient) => ({
      to: recipient.to,
      key_id: recipient.key_id,
      public_key: recipient.public_key,
      algorithm: WRAPPED_KEY_ALGORITHM
    }))
  });
}

test("encrypted content validation enforces profile and wrapped key requirements", () => {
  const invalid = makeEnvelope({
    content: {
      encrypted: true,
      profile: "unknown-profile",
      epoch: 0,
      ciphertext: "YWJj",
      wrapped_keys: [wrappedKey("loom://bob@node.test", BOB_ENCRYPTION_KEY_ID, "ZGVm")]
    }
  });
  const invalidErrors = validateEnvelopeShape(invalid);
  assert.equal(invalidErrors.some((error) => error.field === "content.profile"), true);

  const missingWrappedKeyMetadata = makeEnvelope({
    content: {
      encrypted: true,
      profile: "loom-e2ee-1",
      epoch: 0,
      ciphertext: "YWJj",
      wrapped_keys: [{ to: "loom://bob@node.test", ciphertext: "ZGVm" }]
    }
  });
  const missingWrappedKeyMetadataErrors = validateEnvelopeShape(missingWrappedKeyMetadata);
  assert.equal(
    missingWrappedKeyMetadataErrors.some((error) => error.field === "content.wrapped_keys[0].algorithm"),
    true
  );
  assert.equal(
    missingWrappedKeyMetadataErrors.some((error) => error.field === "content.wrapped_keys[0].key_id"),
    true
  );

  const leaking = makeEnvelope({
    content: {
      encrypted: true,
      profile: "loom-e2ee-1",
      epoch: 0,
      ciphertext: "YWJj",
      wrapped_keys: [wrappedKey("loom://bob@node.test", BOB_ENCRYPTION_KEY_ID, "ZGVm")],
      human: { text: "plaintext leak" }
    }
  });
  const leakingErrors = validateEnvelopeShape(leaking);
  assert.equal(leakingErrors.some((error) => error.field === "content.human"), true);

  const valid = makeEnvelope({
    content: {
      encrypted: true,
      profile: "loom-e2ee-1",
      epoch: 0,
      ciphertext: "YWJj",
      wrapped_keys: [wrappedKey("loom://bob@node.test", BOB_ENCRYPTION_KEY_ID, "ZGVm")]
    }
  });
  const validErrors = validateEnvelopeShape(valid);
  assert.equal(validErrors.some((error) => error.field.startsWith("content.")), false);
});

test("e2ee payload crypto path supports encrypt/decrypt roundtrip for recipients", () => {
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();

  const encrypted = encryptE2eePayload({
    profile: "loom-e2ee-1",
    epoch: 7,
    plaintext: {
      intent: "workflow.execute@v1",
      parameters: {
        id: "wf-42",
        retries: 0
      }
    },
    recipients: [
      {
        to: "loom://alice@node.test",
        key_id: ALICE_ENCRYPTION_KEY_ID,
        public_key: aliceEncryptionKeys.public_key
      },
      {
        to: "loom://bob@node.test",
        key_id: BOB_ENCRYPTION_KEY_ID,
        public_key: bobEncryptionKeys.public_key
      }
    ]
  });

  const decryptedForAlice = decryptE2eePayloadJson({
    content: encrypted,
    recipientIdentity: "loom://alice@node.test",
    recipientKeyId: ALICE_ENCRYPTION_KEY_ID,
    recipientPrivateKey: aliceEncryptionKeys.private_key_pem
  });
  assert.equal(decryptedForAlice.profile, "loom-e2ee-x25519-xchacha20-v1");
  assert.equal(decryptedForAlice.epoch, 7);
  assert.deepEqual(decryptedForAlice.plaintext_json, {
    intent: "workflow.execute@v1",
    parameters: {
      id: "wf-42",
      retries: 0
    }
  });

  const decryptedForBob = decryptE2eePayloadJson({
    content: encrypted,
    recipientIdentity: "loom://bob@node.test",
    recipientKeyId: BOB_ENCRYPTION_KEY_ID,
    recipientPrivateKey: bobEncryptionKeys.private_key_pem
  });
  assert.deepEqual(decryptedForBob.plaintext_json, decryptedForAlice.plaintext_json);

  assert.throws(
    () =>
      decryptE2eePayloadJson({
        content: encrypted,
        recipientIdentity: "loom://bob@node.test",
        recipientKeyId: BOB_ENCRYPTION_KEY_ID,
        recipientPrivateKey: aliceEncryptionKeys.private_key_pem
      }),
    /Unable to unwrap content encryption key/
  );
});

test("e2ee attachment crypto path supports encrypt/decrypt roundtrip for recipients", () => {
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();

  const encryptedAttachment = encryptE2eeAttachment({
    profile: "loom-e2ee-1",
    epoch: 7,
    replayCounter: 3,
    plaintext: "attachment-bytes-v1",
    recipients: [
      {
        to: "loom://alice@node.test",
        key_id: ALICE_ENCRYPTION_KEY_ID,
        public_key: aliceEncryptionKeys.public_key
      },
      {
        to: "loom://bob@node.test",
        key_id: BOB_ENCRYPTION_KEY_ID,
        public_key: bobEncryptionKeys.public_key
      }
    ]
  });

  const decryptedForAlice = decryptE2eeAttachment({
    content: encryptedAttachment,
    recipientIdentity: "loom://alice@node.test",
    recipientKeyId: ALICE_ENCRYPTION_KEY_ID,
    recipientPrivateKey: aliceEncryptionKeys.private_key_pem
  });
  assert.equal(decryptedForAlice.plaintext_utf8, "attachment-bytes-v1");

  const decryptedForBob = decryptE2eeAttachment({
    content: encryptedAttachment,
    recipientIdentity: "loom://bob@node.test",
    recipientKeyId: BOB_ENCRYPTION_KEY_ID,
    recipientPrivateKey: bobEncryptionKeys.private_key_pem
  });
  assert.equal(decryptedForBob.plaintext_utf8, "attachment-bytes-v1");
});

test("store enforces encrypted thread profile and epoch after encrypted thread starts", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE2",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EE3",
    content: encryptContent({
      epoch: 0,
      plaintext: {
        message: "root"
      },
      recipients: [
        {
          to: "loom://alice@node.test",
          key_id: ALICE_ENCRYPTION_KEY_ID,
          public_key: aliceEncryptionKeys.public_key
        },
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  store.ingestEnvelope(root);

  const thread = store.getThread(root.thread_id);
  assert.equal(thread.encryption.enabled, true);
  assert.equal(thread.encryption.profile, "loom-e2ee-x25519-xchacha20-v1");
  assert.equal(thread.encryption.key_epoch, 0);

  const unencryptedFollowUp = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE4",
    thread_id: root.thread_id,
    parent_id: root.id
  });
  assert.throws(
    () => store.ingestEnvelope(unencryptedFollowUp),
    (error) => error?.code === "ENCRYPTION_REQUIRED"
  );

  const wrongEpochFollowUp = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE5",
    thread_id: root.thread_id,
    parent_id: root.id,
    content: encryptContent({
      epoch: 1,
      plaintext: {
        message: "wrong-epoch"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  assert.throws(
    () => store.ingestEnvelope(wrongEpochFollowUp),
    (error) => error?.code === "ENVELOPE_INVALID"
  );

  const validFollowUp = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE6",
    thread_id: root.thread_id,
    parent_id: root.id,
    content: encryptContent({
      epoch: 0,
      replayCounter: 1,
      plaintext: {
        message: "ok"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  const stored = store.ingestEnvelope(validFollowUp);
  assert.equal(stored.id, validFollowUp.id);
});

test("store enforces encrypted replay counters and epoch reset rules at ingest", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA7",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EA8",
    content: encryptContent({
      epoch: 0,
      replayCounter: 0,
      plaintext: {
        message: "root"
      },
      recipients: [
        {
          to: "loom://alice@node.test",
          key_id: ALICE_ENCRYPTION_KEY_ID,
          public_key: aliceEncryptionKeys.public_key
        },
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  store.ingestEnvelope(root);

  const replayOne = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA9",
    thread_id: root.thread_id,
    parent_id: root.id,
    content: encryptContent({
      epoch: 0,
      replayCounter: 1,
      plaintext: {
        message: "counter-one"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  store.ingestEnvelope(replayOne);

  const replayOneDuplicate = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAA",
    thread_id: root.thread_id,
    parent_id: replayOne.id,
    content: encryptContent({
      epoch: 0,
      replayCounter: 1,
      plaintext: {
        message: "counter-one-duplicate"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  assert.throws(
    () => store.ingestEnvelope(replayOneDuplicate),
    (error) => error?.code === "STATE_TRANSITION_INVALID"
  );

  const rotate = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAB",
    thread_id: root.thread_id,
    parent_id: replayOne.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.rotate@v1",
        parameters: {
          epoch: 1,
          wrapped_keys: encryptContent({
            epoch: 1,
            replayCounter: 0,
            plaintext: {
              operation: "rotate"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(rotate);

  const invalidPostRotateCounter = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAC",
    thread_id: root.thread_id,
    parent_id: rotate.id,
    content: encryptContent({
      epoch: 1,
      replayCounter: 2,
      plaintext: {
        message: "epoch-1-counter-two"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  assert.throws(
    () => store.ingestEnvelope(invalidPostRotateCounter),
    (error) => error?.code === "ENVELOPE_INVALID"
  );

  const validPostRotateCounterReset = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAD",
    thread_id: root.thread_id,
    parent_id: rotate.id,
    content: encryptContent({
      epoch: 1,
      replayCounter: 0,
      plaintext: {
        message: "epoch-1-counter-zero"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  const stored = store.ingestEnvelope(validPostRotateCounterReset);
  assert.equal(stored.id, validPostRotateCounterReset.id);
});

test("store rejects wrapped key entries that do not bind to recipient encryption key ids", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EEA",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EEB",
    content: encryptContent({
      epoch: 0,
      plaintext: {
        message: "root"
      },
      recipients: [
        {
          to: "loom://alice@node.test",
          key_id: ALICE_ENCRYPTION_KEY_ID,
          public_key: aliceEncryptionKeys.public_key
        },
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  store.ingestEnvelope(root);

  const invalidFollowUpContent = encryptContent({
    epoch: 0,
    replayCounter: 1,
    plaintext: {
      message: "invalid-key-id"
    },
    recipients: [
      {
        to: "loom://bob@node.test",
        key_id: BOB_ENCRYPTION_KEY_ID,
        public_key: bobEncryptionKeys.public_key
      }
    ]
  });
  invalidFollowUpContent.wrapped_keys[0].key_id = "k_enc_bob_unknown";

  const invalidFollowUp = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EEC",
    thread_id: root.thread_id,
    parent_id: root.id,
    content: invalidFollowUpContent
  });

  assert.throws(
    () => store.ingestEnvelope(invalidFollowUp),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread_op encryption intents can enable and rotate thread encryption epochs", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE7",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EE8"
  });
  store.ingestEnvelope(root);

  const enable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EE9",
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v1",
          epoch: 3,
          wrapped_keys: encryptContent({
            epoch: 3,
            plaintext: {
              operation: "enable"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enable);

  const threadAfterEnable = store.getThread(root.thread_id);
  assert.equal(threadAfterEnable.encryption.enabled, true);
  assert.equal(threadAfterEnable.encryption.profile, "loom-e2ee-x25519-xchacha20-v1");
  assert.equal(threadAfterEnable.encryption.key_epoch, 3);

  const rotate = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA0",
    thread_id: root.thread_id,
    parent_id: enable.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.rotate@v1",
        parameters: {
          epoch: 4,
          wrapped_keys: encryptContent({
            epoch: 4,
            plaintext: {
              operation: "rotate"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(rotate);

  const threadAfterRotate = store.getThread(root.thread_id);
  assert.equal(threadAfterRotate.encryption.key_epoch, 4);

  const encryptedAtRotatedEpoch = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA1",
    thread_id: root.thread_id,
    parent_id: rotate.id,
    content: encryptContent({
      epoch: 4,
      plaintext: {
        message: "post-rotate"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });
  const stored = store.ingestEnvelope(encryptedAtRotatedEpoch);
  assert.equal(stored.id, encryptedAtRotatedEpoch.id);
});

test("encrypted thread bootstrap requires wrapped keys for all active participants", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const missingSenderWrappedKey = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA2",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EA3",
    content: encryptContent({
      epoch: 0,
      plaintext: {
        message: "missing-sender-key"
      },
      recipients: [
        {
          to: "loom://bob@node.test",
          key_id: BOB_ENCRYPTION_KEY_ID,
          public_key: bobEncryptionKeys.public_key
        }
      ]
    })
  });

  assert.throws(
    () => store.ingestEnvelope(missingSenderWrappedKey),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("encryption.epoch operation requires wrapped keys for all active participants", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA4",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EA5"
  });
  store.ingestEnvelope(root);

  const invalidEnable = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA6",
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v1",
          epoch: 0,
          wrapped_keys: encryptContent({
            epoch: 0,
            plaintext: {
              operation: "enable"
            },
            recipients: [
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(invalidEnable),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("encryption.epoch rejects non-allowlisted profile downgrade migrations", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA7",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EA8"
  });
  store.ingestEnvelope(root);

  const enableV2 = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EA9",
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v2",
          epoch: 0,
          wrapped_keys: encryptContent({
            profile: "loom-e2ee-x25519-xchacha20-v2",
            epoch: 0,
            plaintext: {
              operation: "enable-v2"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enableV2);

  const downgradeToV1 = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAA",
    thread_id: root.thread_id,
    parent_id: enableV2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v1",
          epoch: 1,
          wrapped_keys: encryptContent({
            profile: "loom-e2ee-x25519-xchacha20-v1",
            epoch: 1,
            plaintext: {
              operation: "downgrade-v1"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(downgradeToV1),
    (error) => error?.code === "STATE_TRANSITION_INVALID"
  );
});

test("encryption.epoch allows explicitly allowlisted profile migration", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceEncryptionKeys = generateE2eeX25519KeyPair();
  const bobEncryptionKeys = generateE2eeX25519KeyPair();
  const store = new LoomStore({
    nodeId: "node.test",
    e2eeProfileMigrationAllowlist: "loom-e2ee-x25519-xchacha20-v2>loom-e2ee-x25519-xchacha20-v1"
  });

  registerIdentityWithE2eeKeys(store, {
    id: "loom://alice@node.test",
    displayName: "Alice",
    signingKeyId: ALICE_SIGNING_KEY_ID,
    signingPublicKeyPem: aliceKeys.publicKeyPem,
    encryptionKeyId: ALICE_ENCRYPTION_KEY_ID,
    encryptionPublicKey: aliceEncryptionKeys.public_key
  });
  registerIdentityWithE2eeKeys(store, {
    id: "loom://bob@node.test",
    displayName: "Bob",
    signingKeyId: BOB_SIGNING_KEY_ID,
    signingPublicKeyPem: bobKeys.publicKeyPem,
    encryptionKeyId: BOB_ENCRYPTION_KEY_ID,
    encryptionPublicKey: bobEncryptionKeys.public_key
  });

  const root = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAB",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69E2EAC"
  });
  store.ingestEnvelope(root);

  const enableV2 = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAD",
    thread_id: root.thread_id,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v2",
          epoch: 0,
          wrapped_keys: encryptContent({
            profile: "loom-e2ee-x25519-xchacha20-v2",
            epoch: 0,
            plaintext: {
              operation: "enable-v2"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(enableV2);

  const migrateToV1 = signBaseEnvelope(aliceKeys.privateKeyPem, {
    id: "env_01ARZ3NDEKTSV4RRFFQ69E2EAE",
    thread_id: root.thread_id,
    parent_id: enableV2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "encryption.epoch@v1",
        parameters: {
          profile: "loom-e2ee-x25519-xchacha20-v1",
          epoch: 1,
          wrapped_keys: encryptContent({
            profile: "loom-e2ee-x25519-xchacha20-v1",
            epoch: 1,
            plaintext: {
              operation: "migrate-v1"
            },
            recipients: [
              {
                to: "loom://alice@node.test",
                key_id: ALICE_ENCRYPTION_KEY_ID,
                public_key: aliceEncryptionKeys.public_key
              },
              {
                to: "loom://bob@node.test",
                key_id: BOB_ENCRYPTION_KEY_ID,
                public_key: bobEncryptionKeys.public_key
              }
            ]
          }).wrapped_keys
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(migrateToV1);

  const thread = store.getThread(root.thread_id);
  assert.equal(thread.encryption.profile, "loom-e2ee-x25519-xchacha20-v1");
  assert.equal(thread.encryption.key_epoch, 1);
});
