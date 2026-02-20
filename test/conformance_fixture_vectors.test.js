import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { canonicalizeEnvelope, canonicalizeJson } from "../src/protocol/canonical.js";
import { createCapabilityPoP, verifyCapabilityPoP } from "../src/protocol/capability_pop.js";
import { signEnvelope, verifyEnvelopeSignature } from "../src/protocol/crypto.js";
import { validateEnvelopeShape } from "../src/protocol/envelope.js";
import { verifyDelegationLinkOrThrow, verifyDelegationChainOrThrow } from "../src/protocol/delegation.js";
import { createReplayTracker, checkReplayCounter, acceptReplayCounter, replayStateKey } from "../src/protocol/replay.js";
import { loadEnvelopeSchema, listAvailableSchemas } from "../src/protocol/schema_validator.js";
import {
  decryptE2eeAttachment,
  decryptE2eePayloadJson,
  encryptE2eeAttachment,
  encryptE2eePayload,
  listAllE2eeProfiles,
  listSupportedE2eeProfiles,
  resolveE2eeProfile,
  validateEncryptedContentShape,
  validateEncryptionEpochParameters
} from "../src/protocol/e2ee.js";

function loadFixture(name) {
  const fixtureUrl = new URL(`./fixtures/conformance/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fixtureUrl, "utf-8"));
}

test("fixture vectors: canonical JSON vectors remain stable", () => {
  const fixture = loadFixture("canonical-json-v1.json");

  for (const vector of fixture.vectors) {
    if (vector.expected_error) {
      assert.throws(() => canonicalizeJson(vector.input), new RegExp(vector.expected_error));
      continue;
    }
    assert.equal(canonicalizeJson(vector.input), vector.expected, vector.id);
  }
});

test("fixture vectors: envelope signature context-prefixed vector remains stable", () => {
  const fixture = loadFixture("envelope-signature-ed25519-v1.json").vector;
  const signedEnvelope = signEnvelope(fixture.unsigned_envelope, fixture.private_key_pem, fixture.key_id);

  assert.equal(canonicalizeEnvelope(signedEnvelope), fixture.expected_canonical);
  assert.equal(signedEnvelope.signature.value, fixture.expected_signature_base64url_context);
  assert.equal(signedEnvelope.signature.context, fixture.signature_context);
  assert.equal(
    verifyEnvelopeSignature(signedEnvelope, { [fixture.key_id]: fixture.public_key_pem }),
    true
  );
});

test("fixture vectors: envelope signature legacy fallback remains stable", () => {
  const fixture = loadFixture("envelope-signature-ed25519-v1.json").vector;
  const signedLegacy = signEnvelope(fixture.unsigned_envelope, fixture.private_key_pem, fixture.key_id, { signatureContext: null });

  assert.equal(signedLegacy.signature.value, fixture.expected_signature_base64url_legacy);
  assert.equal(signedLegacy.signature.context, undefined);
  assert.equal(
    verifyEnvelopeSignature(signedLegacy, { [fixture.key_id]: fixture.public_key_pem }),
    true
  );
});

test("fixture vectors: signature context vectors verify correctly", () => {
  const fixture = loadFixture("signature-context-v1.json");
  for (const vector of fixture.vectors) {
    const result = verifyEnvelopeSignature(vector.envelope, { [vector.envelope.signature.key_id]: fixture.public_key_pem });
    assert.equal(result, vector.should_verify, vector.id);
  }
});

test("fixture vectors: JCS number serialization vectors remain stable", () => {
  const fixture = loadFixture("jcs-number-serialization-v1.json");
  for (const vector of fixture.vectors) {
    const result = canonicalizeJson(vector.input);
    assert.equal(result, vector.expected, vector.id);
  }
  assert.equal(canonicalizeJson(-0), "0", "negative-zero");
});

test("fixture vectors: e2ee profile vectors remain stable", () => {
  const fixture = loadFixture("e2ee-profile-v1.json");
  for (const vector of fixture.vectors) {
    const errors = validateEncryptedContentShape(vector.content, vector.options || {});
    if (vector.expected_valid) {
      assert.equal(errors.length, 0, vector.id);
      continue;
    }
    assert.equal(errors.some((error) => error.field === vector.expected_error_field), true, vector.id);
  }
});

test("fixture vectors: e2ee epoch parameter vectors remain stable", () => {
  const fixture = loadFixture("e2ee-epoch-params-v1.json");
  for (const vector of fixture.vectors) {
    const errors = validateEncryptionEpochParameters(vector.parameters, {
      requiredRecipients: vector.required_recipients || []
    });
    if (vector.expected_valid) {
      assert.equal(errors.length, 0, vector.id);
      continue;
    }
    assert.equal(errors.some((error) => error.field === vector.expected_error_field), true, vector.id);
  }
});

test("fixture vectors: e2ee crypto vectors remain stable", () => {
  const fixture = loadFixture("e2ee-crypto-x25519-xchacha-v1.json").vector;

  const encrypted = encryptE2eePayload({
    profile: fixture.input.profile,
    epoch: fixture.input.epoch,
    replayCounter: fixture.input.replay_counter,
    profileCommitment: fixture.input.profile_commitment,
    plaintext: fixture.input.plaintext_json,
    contentEncryptionKey: fixture.input.content_encryption_key,
    payloadNonce: fixture.input.payload_nonce,
    recipients: fixture.input.recipients.map((recipient) => ({
      to: recipient.to,
      key_id: recipient.key_id,
      algorithm: recipient.algorithm,
      public_key: recipient.recipient_public_key,
      ephemeral_private_key: {
        private_key: recipient.ephemeral_private_key,
        public_key: recipient.ephemeral_public_key
      },
      wrap_nonce: recipient.wrap_nonce
    }))
  });

  assert.deepEqual(encrypted, fixture.expected_encrypted_content);

  for (const decryptCase of fixture.decrypt_cases) {
    const matchingRecipient = fixture.input.recipients.find(
      (recipient) =>
        recipient.to === decryptCase.recipient_identity &&
        recipient.key_id === decryptCase.recipient_key_id
    );
    assert.ok(matchingRecipient, `missing recipient vector for ${decryptCase.recipient_identity}`);

    const decrypted = decryptE2eePayloadJson({
      content: fixture.expected_encrypted_content,
      recipientIdentity: decryptCase.recipient_identity,
      recipientKeyId: decryptCase.recipient_key_id,
      recipientPrivateKey: {
        private_key: decryptCase.recipient_private_key,
        public_key: matchingRecipient.recipient_public_key
      }
    });

    assert.deepEqual(decrypted.plaintext_json, fixture.expected_plaintext_json);
    assert.equal(decrypted.wrapped_key.algorithm, decryptCase.expected_wrapped_key_algorithm);
  }
});

test("fixture vectors: e2ee attachment crypto vectors remain stable", () => {
  const fixture = loadFixture("e2ee-attachment-crypto-x25519-xchacha-v1.json").vector;

  const encrypted = encryptE2eeAttachment({
    profile: fixture.input.profile,
    epoch: fixture.input.epoch,
    replayCounter: fixture.input.replay_counter,
    profileCommitment: fixture.input.profile_commitment,
    plaintext: fixture.input.plaintext_utf8,
    contentEncryptionKey: fixture.input.content_encryption_key,
    payloadNonce: fixture.input.payload_nonce,
    recipients: fixture.input.recipients.map((recipient) => ({
      to: recipient.to,
      key_id: recipient.key_id,
      algorithm: recipient.algorithm,
      public_key: recipient.recipient_public_key,
      ephemeral_private_key: {
        private_key: recipient.ephemeral_private_key,
        public_key: recipient.ephemeral_public_key
      },
      wrap_nonce: recipient.wrap_nonce
    }))
  });

  assert.deepEqual(encrypted, fixture.expected_encrypted_attachment);

  for (const decryptCase of fixture.decrypt_cases) {
    const decrypted = decryptE2eeAttachment({
      content: fixture.expected_encrypted_attachment,
      recipientIdentity: decryptCase.recipient_identity,
      recipientKeyId: decryptCase.recipient_key_id,
      recipientPrivateKey: decryptCase.recipient_private_key
    });
    assert.equal(decrypted.plaintext_utf8, fixture.expected_plaintext_utf8);
    assert.equal(decrypted.wrapped_key.algorithm, decryptCase.expected_wrapped_key_algorithm);
  }
});

test("e2ee profiles: all profiles have security_properties", () => {
  const allProfiles = listAllE2eeProfiles();
  assert.ok(allProfiles.length >= 3, "should have at least 3 profiles (v1, v2, MLS)");

  for (const profile of allProfiles) {
    assert.ok(profile.security_properties, `${profile.id} missing security_properties`);
    assert.equal(typeof profile.security_properties.forward_secrecy, "boolean", `${profile.id} missing forward_secrecy`);
    assert.equal(typeof profile.security_properties.post_compromise_security, "boolean", `${profile.id} missing post_compromise_security`);
    assert.ok(typeof profile.security_properties.confidentiality === "string", `${profile.id} missing confidentiality`);
  }
});

test("e2ee profiles: MLS placeholder exists as reserved", () => {
  const allProfiles = listAllE2eeProfiles();
  const mls = allProfiles.find((p) => p.id === "loom-e2ee-mls-1");
  assert.ok(mls, "MLS placeholder profile should exist");
  assert.equal(mls.status, "reserved");
  assert.equal(mls.security_properties.forward_secrecy, true);
  assert.equal(mls.security_properties.post_compromise_security, true);
  assert.equal(mls.security_properties.confidentiality, "mls_grade");
});

test("e2ee profiles: resolveE2eeProfile returns null for reserved profiles", () => {
  const resolved = resolveE2eeProfile("loom-e2ee-mls-1");
  assert.equal(resolved, null, "reserved profiles should not be resolvable");
});

test("e2ee profiles: listSupportedE2eeProfiles excludes reserved profiles", () => {
  const supported = listSupportedE2eeProfiles();
  assert.ok(!supported.includes("loom-e2ee-mls-1"), "reserved profile should not appear in supported list");
  assert.ok(supported.includes("loom-e2ee-x25519-xchacha20-v1"), "v1 should be in supported list");
  assert.ok(supported.includes("loom-e2ee-x25519-xchacha20-v2"), "v2 should be in supported list");
});

test("fixture vectors: capability PoP vectors remain stable", () => {
  const fixture = loadFixture("capability-pop-v1.json");

  for (const vector of fixture.vectors) {
    const publicKeyPem = vector.use_wrong_key ? fixture.wrong_public_key_pem : fixture.public_key_pem;
    const result = verifyCapabilityPoP({
      capabilityId: vector.capability_id,
      envelopeId: vector.envelope_id,
      timestamp: vector.timestamp,
      signature: vector.signature,
      publicKeyPem
    });
    assert.equal(result, vector.should_verify, vector.id);
  }
});

test("fixture vectors: capability PoP round-trip", () => {
  const fixture = loadFixture("capability-pop-v1.json");
  const sig = createCapabilityPoP({
    capabilityId: "cap_test_roundtrip",
    envelopeId: "env_test_roundtrip",
    timestamp: "2025-06-01T00:00:00.000Z",
    privateKeyPem: fixture.private_key_pem
  });
  assert.equal(
    verifyCapabilityPoP({
      capabilityId: "cap_test_roundtrip",
      envelopeId: "env_test_roundtrip",
      timestamp: "2025-06-01T00:00:00.000Z",
      signature: sig,
      publicKeyPem: fixture.public_key_pem
    }),
    true
  );
});

test("envelope JSON Schema: loads and has expected structure", () => {
  const schema = loadEnvelopeSchema();
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.title, "LOOM Envelope v1.1");
  assert.ok(schema.required.includes("loom"));
  assert.ok(schema.required.includes("id"));
  assert.ok(schema.required.includes("thread_id"));
  assert.ok(schema.required.includes("type"));
  assert.ok(schema.required.includes("from"));
  assert.ok(schema.required.includes("to"));
  assert.ok(schema.required.includes("content"));
  assert.ok(schema.required.includes("signature"));
  assert.ok(schema.required.includes("created_at"));
  assert.ok(schema.properties.loom);
  assert.ok(schema.properties.from);
  assert.ok(schema.properties.signature);
  assert.ok(schema.$defs.sender);
  assert.ok(schema.$defs.recipient);
  assert.ok(schema.$defs.signature);
  assert.ok(schema.$defs.content);
  assert.ok(schema.$defs.attachment);
});

test("envelope JSON Schema: sender definition includes device_id", () => {
  const schema = loadEnvelopeSchema();
  const sender = schema.$defs.sender;
  assert.ok(sender.properties.device_id);
  assert.equal(sender.properties.device_id.type, "string");
  assert.equal(sender.properties.device_id.minLength, 1);
  assert.equal(sender.properties.device_id.maxLength, 128);
});

test("envelope JSON Schema: signature includes context field", () => {
  const schema = loadEnvelopeSchema();
  const sig = schema.$defs.signature;
  assert.ok(sig.properties.context);
  assert.equal(sig.properties.algorithm.const, "Ed25519");
});

test("envelope JSON Schema: listAvailableSchemas returns expected list", () => {
  const schemas = listAvailableSchemas();
  assert.ok(schemas.includes("envelope-v1.1"));
});

test("envelope JSON Schema: caching works (same reference on second load)", () => {
  const schema1 = loadEnvelopeSchema();
  const schema2 = loadEnvelopeSchema();
  assert.equal(schema1, schema2, "cached schema should return the same object reference");
});

test("envelope JSON Schema: divergence guard — schema required fields match validateEnvelopeShape", () => {
  const schema = loadEnvelopeSchema();
  const schemaRequired = new Set(schema.required);

  // Build a minimal envelope missing each required field one at a time.
  // validateEnvelopeShape must produce an error for the same field the schema requires.
  const baseEnvelope = {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FA0",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FA1",
    parent_id: null,
    type: "message",
    from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-20T10:00:00Z",
    priority: "normal",
    content: {
      human: { text: "hello", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    signature: { algorithm: "Ed25519", key_id: "k_sign_alice_1", value: "placeholderplaceholder" }
  };

  // Verify the base envelope passes validation
  const baseErrors = validateEnvelopeShape(baseEnvelope);
  assert.equal(baseErrors.length, 0, "base envelope should pass validation");

  // For each schema-required field, removing it should produce a validation error
  for (const field of schemaRequired) {
    const mutated = { ...baseEnvelope };
    delete mutated[field];
    const errors = validateEnvelopeShape(mutated);
    const fieldErrors = errors.filter((e) => e.field === field || e.field.startsWith(field + "."));
    assert.ok(
      fieldErrors.length > 0,
      `Schema requires "${field}" but validateEnvelopeShape did not error when it was removed (got errors: ${JSON.stringify(errors.map((e) => e.field))})`
    );
  }

  // Verify there are no fields that validateEnvelopeShape requires but the schema doesn't
  // by checking that removing non-required-in-schema fields doesn't break validation
  const schemaOptionalTopLevel = Object.keys(schema.properties).filter((k) => !schemaRequired.has(k));
  for (const field of schemaOptionalTopLevel) {
    if (!(field in baseEnvelope)) continue;
    const mutated = { ...baseEnvelope };
    delete mutated[field];
    const errors = validateEnvelopeShape(mutated);
    const fieldErrors = errors.filter((e) => e.field === field);
    // These should NOT produce field-level errors (field is optional in schema)
    assert.equal(
      fieldErrors.length,
      0,
      `Schema says "${field}" is optional but validateEnvelopeShape errors when removed: ${JSON.stringify(fieldErrors)}`
    );
  }
});

test("fixture vectors: delegation link missing created_at is rejected", () => {
  const fixture = loadFixture("delegation-chain-v1.json");
  const vector = fixture.vectors.find((v) => v.id === "missing-created-at");
  const resolveIdentity = () => ({ signing_keys: [{ key_id: "k_sign_owner1", public_key_pem: fixture.owner_public_key_pem }] });
  assert.throws(
    () => verifyDelegationLinkOrThrow(vector.link, { resolveIdentity }),
    (err) => err.code === vector.expected_error
  );
});

test("fixture vectors: delegation link with future created_at is rejected", () => {
  const fixture = loadFixture("delegation-chain-v1.json");
  const vector = fixture.vectors.find((v) => v.id === "future-created-at");
  const resolveIdentity = () => ({ signing_keys: [{ key_id: "k_sign_owner1", public_key_pem: fixture.owner_public_key_pem }] });
  assert.throws(
    () => verifyDelegationLinkOrThrow(vector.link, { resolveIdentity }),
    (err) => err.code === vector.expected_error
  );
});

test("fixture vectors: delegation chain depth exceeded is rejected", () => {
  const fixture = loadFixture("delegation-chain-v1.json");
  const vector = fixture.vectors.find((v) => v.id === "chain-depth-exceeded");
  const resolveIdentity = () => ({
    type: "human",
    signing_keys: [{ key_id: "k_sign_owner1", public_key_pem: fixture.owner_public_key_pem }]
  });
  const envelope = {
    from: {
      identity: "loom://agent@node.test",
      delegation_chain: [fixture.valid_link, fixture.valid_link]
    },
    content: { structured: { intent: "message.send@v1" } }
  };
  assert.throws(
    () => verifyDelegationChainOrThrow(envelope, { resolveIdentity, maxChainLength: vector.max_chain_length }),
    (err) => err.code === vector.expected_error
  );
});

test("fixture vectors: replay sliding window vectors remain stable", () => {
  const fixture = loadFixture("replay-sliding-window-v1.json");

  for (const vector of fixture.vectors) {
    if (vector.state_keys) {
      for (const keyCase of vector.state_keys) {
        assert.equal(
          replayStateKey(keyCase.identity, keyCase.device_id),
          keyCase.expected_key,
          `${vector.id}: ${keyCase.identity}:${keyCase.device_id}`
        );
      }
      continue;
    }

    const tracker = createReplayTracker(vector.window_size);
    for (const op of vector.operations) {
      const result = vector.check_only
        ? checkReplayCounter(tracker, op.counter)
        : acceptReplayCounter(tracker, op.counter);
      assert.equal(result.accepted, op.expected_accepted, `${vector.id}: counter ${op.counter}`);
      if (op.expected_reason) {
        assert.equal(result.reason, op.expected_reason, `${vector.id}: counter ${op.counter} reason`);
      }
    }
  }
});
