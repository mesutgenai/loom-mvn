import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { canonicalizeEnvelope, canonicalizeJson } from "../src/protocol/canonical.js";
import { signEnvelope, verifyEnvelopeSignature } from "../src/protocol/crypto.js";
import {
  decryptE2eeAttachment,
  decryptE2eePayloadJson,
  encryptE2eeAttachment,
  encryptE2eePayload,
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

test("fixture vectors: envelope signature vector remains stable", () => {
  const fixture = loadFixture("envelope-signature-ed25519-v1.json").vector;
  const signedEnvelope = signEnvelope(fixture.unsigned_envelope, fixture.private_key_pem, fixture.key_id);

  assert.equal(canonicalizeEnvelope(signedEnvelope), fixture.expected_canonical);
  assert.equal(signedEnvelope.signature.value, fixture.expected_signature_base64url);
  assert.equal(
    verifyEnvelopeSignature(signedEnvelope, {
      [fixture.key_id]: fixture.public_key_pem
    }),
    true
  );
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
