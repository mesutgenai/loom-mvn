import { canonicalizeJson } from "./canonical.js";
import { verifyUtf8MessageSignature, signUtf8Message } from "./crypto.js";

const POP_SIGNATURE_CONTEXT = "LOOM-CAPABILITY-POP-v1\0";

/**
 * Create a Proof-of-Possession proof binding a capability to an envelope.
 *
 * Signs: context + canonical({ capability_id, envelope_id, timestamp })
 *
 * @param {object} options
 * @param {string} options.capabilityId - The capability token ID
 * @param {string} options.envelopeId - The envelope being authorized
 * @param {string} options.timestamp - ISO-8601 timestamp
 * @param {string} options.privateKeyPem - The signing private key PEM
 * @returns {string} base64url signature
 */
export function createCapabilityPoP({ capabilityId, envelopeId, timestamp, privateKeyPem }) {
  const payload = canonicalizeJson({
    capability_id: capabilityId,
    envelope_id: envelopeId,
    timestamp
  });
  const message = POP_SIGNATURE_CONTEXT + payload;
  return signUtf8Message(privateKeyPem, message);
}

/**
 * Verify a Proof-of-Possession proof.
 *
 * @param {object} options
 * @param {string} options.capabilityId - The capability token ID
 * @param {string} options.envelopeId - The envelope being authorized
 * @param {string} options.timestamp - ISO-8601 timestamp
 * @param {string} options.signature - base64url signature to verify
 * @param {string} options.publicKeyPem - The public key PEM
 * @returns {boolean} true if valid
 */
export function verifyCapabilityPoP({ capabilityId, envelopeId, timestamp, signature, publicKeyPem }) {
  const payload = canonicalizeJson({
    capability_id: capabilityId,
    envelope_id: envelopeId,
    timestamp
  });
  const message = POP_SIGNATURE_CONTEXT + payload;
  return verifyUtf8MessageSignature(publicKeyPem, message, signature);
}

/**
 * Set of intent actions that require PoP when using capability tokens.
 */
export const POP_REQUIRED_INTENTS = new Set([
  "capability.revoked@v1",
  "delegation.revoked@v1",
  "thread.delegate@v1",
  "encryption.epoch@v1",
  "encryption.rotate@v1",
  "thread.link@v1"
]);
