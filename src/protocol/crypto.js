import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

import { canonicalizeEnvelope } from "./canonical.js";
import { LoomError } from "./errors.js";

const ENVELOPE_SIGNATURE_CONTEXT = "LOOM-ENVELOPE-SIG-v1\0";

export function toBase64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value) {
  if (typeof value !== "string") {
    throw new TypeError("Expected base64url string");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64");
}

export function generateSigningKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

export function derivePublicKeyPemFromPrivateKeyPem(privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(privateKey);
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

export function signEnvelope(envelope, privateKeyPem, keyId, options = {}) {
  const useContext = options.signatureContext !== null;
  const context = useContext ? (options.signatureContext ?? ENVELOPE_SIGNATURE_CONTEXT) : "";
  const privateKey = createPrivateKey(privateKeyPem);
  const canonical = canonicalizeEnvelope(envelope);
  const message = context + canonical;
  const signatureBytes = sign(null, Buffer.from(message, "utf-8"), privateKey);

  return {
    ...envelope,
    signature: {
      algorithm: "Ed25519",
      key_id: keyId,
      value: toBase64Url(signatureBytes),
      ...(useContext ? { context: "LOOM-ENVELOPE-SIG-v1" } : {})
    }
  };
}

export function signUtf8Message(privateKeyPem, message) {
  const privateKey = createPrivateKey(privateKeyPem);
  const signatureBytes = sign(null, Buffer.from(String(message), "utf-8"), privateKey);
  return toBase64Url(signatureBytes);
}

export function verifyUtf8MessageSignature(publicKeyPem, message, signatureValue) {
  const publicKey = createPublicKey(publicKeyPem);
  const signatureBytes = fromBase64Url(signatureValue);
  return verify(null, Buffer.from(String(message), "utf-8"), publicKey, signatureBytes);
}

export function verifyEnvelopeSignature(envelope, keyResolver) {
  const signature = envelope?.signature;
  if (!signature || signature.algorithm !== "Ed25519" || !signature.key_id || !signature.value) {
    throw new LoomError("SIGNATURE_INVALID", "Missing or malformed envelope signature", 401, {
      field: "signature"
    });
  }

  const publicKeyPem =
    typeof keyResolver === "function"
      ? keyResolver(signature.key_id, envelope)
      : keyResolver?.[signature.key_id];

  if (!publicKeyPem) {
    throw new LoomError("SIGNATURE_INVALID", `Unknown signing key: ${signature.key_id}`, 401, {
      field: "signature.key_id"
    });
  }

  const publicKey = createPublicKey(publicKeyPem);
  const canonical = canonicalizeEnvelope(envelope);
  const signatureBytes = fromBase64Url(signature.value);

  // Try context-prefixed verification first
  const contextMessage = ENVELOPE_SIGNATURE_CONTEXT + canonical;
  let valid = verify(null, Buffer.from(contextMessage, "utf-8"), publicKey, signatureBytes);

  // Legacy fallback for envelopes signed without context prefix
  if (!valid && !signature.context) {
    valid = verify(null, Buffer.from(canonical, "utf-8"), publicKey, signatureBytes);
  }

  if (!valid) {
    throw new LoomError("SIGNATURE_INVALID", "Envelope signature verification failed", 401, {
      field: "signature.value"
    });
  }

  return true;
}
