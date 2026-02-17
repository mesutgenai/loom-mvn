import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { connect as connectHttp2 } from "node:http2";
import { readFileSync } from "node:fs";

import { createLoomServer } from "../src/node/server.js";
import {
  generateSigningKeyPair,
  signEnvelope,
  signUtf8Message,
  verifyUtf8MessageSignature
} from "../src/protocol/crypto.js";
import { canonicalizeJson } from "../src/protocol/canonical.js";
import { canonicalizeDelegationLink } from "../src/protocol/delegation.js";

const TEST_TLS_KEY_PEM = readFileSync(new URL("./fixtures/wire_tls_key.pem", import.meta.url), "utf-8");
const TEST_TLS_CERT_PEM = readFileSync(new URL("./fixtures/wire_tls_cert.pem", import.meta.url), "utf-8");

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });

  const body = await response.json();
  return { response, body };
}

async function textRequest(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.text();
  return { response, body };
}

function buildIdentityRegistrationProof({
  challengeId,
  identity,
  keyId,
  nonce,
  signingKeys,
  privateKeyPem,
  type = "human",
  displayName = null
}) {
  const normalizedSigningKeys = [...signingKeys]
    .map((key) => ({
      key_id: String(key?.key_id || "").trim(),
      public_key_pem: String(key?.public_key_pem || "").trim()
    }))
    .sort((left, right) => left.key_id.localeCompare(right.key_id));
  const registrationDocument = {
    loom: "1.1",
    id: identity,
    type,
    display_name: displayName || identity,
    signing_keys: normalizedSigningKeys
  };
  const documentHash = createHash("sha256")
    .update(canonicalizeJson(registrationDocument), "utf-8")
    .digest("hex");
  const message = [
    "loom.identity.register.v1",
    identity,
    keyId,
    documentHash,
    nonce
  ].join("\n");

  return {
    challenge_id: challengeId,
    key_id: keyId,
    signature: signUtf8Message(privateKeyPem, message)
  };
}

function buildNodeSignedIdentityDocument({
  identity,
  signingKeys,
  nodeKeyId,
  nodePrivateKeyPem,
  type = "human",
  displayName = null
}) {
  const normalizedSigningKeys = [...(signingKeys || [])]
    .map((key) => ({
      key_id: String(key?.key_id || "").trim(),
      public_key_pem: String(key?.public_key_pem || "").trim()
    }))
    .sort((left, right) => left.key_id.localeCompare(right.key_id));

  const identityDocument = {
    loom: "1.1",
    id: identity,
    type,
    display_name: displayName || identity,
    signing_keys: normalizedSigningKeys
  };
  const signature = signUtf8Message(nodePrivateKeyPem, canonicalizeJson(identityDocument));

  return {
    ...identityDocument,
    node_signature: {
      algorithm: "Ed25519",
      key_id: nodeKeyId,
      value: signature
    }
  };
}

test("API serves LOOM live dashboard at root path", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const page = await textRequest(`${baseUrl}/`);
  assert.equal(page.response.status, 200);
  assert.match(page.response.headers.get("content-type") || "", /text\/html/i);
  assert.match(page.body, /LOOM Live Console/);
});

test("API can serve over native TLS HTTP/2", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    nativeTlsEnabled: true,
    nativeTlsKeyPem: TEST_TLS_KEY_PEM,
    nativeTlsCertPem: TEST_TLS_CERT_PEM
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const client = connectHttp2(`https://127.0.0.1:${address.port}`, {
    rejectUnauthorized: false
  });
  t.after(() => {
    client.close();
  });

  const response = await new Promise((resolve, reject) => {
    const request = client.request({
      ":method": "GET",
      ":path": "/health"
    });
    let headers = null;
    let body = "";
    request.setEncoding("utf-8");
    request.on("response", (value) => {
      headers = value;
    });
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("error", reject);
    request.on("end", () => {
      resolve({
        headers,
        body
      });
    });
    request.end();
  });

  assert.equal(response.headers[":status"], 200);
  const parsedBody = JSON.parse(response.body);
  assert.equal(parsedBody.ok, true);
  assert.equal(parsedBody.service, "loom-mvn");
});

test("API node document advertises identity resolve URL", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const aliceKeys = generateSigningKeyPair();

  const nodeDocument = await jsonRequest(`${baseUrl}/.well-known/loom.json`);
  assert.equal(nodeDocument.response.status, 200);
  assert.equal(nodeDocument.body.identity_resolve_url, "https://127.0.0.1/v1/identity/{identity}");
  assert.equal(
    nodeDocument.body?.federation?.identity_resolve_url,
    "https://127.0.0.1/v1/identity/{identity}"
  );

  const registerAlice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_node_doc_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAlice.response.status, 201);

  const identity = await jsonRequest(`${baseUrl}/v1/identity/${encodeURIComponent("loom://alice@node.test")}`);
  assert.equal(identity.response.status, 200);
  assert.equal(identity.body.id, "loom://alice@node.test");
  assert.equal(identity.body.node_signature?.algorithm, "Ed25519");
  assert.equal(identity.body.node_signature?.key_id, "k_node_sign_local_1");
  assert.equal(typeof identity.body.node_signature?.value, "string");
});

test("API rejects request bodies larger than configured max", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    maxBodyBytes: 128
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const oversizedIdentity = {
    id: "loom://alice@node.test",
    display_name: "A".repeat(500),
    signing_keys: [
      {
        key_id: "k_sign_alice_1",
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----\n"
      }
    ]
  };

  const result = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify(oversizedIdentity)
  });

  assert.equal(result.response.status, 413);
  assert.equal(result.body.error.code, "PAYLOAD_TOO_LARGE");
});

test("API can disable public identity signup", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret",
    identitySignupEnabled: false
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const payload = {
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
  };

  const denied = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
  assert.equal(denied.response.status, 403);
  assert.equal(denied.body.error.code, "CAPABILITY_DENIED");

  const allowed = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(allowed.response.status, 201);
  assert.equal(allowed.body.id, payload.id);
});

test("API enforces local-domain identity registration and gated remote imports", async (t) => {
  const keys = generateSigningKeyPair();
  const remoteKeys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const localIdentity = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_local_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(localIdentity.response.status, 201);

  const remoteDenied = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_import_1", public_key_pem: remoteKeys.publicKeyPem }]
    })
  });
  assert.equal(remoteDenied.response.status, 403);
  assert.equal(remoteDenied.body.error.code, "CAPABILITY_DENIED");

  const remoteAllowed = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret"
    },
    body: JSON.stringify({
      id: "loom://alice@remote.test",
      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_import_1", public_key_pem: remoteKeys.publicKeyPem }]
    })
  });
  assert.equal(remoteAllowed.response.status, 201);
  assert.equal(remoteAllowed.body.id, "loom://alice@remote.test");
});

test("API rejects reserved/system signing key ids during identity registration", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const reserved = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_system_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(reserved.response.status, 400);
  assert.equal(reserved.body.error.code, "ENVELOPE_INVALID");
});

test("API rejects cross-identity key_id reuse during identity registration", async (t) => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const alice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_shared_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(alice.response.status, 201);

  const bob = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://bob@node.test",
      display_name: "Bob",
      signing_keys: [{ key_id: "k_sign_shared_1", public_key_pem: bobKeys.publicKeyPem }]
    })
  });
  assert.equal(bob.response.status, 400);
  assert.equal(bob.body.error.code, "ENVELOPE_INVALID");
});

test("API can require proof-of-key for identity registration", async (t) => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    identityRequireProof: true
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const challenge = await jsonRequest(`${baseUrl}/v1/identity/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_proof_1"
    })
  });
  assert.equal(challenge.response.status, 200, JSON.stringify(challenge.body));

  const missingProof = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_proof_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(missingProof.response.status, 401);
  assert.equal(missingProof.body.error.code, "SIGNATURE_INVALID");

  const badProof = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_proof_1", public_key_pem: aliceKeys.publicKeyPem }],
      registration_proof: {
        challenge_id: challenge.body.challenge_id,
        key_id: "k_sign_alice_proof_1",
        signature: signUtf8Message(aliceKeys.privateKeyPem, "wrong-message")
      }
    })
  });
  assert.equal(badProof.response.status, 401);
  assert.equal(badProof.body.error.code, "SIGNATURE_INVALID");

  const goodProof = buildIdentityRegistrationProof({
    challengeId: challenge.body.challenge_id,
    identity: "loom://alice@node.test",
    keyId: "k_sign_alice_proof_1",
    nonce: challenge.body.nonce,
    signingKeys: [{ key_id: "k_sign_alice_proof_1", public_key_pem: aliceKeys.publicKeyPem }],
    privateKeyPem: aliceKeys.privateKeyPem,
    displayName: "Alice"
  });
  const registered = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_proof_1", public_key_pem: aliceKeys.publicKeyPem }],
      registration_proof: goodProof
    })
  });
  assert.equal(registered.response.status, 201, JSON.stringify(registered.body));

  const reusedProof = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://bob@node.test",
      display_name: "Bob",
      signing_keys: [{ key_id: "k_sign_bob_proof_1", public_key_pem: bobKeys.publicKeyPem }],
      registration_proof: {
        ...goodProof,
        key_id: "k_sign_bob_proof_1"
      }
    })
  });
  assert.equal(reusedProof.response.status, 401);
  assert.equal(reusedProof.body.error.code, "SIGNATURE_INVALID");
});

test("API supports owner-authenticated identity key rotation and blocks non-owner updates", async (t) => {
  const aliceKey1 = generateSigningKeyPair();
  const aliceKey2 = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const registerAlice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_rotate_1", public_key_pem: aliceKey1.publicKeyPem }]
    })
  });
  assert.equal(registerAlice.response.status, 201);

  const registerBob = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://bob@node.test",
      display_name: "Bob",
      signing_keys: [{ key_id: "k_sign_bob_rotate_1", public_key_pem: bobKeys.publicKeyPem }]
    })
  });
  assert.equal(registerBob.response.status, 201);

  const challengeAlice = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_rotate_1"
    })
  });
  assert.equal(challengeAlice.response.status, 200);

  const tokenAlice = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_rotate_1",
      challenge_id: challengeAlice.body.challenge_id,
      signature: signUtf8Message(aliceKey1.privateKeyPem, challengeAlice.body.nonce)
    })
  });
  assert.equal(tokenAlice.response.status, 200);

  const challengeBob = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://bob@node.test",
      key_id: "k_sign_bob_rotate_1"
    })
  });
  assert.equal(challengeBob.response.status, 200);

  const tokenBob = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://bob@node.test",
      key_id: "k_sign_bob_rotate_1",
      challenge_id: challengeBob.body.challenge_id,
      signature: signUtf8Message(bobKeys.privateKeyPem, challengeBob.body.nonce)
    })
  });
  assert.equal(tokenBob.response.status, 200);

  const deniedPatch = await jsonRequest(`${baseUrl}/v1/identity/${encodeURIComponent("loom://alice@node.test")}`, {
    method: "PATCH",
    headers: {
      authorization: `Bearer ${tokenBob.body.access_token}`
    },
    body: JSON.stringify({
      display_name: "Not Allowed"
    })
  });
  assert.equal(deniedPatch.response.status, 403);
  assert.equal(deniedPatch.body.error.code, "CAPABILITY_DENIED");

  const rotated = await jsonRequest(`${baseUrl}/v1/identity/${encodeURIComponent("loom://alice@node.test")}`, {
    method: "PATCH",
    headers: {
      authorization: `Bearer ${tokenAlice.body.access_token}`
    },
    body: JSON.stringify({
      display_name: "Alice Rotated",
      signing_keys: [
        { key_id: "k_sign_alice_rotate_1", public_key_pem: aliceKey1.publicKeyPem },
        { key_id: "k_sign_alice_rotate_2", public_key_pem: aliceKey2.publicKeyPem }
      ]
    })
  });
  assert.equal(rotated.response.status, 200, JSON.stringify(rotated.body));
  assert.equal(rotated.body.display_name, "Alice Rotated");
  assert.equal(rotated.body.signing_keys.length, 2);

  const challengeWithNewKey = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_rotate_2"
    })
  });
  assert.equal(challengeWithNewKey.response.status, 200);
});

test("API blocks auth challenge for imported remote identities", async (t) => {
  const remoteKeys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const imported = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret"
    },
    body: JSON.stringify({
      id: "loom://alice@remote.test",
      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_auth_block_1", public_key_pem: remoteKeys.publicKeyPem }]
    })
  });
  assert.equal(imported.response.status, 201);

  const remoteChallenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@remote.test",
      key_id: "k_sign_remote_auth_block_1"
    })
  });
  assert.equal(remoteChallenge.response.status, 403);
  assert.equal(remoteChallenge.body.error.code, "CAPABILITY_DENIED");
});

test("API can disable bridge and gateway send routes", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    bridgeInboundEnabled: false,
    bridgeSendEnabled: false,
    gatewaySmtpSubmitEnabled: false
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    body: JSON.stringify({})
  });
  assert.equal(inbound.response.status, 404);
  assert.equal(inbound.body.error.code, "ENVELOPE_NOT_FOUND");

  const directSend = await jsonRequest(`${baseUrl}/v1/bridge/email/send`, {
    method: "POST",
    body: JSON.stringify({})
  });
  assert.equal(directSend.response.status, 404);
  assert.equal(directSend.body.error.code, "ENVELOPE_NOT_FOUND");

  const smtpSubmit = await jsonRequest(`${baseUrl}/v1/gateway/smtp/submit`, {
    method: "POST",
    body: JSON.stringify({})
  });
  assert.equal(smtpSubmit.response.status, 404);
  assert.equal(smtpSubmit.body.error.code, "ENVELOPE_NOT_FOUND");
});

test("API enforces rate limit on sensitive auth routes", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 1000,
    rateLimitSensitiveMax: 3
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const first = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(first.response.status, 200);

  const second = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(second.response.status, 200);

  const third = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(third.response.status, 429);
  assert.equal(third.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(third.body.error.details.scope, "sensitive");
});

test("API enforces per-identity rate limit in addition to per-IP limits", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 10_000,
    rateLimitSensitiveMax: 10_000,
    identityRateWindowMs: 60_000,
    identityRateDefaultMax: 2,
    identityRateSensitiveMax: 2
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_idrl_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_idrl_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_idrl_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const first = await jsonRequest(`${baseUrl}/v1/threads`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(first.response.status, 200);

  const second = await jsonRequest(`${baseUrl}/v1/threads`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(second.response.status, 200);

  const third = await jsonRequest(`${baseUrl}/v1/threads`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(third.response.status, 429);
  assert.equal(third.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(third.body.error.details.scope, "identity:default");
});

test("API enforces per-identity daily envelope quota", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    envelopeDailyMax: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_quota_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_quota_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_quota_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const firstEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G6Q10",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G6Q11",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_quota_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T21:00:00Z",
      priority: "normal",
      content: {
        human: { text: "first", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_quota_1"
  );

  const firstSend = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify(firstEnvelope)
  });
  assert.equal(firstSend.response.status, 201);

  const secondEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G6Q12",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G6Q13",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_quota_1",
        type: "human"
      },
      to: [{ identity: "loom://carol@node.test", role: "primary" }],
      created_at: "2026-02-16T21:01:00Z",
      priority: "normal",
      content: {
        human: { text: "second", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_quota_1"
  );

  const secondSend = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify(secondEnvelope)
  });
  assert.equal(secondSend.response.status, 429);
  assert.equal(secondSend.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(secondSend.body.error.details.scope, "identity:envelope_daily");
});

test("API enforces thread recipient fanout cap", async (t) => {
  const keys = generateSigningKeyPair();
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    threadRecipientFanoutMax: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_fanout_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_fanout_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_fanout_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G6Q14",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G6Q15",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_fanout_1",
        type: "human"
      },
      to: [
        { identity: "loom://bob@node.test", role: "primary" },
        { identity: "loom://carol@node.test", role: "cc" }
      ],
      created_at: "2026-02-16T21:10:00Z",
      priority: "normal",
      content: {
        human: { text: "fanout", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_fanout_1"
  );

  const send = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(send.response.status, 413);
  assert.equal(send.body.error.code, "PAYLOAD_TOO_LARGE");
});

test("API does not trust x-forwarded-for for rate limit buckets by default", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 1000,
    rateLimitSensitiveMax: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const payload = {
    identity: "loom://missing@node.test",
    key_id: "k_missing_1"
  };

  const first = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "198.51.100.10"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(first.response.status, 404);

  const second = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "203.0.113.44"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(second.response.status, 429);
  assert.equal(second.body.error.code, "RATE_LIMIT_EXCEEDED");
});

test("API can trust x-forwarded-for when explicitly enabled", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 1000,
    rateLimitSensitiveMax: 1,
    trustProxy: true
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const payload = {
    identity: "loom://missing@node.test",
    key_id: "k_missing_1"
  };

  const first = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "198.51.100.10"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(first.response.status, 404);

  const second = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "203.0.113.44"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(second.response.status, 404);
});

test("API trusts x-forwarded-for only when proxy source is allowlisted", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 1000,
    rateLimitSensitiveMax: 1,
    trustProxy: true,
    trustProxyAllowlist: "127.0.0.1/32"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const payload = {
    identity: "loom://missing@node.test",
    key_id: "k_missing_1"
  };

  const first = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "198.51.100.10"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(first.response.status, 404);

  const second = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "203.0.113.44"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(second.response.status, 404);
});

test("API ignores x-forwarded-for when proxy source is not allowlisted", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    rateLimitWindowMs: 60_000,
    rateLimitDefaultMax: 1000,
    rateLimitSensitiveMax: 1,
    trustProxy: true,
    trustProxyAllowlist: "198.51.100.0/24"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const payload = {
    identity: "loom://missing@node.test",
    key_id: "k_missing_1"
  };

  const first = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "198.51.100.10"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(first.response.status, 404);

  const second = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    headers: {
      "x-forwarded-for": "203.0.113.44"
    },
    body: JSON.stringify(payload)
  });
  assert.equal(second.response.status, 429);
  assert.equal(second.body.error.code, "RATE_LIMIT_EXCEEDED");
});

test("API rejects invalid trusted proxy allowlist configuration", () => {
  assert.throws(
    () =>
      createLoomServer({
        nodeId: "node.test",
        domain: "127.0.0.1",
        trustProxy: true,
        trustProxyAllowlist: "not-a-cidr"
      }),
    /LOOM_TRUST_PROXY_ALLOWLIST/
  );
});

test("API exposes readiness and protects admin operational endpoints", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token",
    runtimeStatusProvider: () => ({
      outbox_worker: {
        enabled: true,
        in_progress: false,
        runs_total: 3,
        last_processed_count: 1,
        last_error: null
      }
    })
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const ready = await jsonRequest(`${baseUrl}/ready`);
  assert.equal(ready.response.status, 200);
  assert.equal(ready.body.ok, true);
  assert.equal(ready.body.checks.http, "ok");

  const deniedStatus = await jsonRequest(`${baseUrl}/v1/admin/status`);
  assert.equal(deniedStatus.response.status, 403);
  assert.equal(deniedStatus.body.error.code, "CAPABILITY_DENIED");

  const adminStatus = await jsonRequest(`${baseUrl}/v1/admin/status`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(adminStatus.response.status, 200);
  assert.equal(adminStatus.body.service, "loom-mvn");
  assert.equal(typeof adminStatus.body.metrics.requests_total, "number");
  assert.equal(typeof adminStatus.body.outbox.federation.total, "number");
  assert.equal(typeof adminStatus.body.outbox.email.total, "number");
  assert.equal(typeof adminStatus.body.outbox.webhook.total, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.max_envelopes_per_delivery, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.rate_limit_window_ms, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.rate_limit_max, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.global_rate_limit_window_ms, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.global_rate_limit_max, "number");
  assert.equal(typeof adminStatus.body.federation_inbound_policy.require_signed_receipts, "boolean");
  assert.equal(typeof adminStatus.body.federation_guards.local.challenge_tokens_tracked, "number");
  assert.equal(typeof adminStatus.body.persistence_schema.backend, "string");

  const deniedMetrics = await jsonRequest(`${baseUrl}/metrics`);
  assert.equal(deniedMetrics.response.status, 403);
  assert.equal(deniedMetrics.body.error.code, "CAPABILITY_DENIED");

  const metrics = await textRequest(`${baseUrl}/metrics`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(metrics.response.status, 200);
  assert.match(metrics.response.headers.get("content-type") || "", /text\/plain/i);
  assert.match(metrics.body, /loom_requests_total/);
  assert.match(metrics.body, /loom_federation_outbox_total/);
});

test("API enforces auth for envelope submission and supports proof-of-key login", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });

  assert.equal(register.response.status, 201);

  const unsignedEnvelope = {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD0",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FD1",
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-16T20:20:00Z",
    priority: "normal",
    content: {
      human: { text: "auth test", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: []
  };

  const envelope = signEnvelope(unsignedEnvelope, keys.privateKeyPem, "k_sign_alice_1");

  const unauthenticatedSend = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    body: JSON.stringify(envelope)
  });

  assert.equal(unauthenticatedSend.response.status, 401);
  assert.equal(unauthenticatedSend.body.error.code, "SIGNATURE_INVALID");

  const challengeResult = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });

  assert.equal(challengeResult.response.status, 200);

  const challengeSignature = signUtf8Message(keys.privateKeyPem, challengeResult.body.nonce);

  const tokenResult = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challengeResult.body.challenge_id,
      signature: challengeSignature
    })
  });

  assert.equal(tokenResult.response.status, 200);
  assert.equal(tokenResult.body.token_type, "Bearer");

  const authenticatedSend = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    },
    body: JSON.stringify(envelope)
  });

  assert.equal(authenticatedSend.response.status, 201);
  assert.equal(authenticatedSend.body.meta.event_seq, 1);

  const unauthorizedSearch = await jsonRequest(`${baseUrl}/v1/search?q=auth`);
  assert.equal(unauthorizedSearch.response.status, 401);

  const authorizedSearch = await jsonRequest(`${baseUrl}/v1/search?q=auth`, {
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    }
  });
  assert.equal(authorizedSearch.response.status, 200);
  assert.equal(authorizedSearch.body.total, 1);
  assert.equal(authorizedSearch.body.results[0].envelope_id, envelope.id);

  const unauthorizedAudit = await jsonRequest(`${baseUrl}/v1/audit?limit=5`);
  assert.equal(unauthorizedAudit.response.status, 401);

  const authorizedAudit = await jsonRequest(`${baseUrl}/v1/audit?limit=5`, {
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    }
  });
  assert.equal(authorizedAudit.response.status, 200);
  assert.equal(Array.isArray(authorizedAudit.body.entries), true);
  assert.equal(authorizedAudit.body.entries.length > 0, true);

  const threadOpEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FD2",
      thread_id: envelope.thread_id,
      parent_id: envelope.id,
      type: "thread_op",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:21:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_1"
  );

  const opResponse = await jsonRequest(`${baseUrl}/v1/threads/${envelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    },
    body: JSON.stringify(threadOpEnvelope)
  });

  assert.equal(opResponse.response.status, 201);

  const threadResponse = await jsonRequest(`${baseUrl}/v1/threads/${envelope.thread_id}`, {
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    }
  });
  assert.equal(threadResponse.response.status, 200);
  assert.equal(threadResponse.body.state, "resolved");
});

test("API requires authentication for thread and envelope reads by default", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();

  const registerAlice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_read_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAlice.response.status, 201);

  const registerBob = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://bob@node.test",
      display_name: "Bob",
      signing_keys: [{ key_id: "k_sign_bob_read_1", public_key_pem: bobKeys.publicKeyPem }]
    })
  });
  assert.equal(registerBob.response.status, 201);

  const challengeAlice = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_read_1"
    })
  });
  assert.equal(challengeAlice.response.status, 200);

  const tokenAlice = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_read_1",
      challenge_id: challengeAlice.body.challenge_id,
      signature: signUtf8Message(aliceKeys.privateKeyPem, challengeAlice.body.nonce)
    })
  });
  assert.equal(tokenAlice.response.status, 200);

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5R11",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5R12",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_read_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T20:25:00Z",
      priority: "normal",
      content: {
        human: { text: "private read route", format: "markdown" },
        structured: {
          intent: "message.general@v1",
          parameters: {}
        },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_read_1"
  );

  const sendEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokenAlice.body.access_token}`
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(sendEnvelope.response.status, 201, JSON.stringify(sendEnvelope.body));

  const unauthEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${envelope.id}`);
  assert.equal(unauthEnvelope.response.status, 401);

  const unauthThread = await jsonRequest(`${baseUrl}/v1/threads/${envelope.thread_id}`);
  assert.equal(unauthThread.response.status, 401);
});

test("API supports delegation create/list/revoke for authenticated delegator", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const ownerKeys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://owner@node.test",
      display_name: "Owner",
      signing_keys: [{ key_id: "k_sign_owner_1", public_key_pem: ownerKeys.publicKeyPem }]
    })
  });

  assert.equal(register.response.status, 201);

  const challengeResult = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://owner@node.test",
      key_id: "k_sign_owner_1"
    })
  });
  assert.equal(challengeResult.response.status, 200);

  const challengeSignature = signUtf8Message(ownerKeys.privateKeyPem, challengeResult.body.nonce);
  const tokenResult = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://owner@node.test",
      key_id: "k_sign_owner_1",
      challenge_id: challengeResult.body.challenge_id,
      signature: challengeSignature
    })
  });
  assert.equal(tokenResult.response.status, 200);

  const delegationWithoutSignature = {
    id: "dlg_01ARZ3NDEKTSV4RRFFQ69G5FE5",
    delegator: "loom://owner@node.test",
    delegate: "loom://assistant.owner@node.test",
    scope: ["message.general@v1"],
    created_at: "2026-02-16T20:40:00Z",
    expires_at: "2027-02-16T20:40:00Z",
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_owner_1"
  };

  const delegationPayload = {
    ...delegationWithoutSignature,
    signature: signUtf8Message(
      ownerKeys.privateKeyPem,
      canonicalizeDelegationLink(delegationWithoutSignature)
    )
  };

  const createDelegation = await jsonRequest(`${baseUrl}/v1/delegations`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    },
    body: JSON.stringify(delegationPayload)
  });
  assert.equal(createDelegation.response.status, 201);

  const listDelegations = await jsonRequest(`${baseUrl}/v1/delegations`, {
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    }
  });
  assert.equal(listDelegations.response.status, 200);
  assert.equal(listDelegations.body.delegations.length, 1);

  const revokeDelegation = await jsonRequest(`${baseUrl}/v1/delegations/${delegationPayload.id}`, {
    method: "DELETE",
    headers: {
      authorization: `Bearer ${tokenResult.body.access_token}`
    }
  });
  assert.equal(revokeDelegation.response.status, 200);
  assert.equal(revokeDelegation.body.revoked, true);
});

test("API supports blob create/upload/complete/download", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const rootEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FF0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FF1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T20:50:00Z",
      priority: "normal",
      content: {
        human: { text: "blob thread", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_1"
  );

  const sendEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify(rootEnvelope)
  });
  assert.equal(sendEnvelope.response.status, 201);

  const createBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      thread_id: rootEnvelope.thread_id,
      filename: "note.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(createBlob.response.status, 201);
  const blobId = createBlob.body.blob_id;

  const putPart = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("hello blob", "utf-8").toString("base64")
    })
  });
  assert.equal(putPart.response.status, 200);

  const completeBlob = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({})
  });
  assert.equal(completeBlob.response.status, 200);
  assert.equal(completeBlob.body.status, "complete");

  const getBlob = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(getBlob.response.status, 200);
  assert.equal(Buffer.from(getBlob.body.data_base64, "base64").toString("utf-8"), "hello blob");
});

test("API enforces blob part size and count limits", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    blobMaxBytes: 8,
    blobMaxPartBytes: 4,
    blobMaxParts: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_blob_limit_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_limit_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_limit_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const createBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "limit.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(createBlob.response.status, 201);
  const blobId = createBlob.body.blob_id;

  const oversizedPart = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("hello", "utf-8").toString("base64")
    })
  });
  assert.equal(oversizedPart.response.status, 413);
  assert.equal(oversizedPart.body.error.code, "PAYLOAD_TOO_LARGE");

  const firstPart = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("abcd", "utf-8").toString("base64")
    })
  });
  assert.equal(firstPart.response.status, 200);

  const secondPart = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/parts/2`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("ef", "utf-8").toString("base64")
    })
  });
  assert.equal(secondPart.response.status, 413);
  assert.equal(secondPart.body.error.code, "PAYLOAD_TOO_LARGE");
});

test("API enforces per-identity blob daily count quota", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    blobDailyCountMax: 1,
    blobIdentityTotalBytesMax: 4
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_blob_quota_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const createBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "quota.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(createBlob.response.status, 201);
  const blobId = createBlob.body.blob_id;

  const firstCreate = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "count-limit.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(firstCreate.response.status, 429);
  assert.equal(firstCreate.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(firstCreate.body.error.details.scope, "identity:blob_daily_count");

  const firstPart = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("abcd", "utf-8").toString("base64")
    })
  });
  assert.equal(firstPart.response.status, 200);

  const firstComplete = await jsonRequest(`${baseUrl}/v1/blobs/${blobId}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(firstComplete.response.status, 200);

  const secondBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "total-limit.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(secondBlob.response.status, 429);
  assert.equal(secondBlob.body.error.details.scope, "identity:blob_daily_count");
});

test("API enforces per-identity daily blob byte quota on complete", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    blobDailyCountMax: 10,
    blobDailyBytesMax: 4,
    blobIdentityTotalBytesMax: 100
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_blob_quota_3", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_3"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_3",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const firstBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "first-daily-bytes.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(firstBlob.response.status, 201);

  const firstPart = await jsonRequest(`${baseUrl}/v1/blobs/${firstBlob.body.blob_id}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("abcd", "utf-8").toString("base64")
    })
  });
  assert.equal(firstPart.response.status, 200);

  const firstComplete = await jsonRequest(`${baseUrl}/v1/blobs/${firstBlob.body.blob_id}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(firstComplete.response.status, 200);

  const secondBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "second-daily-bytes.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(secondBlob.response.status, 201);

  const secondPart = await jsonRequest(`${baseUrl}/v1/blobs/${secondBlob.body.blob_id}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("a", "utf-8").toString("base64")
    })
  });
  assert.equal(secondPart.response.status, 200);

  const secondComplete = await jsonRequest(`${baseUrl}/v1/blobs/${secondBlob.body.blob_id}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(secondComplete.response.status, 429);
  assert.equal(secondComplete.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(secondComplete.body.error.details.scope, "identity:blob_daily_bytes");
});

test("API enforces per-identity total blob byte quota on complete", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    blobDailyCountMax: 10,
    blobIdentityTotalBytesMax: 4
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_blob_quota_2", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_2"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_blob_quota_2",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const firstBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "first.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(firstBlob.response.status, 201);

  const firstPart = await jsonRequest(`${baseUrl}/v1/blobs/${firstBlob.body.blob_id}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("abcd", "utf-8").toString("base64")
    })
  });
  assert.equal(firstPart.response.status, 200);

  const firstComplete = await jsonRequest(`${baseUrl}/v1/blobs/${firstBlob.body.blob_id}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(firstComplete.response.status, 200);

  const secondBlob = await jsonRequest(`${baseUrl}/v1/blobs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      filename: "second.txt",
      mime_type: "text/plain"
    })
  });
  assert.equal(secondBlob.response.status, 201);

  const secondPart = await jsonRequest(`${baseUrl}/v1/blobs/${secondBlob.body.blob_id}/parts/1`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      data_base64: Buffer.from("a", "utf-8").toString("base64")
    })
  });
  assert.equal(secondPart.response.status, 200);

  const secondComplete = await jsonRequest(`${baseUrl}/v1/blobs/${secondBlob.body.blob_id}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(secondComplete.response.status, 429);
  assert.equal(secondComplete.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(secondComplete.body.error.details.scope, "identity:blob_total_bytes");
});

test("API accepts signed federation delivery from trusted node", async (t) => {
  const { server, store } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeysPrimary = generateSigningKeyPair();
  const remoteNodeKeysSecondary = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  const registerAdmin = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAdmin.response.status, 201);

  const registerRemoteSender = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });
  assert.equal(registerRemoteSender.response.status, 201);

  const adminChallenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });
  assert.equal(adminChallenge.response.status, 200);

  const adminToken = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: adminChallenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, adminChallenge.body.nonce)
    })
  });
  assert.equal(adminToken.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${adminToken.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeysPrimary.publicKeyPem,
      signing_keys: [
        {
          key_id: "k_node_sign_remote_1",
          public_key_pem: remoteNodeKeysPrimary.publicKeyPem
        },
        {
          key_id: "k_node_sign_remote_2",
          public_key_pem: remoteNodeKeysSecondary.publicKeyPem
        }
      ]
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FG1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:10:00Z",
      priority: "normal",
      content: {
        human: { text: "Federated hello", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };

  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeysSecondary.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_2",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 202, JSON.stringify(deliver.body));
  assert.equal(deliver.body.accepted_count, 1);

  const getEnvelope = store.getEnvelope(remoteEnvelope.id);
  assert.equal(getEnvelope.id, remoteEnvelope.id);
});

test("API auto-resolves remote sender identity during federation delivery", async (t) => {
  const { server, store } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const remoteSenderKeys = generateSigningKeyPair();
  let identityResolveHits = 0;
  const remoteIdentityServer = createHttpServer((req, res) => {
    const expectedPath = `/identity/resolve?identity=${encodeURIComponent("loom://alice@remote.test")}`;
    if (req.method === "GET" && req.url === expectedPath) {
      identityResolveHits += 1;
      const payload = buildNodeSignedIdentityDocument({
        identity: "loom://alice@remote.test",
        displayName: "Remote Alice",
        signingKeys: [{ key_id: "k_sign_remote_alice_auto_1", public_key_pem: remoteSenderKeys.publicKeyPem }],
        nodeKeyId: "k_node_sign_remote_auto_1",
        nodePrivateKeyPem: remoteNodeKeys.privateKeyPem
      });
      const body = JSON.stringify(payload);
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body).toString()
      });
      res.end(body);
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve) => remoteIdentityServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteIdentityServer.close(resolve)));
  const remoteAddress = remoteIdentityServer.address();
  const remoteBaseUrl = `http://127.0.0.1:${remoteAddress.port}`;

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();

  const registerAdmin = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_auto_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAdmin.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_auto_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_auto_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_auto_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
      identity_resolve_url: `${remoteBaseUrl}/identity/resolve?identity={identity}`,
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(trustNode.response.status, 201, JSON.stringify(trustNode.body));

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FHB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_auto_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:00:00Z",
      priority: "normal",
      content: {
        human: { text: "Auto-resolved identity", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_auto_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_auto_identity_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_auto_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 202, JSON.stringify(deliver.body));
  assert.equal(deliver.body.accepted_count, 1);

  const remoteIdentity = store.resolveIdentity("loom://alice@remote.test");
  assert.equal(remoteIdentity?.id, "loom://alice@remote.test");
  assert.equal(remoteIdentity?.imported_remote, true);
  assert.equal(identityResolveHits, 1);
});

test("API rejects unsigned remote identity documents during federation auto-resolve by default", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const remoteSenderKeys = generateSigningKeyPair();
  const remoteIdentityServer = createHttpServer((req, res) => {
    const expectedPath = `/v1/identity/${encodeURIComponent("loom://alice@remote.test")}`;
    if (req.method === "GET" && req.url === expectedPath) {
      const payload = {
        id: "loom://alice@remote.test",
        display_name: "Remote Alice",
        signing_keys: [{ key_id: "k_sign_remote_alice_unsigned_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
      };
      const body = JSON.stringify(payload);
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body).toString()
      });
      res.end(body);
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve) => remoteIdentityServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteIdentityServer.close(resolve)));
  const remoteAddress = remoteIdentityServer.address();
  const remoteBaseUrl = `http://127.0.0.1:${remoteAddress.port}`;

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_unsigned_identity_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_unsigned_identity_1"
    })
  });
  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_unsigned_identity_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_unsigned_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(trustNode.response.status, 201, JSON.stringify(trustNode.body));

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHG",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FHH",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_unsigned_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:00:30Z",
      priority: "normal",
      content: {
        human: { text: "Unsigned identity document should fail", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_unsigned_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_auto_identity_unsigned_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_unsigned_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 401);
  assert.equal(deliver.body.error.code, "SIGNATURE_INVALID");
});

test("API can disable signed remote identity requirement for federation auto-resolve compatibility", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationRequireSignedRemoteIdentity: false
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const remoteSenderKeys = generateSigningKeyPair();
  const remoteIdentityServer = createHttpServer((req, res) => {
    const expectedPath = `/v1/identity/${encodeURIComponent("loom://alice@remote.test")}`;
    if (req.method === "GET" && req.url === expectedPath) {
      const payload = {
        id: "loom://alice@remote.test",
        display_name: "Remote Alice",
        signing_keys: [{ key_id: "k_sign_remote_alice_compat_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
      };
      const body = JSON.stringify(payload);
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body).toString()
      });
      res.end(body);
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve) => remoteIdentityServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteIdentityServer.close(resolve)));
  const remoteAddress = remoteIdentityServer.address();
  const remoteBaseUrl = `http://127.0.0.1:${remoteAddress.port}`;

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_compat_identity_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_compat_identity_1"
    })
  });
  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_compat_identity_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_compat_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(trustNode.response.status, 201, JSON.stringify(trustNode.body));

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHK",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FHM",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_compat_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:00:45Z",
      priority: "normal",
      content: {
        human: { text: "Unsigned identity document accepted in compatibility mode", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_compat_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_auto_identity_compat_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_compat_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 202, JSON.stringify(deliver.body));
  assert.equal(deliver.body.accepted_count, 1);
});

test("API enforces remote identity host allowlist during federation auto-resolve", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    remoteIdentityHostAllowlist: ["identity.allowed.test"]
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_auto_allowlist_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_auto_allowlist_1"
    })
  });
  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_auto_allowlist_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_auto_allowlist_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      deliver_url: "http://127.0.0.1:34343/v1/federation/deliver",
      identity_resolve_url: "http://127.0.0.1:34343/v1/identity/{identity}",
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(trustNode.response.status, 201, JSON.stringify(trustNode.body));

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHE",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FHF",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_auto_allowlist_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:01:00Z",
      priority: "normal",
      content: {
        human: { text: "Auto-resolve host allowlist", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_auto_allowlist_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_auto_identity_allowlist_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_auto_allowlist_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 403);
  assert.equal(deliver.body.error.code, "CAPABILITY_DENIED");
});

test("API rejects federated envelopes whose sender identity domain mismatches sender node", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_domain_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_domain_1"
    })
  });
  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_domain_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_domain_1",
      public_key_pem: remoteNodeKeys.publicKeyPem
    })
  });
  assert.equal(trustNode.response.status, 201);

  const mismatchedEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHC",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FHD",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@other.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_mismatch_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:02:00Z",
      priority: "normal",
      content: {
        human: { text: "mismatch domain", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_mismatch_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [mismatchedEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_domain_mismatch_1";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_domain_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 401);
  assert.equal(deliver.body.error.code, "SIGNATURE_INVALID");
});

test("API rejects inbound federation when node policy is deny", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "deny"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG2",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FG3",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:15:00Z",
      priority: "normal",
      content: {
        human: { text: "should be denied", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };

  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_deny";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });

  assert.equal(deliver.response.status, 403);
  assert.equal(deliver.body.error.code, "CAPABILITY_DENIED");
});

test("API marks inbound federation threads as quarantined when node policy is quarantine", async (t) => {
  const { server, store } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "quarantine"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FG4",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FG5",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:16:00Z",
      priority: "normal",
      content: {
        human: { text: "should be quarantined", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };

  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_quarantine";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });

  assert.equal(deliver.response.status, 202);

  const thread = store.getThread(remoteEnvelope.thread_id);
  assert.equal(thread.labels.includes("sys.quarantine"), true);
});

test("API rejects inbound federation delivery when envelope batch exceeds configured max", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationInboundMaxEnvelopes: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelopeA = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FGA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FGB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:17:00Z",
      priority: "normal",
      content: {
        human: { text: "batch item A", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const remoteEnvelopeB = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FGC",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FGD",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:17:30Z",
      priority: "normal",
      content: {
        human: { text: "batch item B", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelopeA, remoteEnvelopeB]
  };

  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_batch_limit";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 413);
  assert.equal(deliver.body.error.code, "PAYLOAD_TOO_LARGE");
});

test("API rate-limits inbound federation requests per trusted node", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationNodeRateWindowMs: 60_000,
    federationNodeRateMax: 1
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelopeA = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FGE",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FGF",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:18:00Z",
      priority: "normal",
      content: {
        human: { text: "rate item A", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const remoteEnvelopeB = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FGG",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FGH",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:18:30Z",
      priority: "normal",
      content: {
        human: { text: "rate item B", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  function signDeliveryRequest(rawBody, nonce) {
    const timestamp = new Date().toISOString();
    const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
    const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
    return {
      timestamp,
      signature: signUtf8Message(remoteNodeKeys.privateKeyPem, canonical)
    };
  }

  const wrapperA = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelopeA]
  };
  const rawBodyA = JSON.stringify(wrapperA);
  const signedA = signDeliveryRequest(rawBodyA, "nonce_test_federation_rate_a");
  const firstDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": signedA.timestamp,
      "x-loom-nonce": "nonce_test_federation_rate_a",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": signedA.signature
    },
    body: rawBodyA
  });
  assert.equal(firstDeliver.response.status, 202);

  const wrapperB = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelopeB]
  };
  const rawBodyB = JSON.stringify(wrapperB);
  const signedB = signDeliveryRequest(rawBodyB, "nonce_test_federation_rate_b");
  const secondDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": signedB.timestamp,
      "x-loom-nonce": "nonce_test_federation_rate_b",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": signedB.signature
    },
    body: rawBodyB
  });
  assert.equal(secondDeliver.response.status, 429);
  assert.equal(secondDeliver.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(secondDeliver.body.error.details.scope, "federation_node");
});

test("API auto-quarantines federation node after repeated failed inbound verification", async (t) => {
  const { server, store } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationAbuseQuarantineThreshold: 1,
    federationAbuseDenyThreshold: 50,
    federationAutoPolicyDurationMs: 60_000
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const badNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FH2",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FH3",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:19:00Z",
      priority: "normal",
      content: {
        human: { text: "auto quarantine", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };

  const rawBody = JSON.stringify(wrapper);
  const badTimestamp = new Date().toISOString();
  const badNonce = "nonce_test_federation_auto_quarantine_bad";
  const badBodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const badCanonical = `POST\n/v1/federation/deliver\n${badBodyHash}\n${badTimestamp}\n${badNonce}`;
  const badSignature = signUtf8Message(badNodeKeys.privateKeyPem, badCanonical);

  const badDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": badTimestamp,
      "x-loom-nonce": badNonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": badSignature
    },
    body: rawBody
  });
  assert.equal(badDeliver.response.status, 401);
  assert.equal(badDeliver.body.error.code, "SIGNATURE_INVALID");

  const goodTimestamp = new Date().toISOString();
  const goodNonce = "nonce_test_federation_auto_quarantine_good";
  const goodBodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const goodCanonical = `POST\n/v1/federation/deliver\n${goodBodyHash}\n${goodTimestamp}\n${goodNonce}`;
  const goodSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, goodCanonical);

  const goodDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": goodTimestamp,
      "x-loom-nonce": goodNonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": goodSignature
    },
    body: rawBody
  });
  assert.equal(goodDeliver.response.status, 202, JSON.stringify(goodDeliver.body));

  const thread = store.getThread(remoteEnvelope.thread_id);
  assert.equal(thread.labels.includes("sys.quarantine"), true);

  const nodes = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(nodes.response.status, 200);
  const remoteNode = nodes.body.nodes.find((node) => node.node_id === "remote.test");
  assert.equal(remoteNode.policy, "quarantine");
  assert.equal(remoteNode.auto_policy, "quarantine");
});

test("API auto-denies federation node after repeated failed inbound verification", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationAbuseQuarantineThreshold: 1,
    federationAbuseDenyThreshold: 2,
    federationAutoPolicyDurationMs: 60_000
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const badNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FH4",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FH5",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T21:20:00Z",
      priority: "normal",
      content: {
        human: { text: "auto deny", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);

  function badDelivery(nonce) {
    const timestamp = new Date().toISOString();
    const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
    const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
    const signature = signUtf8Message(badNodeKeys.privateKeyPem, canonical);
    return jsonRequest(`${baseUrl}/v1/federation/deliver`, {
      method: "POST",
      headers: {
        "x-loom-node": "remote.test",
        "x-loom-timestamp": timestamp,
        "x-loom-nonce": nonce,
        "x-loom-key-id": "k_node_sign_remote_1",
        "x-loom-signature": signature
      },
      body: rawBody
    });
  }

  const failA = await badDelivery("nonce_test_federation_auto_deny_a");
  assert.equal(failA.response.status, 401);
  assert.equal(failA.body.error.code, "SIGNATURE_INVALID");

  const failB = await badDelivery("nonce_test_federation_auto_deny_b");
  assert.equal(failB.response.status, 401);
  assert.equal(failB.body.error.code, "SIGNATURE_INVALID");

  const goodTimestamp = new Date().toISOString();
  const goodNonce = "nonce_test_federation_auto_deny_good";
  const goodBodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const goodCanonical = `POST\n/v1/federation/deliver\n${goodBodyHash}\n${goodTimestamp}\n${goodNonce}`;
  const goodSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, goodCanonical);

  const blocked = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": goodTimestamp,
      "x-loom-nonce": goodNonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": goodSignature
    },
    body: rawBody
  });
  assert.equal(blocked.response.status, 403);
  assert.equal(blocked.body.error.code, "CAPABILITY_DENIED");
  assert.equal(blocked.body.error.details.auto_policy, true);

  const nodes = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    }
  });
  assert.equal(nodes.response.status, 200);
  const remoteNode = nodes.body.nodes.find((node) => node.node_id === "remote.test");
  assert.equal(remoteNode.policy, "deny");
  assert.equal(remoteNode.auto_policy, "deny");
});

test("API processes outbound federation outbox and delivers to remote node", async (t) => {
  const localNodeSigningKeys = generateSigningKeyPair();
  const remoteNodeSigningKeysPrimary = generateSigningKeyPair();
  const remoteNodeSigningKeysSecondary = generateSigningKeyPair();

  const { server: remoteServer, store: remoteStore } = createLoomServer({
    nodeId: "remote.test",
    domain: "127.0.0.1",
    federationSigningKeyId: "k_node_sign_remote_2",
    federationSigningPrivateKeyPem: remoteNodeSigningKeysSecondary.privateKeyPem
  });
  await new Promise((resolve) => remoteServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteServer.close(resolve)));
  const remoteAddress = remoteServer.address();
  const remoteBaseUrl = `http://127.0.0.1:${remoteAddress.port}`;

  const { server: localServer } = createLoomServer({
    nodeId: "local.test",
    domain: "127.0.0.1",
    federationSigningKeyId: "k_node_sign_local_1",
    federationSigningPrivateKeyPem: localNodeSigningKeys.privateKeyPem
  });
  await new Promise((resolve) => localServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => localServer.close(resolve)));
  const localAddress = localServer.address();
  const localBaseUrl = `http://127.0.0.1:${localAddress.port}`;

  const localAdminKeys = generateSigningKeyPair();
  const localSenderKeys = generateSigningKeyPair();
  const remoteAdminKeys = generateSigningKeyPair();

  async function registerAndAuth(baseUrl, identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const localAdminToken = await registerAndAuth(
    localBaseUrl,
    "loom://admin@local.test",
    "k_sign_local_admin_1",
    localAdminKeys
  );
  const localSenderToken = await registerAndAuth(
    localBaseUrl,
    "loom://alice@local.test",
    "k_sign_local_sender_1",
    localSenderKeys
  );
  const remoteAdminToken = await registerAndAuth(
    remoteBaseUrl,
    "loom://admin@remote.test",
    "k_sign_remote_admin_1",
    remoteAdminKeys
  );

  // Remote node must know local node signing key to verify wrapper signatures.
  const remoteTrustLocal = await jsonRequest(`${remoteBaseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${remoteAdminToken}`
    },
    body: JSON.stringify({
      node_id: "local.test",
      key_id: "k_node_sign_local_1",
      public_key_pem: localNodeSigningKeys.publicKeyPem
    })
  });
  assert.equal(remoteTrustLocal.response.status, 201);

  // Local node must know remote deliver url and key.
  const localTrustRemote = await jsonRequest(`${localBaseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localAdminToken}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeSigningKeysPrimary.publicKeyPem,
      signing_keys: [
        {
          key_id: "k_node_sign_remote_1",
          public_key_pem: remoteNodeSigningKeysPrimary.publicKeyPem
        },
        {
          key_id: "k_node_sign_remote_2",
          public_key_pem: remoteNodeSigningKeysSecondary.publicKeyPem
        }
      ],
      deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(localTrustRemote.response.status, 201);

  // Remote must also know sender identity key for envelope signature verification.
  const registerSenderOnRemote = await jsonRequest(`${remoteBaseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@local.test",

      imported_remote: true,
      display_name: "alice@local.test",
      signing_keys: [{ key_id: "k_sign_local_sender_1", public_key_pem: localSenderKeys.publicKeyPem }]
    })
  });
  assert.equal(registerSenderOnRemote.response.status, 201);

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FH0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FH1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@local.test",
        display: "Alice",
        key_id: "k_sign_local_sender_1",
        type: "human"
      },
      to: [{ identity: "loom://team@remote.test", role: "primary" }],
      created_at: "2026-02-16T21:25:00Z",
      priority: "normal",
      content: {
        human: { text: "Outbound federation", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    localSenderKeys.privateKeyPem,
    "k_sign_local_sender_1"
  );

  const createEnvelope = await jsonRequest(`${localBaseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(createEnvelope.response.status, 201);

  const queue = await jsonRequest(`${localBaseUrl}/v1/federation/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify({
      recipient_node: "remote.test",
      envelope_ids: [envelope.id]
    })
  });
  assert.equal(queue.response.status, 201);
  assert.equal(queue.body.status, "queued");

  const process = await jsonRequest(`${localBaseUrl}/v1/federation/outbox/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify({
      limit: 10
    })
  });
  assert.equal(process.response.status, 200);
  assert.equal(process.body.processed_count, 1);
  assert.equal(process.body.processed[0].status, "delivered");
  assert.equal(process.body.processed[0].receipt_verified, true);

  const delivered = remoteStore.getEnvelope(envelope.id);
  assert.equal(delivered.id, envelope.id);
});

test("API can require signed federation receipts for outbound delivery", async (t) => {
  let deliverCalls = 0;
  const remoteStub = createHttpServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    deliverCalls += 1;
    const body = {
      sender_node: "local.test",
      accepted_count: 1,
      accepted_envelope_ids: ["env_01ARZ3NDEKTSV4RRFFQ69G5FHZ"]
    };
    res.writeHead(202, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise((resolve) => remoteStub.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteStub.close(resolve)));
  const remoteAddress = remoteStub.address();
  const remoteDeliverUrl = `http://127.0.0.1:${remoteAddress.port}/v1/federation/deliver`;

  const localNodeSigningKeys = generateSigningKeyPair();
  const { server: localServer } = createLoomServer({
    nodeId: "local.test",
    domain: "127.0.0.1",
    federationSigningKeyId: "k_node_sign_local_1",
    federationSigningPrivateKeyPem: localNodeSigningKeys.privateKeyPem,
    federationRequireSignedReceipts: true
  });
  await new Promise((resolve) => localServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => localServer.close(resolve)));
  const localAddress = localServer.address();
  const localBaseUrl = `http://127.0.0.1:${localAddress.port}`;

  const localAdminKeys = generateSigningKeyPair();
  const localSenderKeys = generateSigningKeyPair();
  const remoteNodeSigningKeys = generateSigningKeyPair();

  async function registerAndAuth(baseUrl, identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const localAdminToken = await registerAndAuth(
    localBaseUrl,
    "loom://admin@local.test",
    "k_sign_local_admin_1",
    localAdminKeys
  );
  const localSenderToken = await registerAndAuth(
    localBaseUrl,
    "loom://alice@local.test",
    "k_sign_local_sender_1",
    localSenderKeys
  );

  const localTrustRemote = await jsonRequest(`${localBaseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localAdminToken}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeSigningKeys.publicKeyPem,
      deliver_url: remoteDeliverUrl,
      allow_insecure_http: true,
      allow_private_network: true
    })
  });
  assert.equal(localTrustRemote.response.status, 201);

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FHZ",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FJ0",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@local.test",
        display: "Alice",
        key_id: "k_sign_local_sender_1",
        type: "human"
      },
      to: [{ identity: "loom://team@remote.test", role: "primary" }],
      created_at: "2026-02-16T21:26:00Z",
      priority: "normal",
      content: {
        human: { text: "Outbound federation strict receipt", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    localSenderKeys.privateKeyPem,
    "k_sign_local_sender_1"
  );

  const createEnvelope = await jsonRequest(`${localBaseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(createEnvelope.response.status, 201);

  const queue = await jsonRequest(`${localBaseUrl}/v1/federation/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify({
      recipient_node: "remote.test",
      envelope_ids: [envelope.id],
      max_attempts: 1
    })
  });
  assert.equal(queue.response.status, 201);
  assert.equal(queue.body.status, "queued");

  const process = await jsonRequest(`${localBaseUrl}/v1/federation/outbox/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${localSenderToken}`
    },
    body: JSON.stringify({
      limit: 10
    })
  });
  assert.equal(process.response.status, 200);
  assert.equal(process.body.processed_count, 1);
  assert.equal(process.body.processed[0].status, "failed");
  assert.equal(process.body.processed[0].receipt_verified, false);
  assert.equal(
    String(process.body.processed[0].receipt_verification_error || "").includes("missing_receipt"),
    true
  );
  assert.equal(deliverCalls, 1);
});

test("API bootstraps federation node trust from node discovery document", async (t) => {
  const remoteNodeSigningKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  const { server: remoteServer } = createLoomServer({
    nodeId: "remote.test",
    domain: "127.0.0.1",
    federationSigningKeyId: "k_node_sign_remote_bootstrap_1",
    federationSigningPrivateKeyPem: remoteNodeSigningKeys.privateKeyPem
  });
  await new Promise((resolve) => remoteServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => remoteServer.close(resolve)));
  const remoteAddress = remoteServer.address();
  const remoteBaseUrl = `http://127.0.0.1:${remoteAddress.port}`;

  const { server: localServer } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => localServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => localServer.close(resolve)));
  const localAddress = localServer.address();
  const localBaseUrl = `http://127.0.0.1:${localAddress.port}`;

  const adminKeys = generateSigningKeyPair();

  const registerAdmin = await jsonRequest(`${localBaseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_bootstrap_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAdmin.response.status, 201);

  const registerRemoteSender = await jsonRequest(`${localBaseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_bootstrap_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });
  assert.equal(registerRemoteSender.response.status, 201);

  const challenge = await jsonRequest(`${localBaseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${localBaseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const bootstrap = await jsonRequest(`${localBaseUrl}/v1/federation/nodes/bootstrap`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_document_url: `${remoteBaseUrl}/.well-known/loom.json`,
      allow_insecure_http: true,
      allow_private_network: true,
      deliver_url: `${remoteBaseUrl}/v1/federation/deliver`,
      identity_resolve_url: `${remoteBaseUrl}/v1/identity/{identity}`
    })
  });
  assert.equal(bootstrap.response.status, 201, JSON.stringify(bootstrap.body));
  assert.equal(bootstrap.body.node.node_id, "remote.test");
  assert.equal(bootstrap.body.node.key_id, "k_node_sign_remote_bootstrap_1");
  assert.equal(bootstrap.body.node.identity_resolve_url, `${remoteBaseUrl}/v1/identity/{identity}`);
  assert.equal(Array.isArray(bootstrap.body.node.signing_keys), true);
  assert.equal(bootstrap.body.node.signing_keys.length >= 1, true);
  assert.equal(bootstrap.body.discovery.node_document_url, `${remoteBaseUrl}/.well-known/loom.json`);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G5FK0",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FK1",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_bootstrap_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:10:00Z",
      priority: "normal",
      content: {
        human: { text: "bootstrap trusted delivery", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_bootstrap_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };
  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_bootstrap";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeSigningKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${localBaseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_bootstrap_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 202, JSON.stringify(deliver.body));
  assert.equal(deliver.body.accepted_count, 1);
});

test("API rejects federation bootstrap to private network by default", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();

  const registerAdmin = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_bootstrap_private_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAdmin.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_private_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_private_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const bootstrap = await jsonRequest(`${baseUrl}/v1/federation/nodes/bootstrap`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_document_url: "http://127.0.0.1:34567/.well-known/loom.json",
      allow_insecure_http: true
    })
  });

  assert.equal(bootstrap.response.status, 403);
  assert.equal(bootstrap.body.error.code, "CAPABILITY_DENIED");
});

test("API enforces federation bootstrap host allowlist", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationBootstrapHostAllowlist: ["bootstrap.allowed.test"]
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const adminKeys = generateSigningKeyPair();

  const registerAdmin = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_bootstrap_allowlist_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAdmin.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_allowlist_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_bootstrap_allowlist_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const bootstrap = await jsonRequest(`${baseUrl}/v1/federation/nodes/bootstrap`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_document_url: "http://127.0.0.1:34567/.well-known/loom.json",
      allow_insecure_http: true,
      allow_private_network: true
    })
  });

  assert.equal(bootstrap.response.status, 403);
  assert.equal(bootstrap.body.error.code, "CAPABILITY_DENIED");
});

test("API requires admin token for insecure federation node transport settings when configured", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const userKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();

  const registerUser = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_fed_admin_1", public_key_pem: userKeys.publicKeyPem }]
    })
  });
  assert.equal(registerUser.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_fed_admin_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_fed_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(userKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const insecureNodePayload = {
    node_id: "remote.test",
    key_id: "k_node_sign_remote_admin_1",
    public_key_pem: remoteNodeKeys.publicKeyPem,
    deliver_url: "http://127.0.0.1:33445/v1/federation/deliver",
    identity_resolve_url: "http://127.0.0.1:33445/v1/identity/{identity}",
    allow_insecure_http: true,
    allow_private_network: true
  };

  const denied = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify(insecureNodePayload)
  });
  assert.equal(denied.response.status, 403);
  assert.equal(denied.body.error.code, "CAPABILITY_DENIED");

  const allowed = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`,
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify(insecureNodePayload)
  });
  assert.equal(allowed.response.status, 201, JSON.stringify(allowed.body));
  assert.equal(allowed.body.allow_insecure_http, true);
  assert.equal(allowed.body.allow_private_network, true);
});

test("API rejects webhook private-network targets unless explicitly allowed", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const webhookCreate = await jsonRequest(`${baseUrl}/v1/webhooks`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      url: "http://127.0.0.1:45555/hook",
      events: ["email.outbox.process.delivered"],
      timeout_ms: 1000,
      max_attempts: 3
    })
  });

  assert.equal(webhookCreate.response.status, 403);
  assert.equal(webhookCreate.body.error.code, "CAPABILITY_DENIED");
});

test("API enforces webhook outbound host allowlist", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token",
    webhookOutboundHostAllowlist: ["hooks.allowed.test"]
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const denied = await jsonRequest(`${baseUrl}/v1/webhooks`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      url: "https://hooks.blocked.test/hook",
      events: ["email.outbox.process.delivered"]
    })
  });
  assert.equal(denied.response.status, 403);
  assert.equal(denied.body.error.code, "CAPABILITY_DENIED");

  const allowed = await jsonRequest(`${baseUrl}/v1/webhooks`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      url: "https://hooks.allowed.test/hook",
      events: ["email.outbox.process.delivered"]
    })
  });
  assert.equal(allowed.response.status, 201);
  assert.equal(allowed.body.url, "https://hooks.allowed.test/hook");
});

test("API supports bridge and gateway email surfaces", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const aliceKeys = generateSigningKeyPair();

  const registerAlice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAlice.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(aliceKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "External Sender <sender@example.net>",
      rcpt_to: ["alice@node.test"],
      subject: "Bridge inbound",
      text: "Inbound bridge message",
      message_id: "<msg-inbound-1@example.net>",
      date: "2026-02-16T22:00:00Z",
      headers: {
        "message-id": "<msg-inbound-1@example.net>"
      }
    })
  });
  assert.equal(inbound.response.status, 201, JSON.stringify(inbound.body));
  assert.equal(typeof inbound.body.envelope_id, "string");
  assert.equal(typeof inbound.body.thread_id, "string");

  const inboundEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${inbound.body.envelope_id}`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(inboundEnvelope.response.status, 200);
  assert.equal(inboundEnvelope.body.from.identity, "bridge://sender@example.net");

  const renderOutbound = await jsonRequest(`${baseUrl}/v1/bridge/email/outbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      envelope_id: inbound.body.envelope_id
    })
  });
  assert.equal(renderOutbound.response.status, 200);
  assert.equal(Array.isArray(renderOutbound.body.rcpt_to), true);
  assert.equal(renderOutbound.body.rcpt_to.includes("alice@node.test"), true);
  assert.equal(renderOutbound.body.headers["X-LOOM-Envelope-ID"], inbound.body.envelope_id);

  const listFolders = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(listFolders.response.status, 200);
  const inboxFolder = listFolders.body.folders.find((folder) => folder.name === "INBOX");
  assert.equal(Boolean(inboxFolder), true);
  assert.equal(inboxFolder.count >= 1, true);

  const inboxMessages = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders/INBOX/messages?limit=10`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(inboxMessages.response.status, 200);
  assert.equal(inboxMessages.body.folder, "INBOX");
  assert.equal(
    inboxMessages.body.messages.some((message) => message.envelope_id === inbound.body.envelope_id),
    true
  );

  const smtpSubmit = await jsonRequest(`${baseUrl}/v1/gateway/smtp/submit`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      to: ["bob@node.test"],
      text: "SMTP gateway body",
      message_id: "<msg-smtp-1@node.test>",
      date: "2026-02-16T22:02:00Z"
    })
  });
  assert.equal(smtpSubmit.response.status, 201, JSON.stringify(smtpSubmit.body));
  assert.equal(typeof smtpSubmit.body.envelope_id, "string");

  const sentMessages = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders/Sent/messages?limit=10`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(sentMessages.response.status, 200);
  assert.equal(sentMessages.body.folder, "Sent");
  assert.equal(
    sentMessages.body.messages.some((message) => message.envelope_id === smtpSubmit.body.envelope_id),
    true
  );
});

test("API hardens SMTP and IMAP parsing for edge-case address and header formats", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const aliceKeys = generateSigningKeyPair();

  const registerAlice = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_edge_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(registerAlice.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_edge_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_edge_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(aliceKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "External Sender <sender@example.net>",
      to: '"Alice, Ops" <alice@node.test>; bob@node.test',
      cc: "carol@node.test, Dan <dan@node.test>",
      html: "<p>Hello <strong>world</strong></p>",
      headers: {
        "Message-ID": "<msg-edge-1@example.net>",
        Date: "Mon, 16 Feb 2026 22:05:00 +0000"
      }
    })
  });
  assert.equal(inbound.response.status, 201, JSON.stringify(inbound.body));

  const inboundEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${inbound.body.envelope_id}`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(inboundEnvelope.response.status, 200);
  assert.equal(inboundEnvelope.body.content.human.text.includes("Hello world"), true);
  assert.equal(inboundEnvelope.body.meta.bridge.original_message_id, "msg-edge-1@example.net");

  const inboundRecipients = new Map(inboundEnvelope.body.to.map((recipient) => [recipient.identity, recipient.role]));
  assert.equal(inboundRecipients.get("loom://alice@node.test"), "primary");
  assert.equal(inboundRecipients.get("loom://bob@node.test"), "primary");
  assert.equal(inboundRecipients.get("loom://carol@node.test"), "cc");
  assert.equal(inboundRecipients.get("loom://dan@node.test"), "cc");

  const smtpSubmit = await jsonRequest(`${baseUrl}/v1/gateway/smtp/submit`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      to: '"Bob, Team" <bob@node.test>; eve@node.test',
      cc: "frank@node.test",
      bcc: "grace@node.test",
      text: "reply via smtp gateway",
      headers: {
        "Message-ID": "<msg-edge-smtp-1@node.test>",
        "In-Reply-To": "<msg-edge-1@example.net>",
        Date: "Mon, 16 Feb 2026 22:06:00 +0000"
      }
    })
  });
  assert.equal(smtpSubmit.response.status, 201, JSON.stringify(smtpSubmit.body));
  assert.equal(smtpSubmit.body.thread_id, inbound.body.thread_id);

  const smtpEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${smtpSubmit.body.envelope_id}`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(smtpEnvelope.response.status, 200);
  const smtpRecipients = new Map(smtpEnvelope.body.to.map((recipient) => [recipient.identity, recipient.role]));
  assert.equal(smtpRecipients.get("loom://bob@node.test"), "primary");
  assert.equal(smtpRecipients.get("loom://eve@node.test"), "primary");
  assert.equal(smtpRecipients.get("loom://frank@node.test"), "cc");
  assert.equal(smtpRecipients.get("loom://grace@node.test"), "bcc");

  const sentAlias = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders/sent%20items/messages?limit=20`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(sentAlias.response.status, 200);
  assert.equal(sentAlias.body.folder, "Sent");

  const sentMessage = sentAlias.body.messages.find((message) => message.envelope_id === smtpSubmit.body.envelope_id);
  assert.equal(Boolean(sentMessage), true);
  assert.equal(sentMessage.headers["Message-ID"], `<${smtpSubmit.body.envelope_id}@node.test>`);
  assert.equal(typeof sentMessage.headers["In-Reply-To"], "string");
  assert.equal(sentMessage.in_reply_to, `<${inbound.body.envelope_id}@node.test>`);
});

test("API hides BCC recipients from non-sender IMAP recipient views", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function registerAndLogin(identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceToken = await registerAndLogin("loom://alice@node.test", "k_sign_alice_bcc_1", aliceKeys);
  const bobToken = await registerAndLogin("loom://bob@node.test", "k_sign_bob_bcc_1", bobKeys);

  const smtpSubmit = await jsonRequest(`${baseUrl}/v1/gateway/smtp/submit`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify({
      to: ["bob@node.test"],
      bcc: ["grace@node.test"],
      text: "bcc privacy test"
    })
  });
  assert.equal(smtpSubmit.response.status, 201, JSON.stringify(smtpSubmit.body));

  const deniedEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${smtpSubmit.body.envelope_id}`);
  assert.equal(deniedEnvelope.response.status, 401);
  assert.equal(deniedEnvelope.body.error.code, "SIGNATURE_INVALID");

  const bobEnvelope = await jsonRequest(`${baseUrl}/v1/envelopes/${smtpSubmit.body.envelope_id}`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobEnvelope.response.status, 200);
  const bobEnvelopeRecipients = new Map(
    bobEnvelope.body.to.map((recipient) => [recipient.identity, recipient.role])
  );
  assert.equal(bobEnvelopeRecipients.get("loom://bob@node.test"), "primary");
  assert.equal(bobEnvelopeRecipients.has("loom://grace@node.test"), false);
  assert.equal(typeof bobEnvelope.body.delivery_wrapper?.id, "string");
  assert.equal(bobEnvelope.body.delivery_wrapper?.type, "delivery.wrapper@v1");

  const bobWrapper = await jsonRequest(`${baseUrl}/v1/envelopes/${smtpSubmit.body.envelope_id}/delivery`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobWrapper.response.status, 200);
  assert.equal(bobWrapper.body.delivery_wrapper.envelope_id, smtpSubmit.body.envelope_id);
  assert.equal(bobWrapper.body.delivery_wrapper.recipient_identity, "loom://bob@node.test");
  assert.equal(typeof bobWrapper.body.delivery_wrapper.core_envelope_hash, "string");
  assert.equal(
    bobWrapper.body.delivery_wrapper.visible_recipients.some((recipient) => recipient.identity === "loom://grace@node.test"),
    false
  );

  const bobSent = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders/Sent/messages?limit=20`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobSent.response.status, 200);
  const message = bobSent.body.messages.find((item) => item.envelope_id === smtpSubmit.body.envelope_id);
  assert.equal(Boolean(message), true);
  assert.equal(message.to.includes("loom://bob@node.test"), true);
  assert.equal(message.to.includes("loom://grace@node.test"), false);
});

test("API supports per-user mailbox state without mutating other participants", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function registerAndLogin(identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceToken = await registerAndLogin("loom://alice@node.test", "k_sign_alice_mailbox_1", aliceKeys);
  const bobToken = await registerAndLogin("loom://bob@node.test", "k_sign_bob_mailbox_1", bobKeys);

  const envelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MAA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G7MAB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_mailbox_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T23:10:00Z",
      priority: "normal",
      content: {
        human: { text: "mailbox state test", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_mailbox_1"
  );

  const send = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(send.response.status, 201, JSON.stringify(send.body));

  const bobFoldersBefore = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobFoldersBefore.response.status, 200);
  const bobInboxBefore = bobFoldersBefore.body.folders.find((folder) => folder.name === "INBOX");
  assert.equal(bobInboxBefore.count, 1);

  const bobStateBefore = await jsonRequest(`${baseUrl}/v1/mailbox/threads/${envelope.thread_id}/state`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobStateBefore.response.status, 200);
  assert.equal(bobStateBefore.body.archived, false);

  const bobArchive = await jsonRequest(`${baseUrl}/v1/mailbox/threads/${envelope.thread_id}/state`, {
    method: "PATCH",
    headers: {
      authorization: `Bearer ${bobToken}`
    },
    body: JSON.stringify({
      archived: true
    })
  });
  assert.equal(bobArchive.response.status, 200);
  assert.equal(bobArchive.body.archived, true);

  const bobFoldersAfter = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders`, {
    headers: {
      authorization: `Bearer ${bobToken}`
    }
  });
  assert.equal(bobFoldersAfter.response.status, 200);
  const bobInboxAfter = bobFoldersAfter.body.folders.find((folder) => folder.name === "INBOX");
  const bobArchiveAfter = bobFoldersAfter.body.folders.find((folder) => folder.name === "Archive");
  assert.equal(bobInboxAfter.count, 0);
  assert.equal(bobArchiveAfter.count, 1);

  const aliceFoldersAfter = await jsonRequest(`${baseUrl}/v1/gateway/imap/folders`, {
    headers: {
      authorization: `Bearer ${aliceToken}`
    }
  });
  assert.equal(aliceFoldersAfter.response.status, 200);
  const aliceInbox = aliceFoldersAfter.body.folders.find((folder) => folder.name === "INBOX");
  assert.equal(aliceInbox.count, 1);
});

test("API supports capability presentation token in header for thread operations", async (t) => {
  const { server } = createLoomServer({ nodeId: "node.test", domain: "127.0.0.1" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function registerAndLogin(identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceToken = await registerAndLogin("loom://alice@node.test", "k_sign_alice_cap_1", aliceKeys);
  const bobToken = await registerAndLogin("loom://bob@node.test", "k_sign_bob_cap_1", bobKeys);

  const rootEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MAC",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G7MAD",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_cap_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T23:15:00Z",
      priority: "normal",
      content: {
        human: { text: "capability header test", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_cap_1"
  );

  const sendRoot = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify(rootEnvelope)
  });
  assert.equal(sendRoot.response.status, 201, JSON.stringify(sendRoot.body));

  const issueCapability = await jsonRequest(`${baseUrl}/v1/capabilities`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify({
      thread_id: rootEnvelope.thread_id,
      issued_to: "loom://bob@node.test",
      grants: ["label"],
      single_use: true
    })
  });
  assert.equal(issueCapability.response.status, 201);
  assert.equal(typeof issueCapability.body.presentation_token, "string");
  assert.equal(issueCapability.body.presentation_token.startsWith("cpt_"), true);
  assert.equal(typeof issueCapability.body.portable_token, "object");

  const listCapabilities = await jsonRequest(`${baseUrl}/v1/capabilities?thread_id=${rootEnvelope.thread_id}`, {
    headers: {
      authorization: `Bearer ${aliceToken}`
    }
  });
  assert.equal(listCapabilities.response.status, 200);
  assert.equal(listCapabilities.body.capabilities.length, 1);
  assert.equal(listCapabilities.body.capabilities[0].presentation_token, undefined);

  const opDeniedWithoutCapability = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MAE",
      thread_id: rootEnvelope.thread_id,
      parent_id: rootEnvelope.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_cap_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T23:16:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.update@v1",
          parameters: {
            subject: "portable subject update"
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_cap_1"
  );

  const opDeniedWithoutHeader = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bobToken}`
    },
    body: JSON.stringify(opDeniedWithoutCapability)
  });
  assert.equal(opDeniedWithoutHeader.response.status, 403);
  assert.equal(opDeniedWithoutHeader.body.error.code, "CAPABILITY_DENIED");

  const opAcceptedPortable = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bobToken}`
    },
    body: JSON.stringify(
      signEnvelope(
        {
          loom: "1.1",
          id: "env_01ARZ3NDEKTSV4RRFFQ69G7MAF",
          thread_id: rootEnvelope.thread_id,
          parent_id: rootEnvelope.id,
          type: "thread_op",
          from: {
            identity: "loom://bob@node.test",
            display: "Bob",
            key_id: "k_sign_bob_cap_1",
            type: "human"
          },
          to: [{ identity: "loom://alice@node.test", role: "primary" }],
          created_at: "2026-02-16T23:16:10Z",
          priority: "normal",
          content: {
            structured: {
              intent: "thread.update@v1",
              parameters: {
                subject: "portable subject update",
                capability_token: issueCapability.body.portable_token
              }
            },
            encrypted: false
          },
          attachments: []
        },
        bobKeys.privateKeyPem,
        "k_sign_bob_cap_1"
      )
    )
  });
  assert.equal(opAcceptedPortable.response.status, 201, JSON.stringify(opAcceptedPortable.body));

  const issueResolveCapability = await jsonRequest(`${baseUrl}/v1/capabilities`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify({
      thread_id: rootEnvelope.thread_id,
      issued_to: "loom://bob@node.test",
      grants: ["resolve"],
      single_use: true
    })
  });
  assert.equal(issueResolveCapability.response.status, 201);

  const opResolve = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MAG",
      thread_id: rootEnvelope.thread_id,
      parent_id: rootEnvelope.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_cap_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T23:16:20Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {
            capability_id: issueResolveCapability.body.id
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_cap_1"
  );

  const opAcceptedWithHeader = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bobToken}`,
      "x-loom-capability-token": issueResolveCapability.body.presentation_token
    },
    body: JSON.stringify(opResolve)
  });
  assert.equal(opAcceptedWithHeader.response.status, 201, JSON.stringify(opAcceptedWithHeader.body));

  const publicEnvelopeView = await jsonRequest(`${baseUrl}/v1/envelopes/${opAcceptedPortable.body.id}`);
  assert.equal(publicEnvelopeView.response.status, 401);

  const aliceEnvelopeView = await jsonRequest(`${baseUrl}/v1/envelopes/${opAcceptedPortable.body.id}`, {
    headers: {
      authorization: `Bearer ${aliceToken}`
    }
  });
  assert.equal(aliceEnvelopeView.response.status, 200);
  assert.equal(aliceEnvelopeView.body.content.structured.parameters.capability_token, undefined);
  assert.equal(aliceEnvelopeView.body.content.structured.parameters.capability_token_redacted, true);

  const thread = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}`, {
    headers: {
      authorization: `Bearer ${aliceToken}`
    }
  });
  assert.equal(thread.response.status, 200);
  assert.equal(thread.body.subject, "portable subject update");
  assert.equal(thread.body.state, "resolved");
});

test("API can require portable capability payloads for non-owner thread operations", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    requirePortableThreadOpCapability: true
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function registerAndLogin(identity, keyId, keys) {
    const register = await jsonRequest(`${baseUrl}/v1/identity`, {
      method: "POST",
      body: JSON.stringify({
        id: identity,
        display_name: identity,
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      })
    });
    assert.equal(register.response.status, 201);

    const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId
      })
    });
    assert.equal(challenge.response.status, 200);

    const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
      method: "POST",
      body: JSON.stringify({
        identity,
        key_id: keyId,
        challenge_id: challenge.body.challenge_id,
        signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
      })
    });
    assert.equal(token.response.status, 200);
    return token.body.access_token;
  }

  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const aliceToken = await registerAndLogin("loom://alice@node.test", "k_sign_alice_cap_portable_1", aliceKeys);
  const bobToken = await registerAndLogin("loom://bob@node.test", "k_sign_bob_cap_portable_1", bobKeys);

  const rootEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MBB",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G7MBC",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@node.test",
        display: "Alice",
        key_id: "k_sign_alice_cap_portable_1",
        type: "human"
      },
      to: [{ identity: "loom://bob@node.test", role: "primary" }],
      created_at: "2026-02-16T23:20:00Z",
      priority: "normal",
      content: {
        human: { text: "portable required test", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    aliceKeys.privateKeyPem,
    "k_sign_alice_cap_portable_1"
  );

  const sendRoot = await jsonRequest(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify(rootEnvelope)
  });
  assert.equal(sendRoot.response.status, 201, JSON.stringify(sendRoot.body));

  const issueCapability = await jsonRequest(`${baseUrl}/v1/capabilities`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${aliceToken}`
    },
    body: JSON.stringify({
      thread_id: rootEnvelope.thread_id,
      issued_to: "loom://bob@node.test",
      grants: ["resolve"],
      single_use: true
    })
  });
  assert.equal(issueCapability.response.status, 201);
  assert.equal(typeof issueCapability.body.presentation_token, "string");
  assert.equal(typeof issueCapability.body.portable_token, "object");

  const headerOnlyOp = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MBD",
      thread_id: rootEnvelope.thread_id,
      parent_id: rootEnvelope.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_cap_portable_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T23:21:00Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {
            capability_id: issueCapability.body.id
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_cap_portable_1"
  );

  const deniedHeader = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bobToken}`,
      "x-loom-capability-token": issueCapability.body.presentation_token
    },
    body: JSON.stringify(headerOnlyOp)
  });
  assert.equal(deniedHeader.response.status, 403);
  assert.equal(deniedHeader.body.error.code, "CAPABILITY_DENIED");

  const portableOp = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G7MBE",
      thread_id: rootEnvelope.thread_id,
      parent_id: rootEnvelope.id,
      type: "thread_op",
      from: {
        identity: "loom://bob@node.test",
        display: "Bob",
        key_id: "k_sign_bob_cap_portable_1",
        type: "human"
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }],
      created_at: "2026-02-16T23:21:30Z",
      priority: "normal",
      content: {
        structured: {
          intent: "thread.resolve@v1",
          parameters: {
            capability_token: issueCapability.body.portable_token
          }
        },
        encrypted: false
      },
      attachments: []
    },
    bobKeys.privateKeyPem,
    "k_sign_bob_cap_portable_1"
  );

  const acceptedPortable = await jsonRequest(`${baseUrl}/v1/threads/${rootEnvelope.thread_id}/ops`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bobToken}`
    },
    body: JSON.stringify(portableOp)
  });
  assert.equal(acceptedPortable.response.status, 201, JSON.stringify(acceptedPortable.body));
});

test("API supports outbound email relay outbox queue and process", async (t) => {
  const relayCalls = [];
  const mockRelay = {
    isEnabled: () => true,
    getStatus: () => ({
      enabled: true,
      mode: "mock",
      configured: true
    }),
    send: async (message) => {
      relayCalls.push(message);
      return {
        provider_message_id: `mock-${relayCalls.length}`,
        accepted: message.rcpt_to,
        rejected: [],
        response: "250 queued",
        relay_mode: "mock"
      };
    }
  };

  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    emailRelay: mockRelay
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "Sender <sender@example.net>",
      rcpt_to: ["alice@node.test"],
      text: "relay target message"
    })
  });
  assert.equal(inbound.response.status, 201);

  const queue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      envelope_id: inbound.body.envelope_id,
      to_email: ["alice@node.test"],
      smtp_from: "no-reply@node.test"
    })
  });
  assert.equal(queue.response.status, 201);
  assert.equal(queue.body.status, "queued");

  const processBatch = await jsonRequest(`${baseUrl}/v1/email/outbox/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      limit: 10
    })
  });
  assert.equal(processBatch.response.status, 200);
  assert.equal(processBatch.body.processed_count, 1);
  assert.equal(processBatch.body.processed[0].status, "delivered");
  assert.equal(processBatch.body.processed[0].provider_message_id, "mock-1");
  assert.equal(relayCalls.length, 1);

  const outboxList = await jsonRequest(`${baseUrl}/v1/email/outbox?status=delivered`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(outboxList.response.status, 200);
  assert.equal(outboxList.body.outbox.length, 1);
  assert.equal(outboxList.body.outbox[0].provider_message_id, "mock-1");

  const directSend = await jsonRequest(`${baseUrl}/v1/bridge/email/send`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      envelope_id: inbound.body.envelope_id,
      to_email: ["alice@node.test"],
      smtp_from: "no-reply@node.test"
    })
  });
  assert.equal(directSend.response.status, 200);
  assert.equal(directSend.body.status, "delivered");
  assert.equal(directSend.body.provider_message_id, "mock-2");
  assert.equal(relayCalls.length, 2);
});

test("API exposes dead-letter outbox and supports admin requeue", async (t) => {
  let relaySendCalls = 0;
  const flakyRelay = {
    isEnabled: () => true,
    getStatus: () => ({
      enabled: true,
      mode: "mock",
      configured: true
    }),
    send: async (message) => {
      relaySendCalls += 1;
      if (relaySendCalls === 1) {
        throw new Error("temporary relay failure");
      }
      return {
        provider_message_id: `mock-${relaySendCalls}`,
        accepted: message.rcpt_to,
        rejected: [],
        response: "250 queued",
        relay_mode: "mock"
      };
    }
  };

  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token",
    emailRelay: flakyRelay
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "Sender <sender@example.net>",
      rcpt_to: ["alice@node.test"],
      text: "dlq test"
    })
  });
  assert.equal(inbound.response.status, 201);

  const queue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      envelope_id: inbound.body.envelope_id,
      to_email: ["alice@node.test"],
      smtp_from: "no-reply@node.test",
      max_attempts: 1
    })
  });
  assert.equal(queue.response.status, 201);
  const outboxId = queue.body.id;

  const failAttempt = await jsonRequest(`${baseUrl}/v1/email/outbox/${outboxId}/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(failAttempt.response.status, 200);
  assert.equal(failAttempt.body.status, "failed");

  const deniedDlq = await jsonRequest(`${baseUrl}/v1/outbox/dlq`);
  assert.equal(deniedDlq.response.status, 403);
  assert.equal(deniedDlq.body.error.code, "CAPABILITY_DENIED");

  const dlq = await jsonRequest(`${baseUrl}/v1/outbox/dlq?kind=email`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(dlq.response.status, 200);
  assert.equal(dlq.body.entries.length, 1);
  assert.equal(dlq.body.entries[0].kind, "email");
  assert.equal(dlq.body.entries[0].id, outboxId);

  const requeue = await jsonRequest(`${baseUrl}/v1/outbox/dlq/requeue`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      kind: "email",
      id: outboxId
    })
  });
  assert.equal(requeue.response.status, 200);
  assert.equal(requeue.body.kind, "email");
  assert.equal(requeue.body.item.status, "queued");

  const deliverAttempt = await jsonRequest(`${baseUrl}/v1/email/outbox/${outboxId}/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(deliverAttempt.response.status, 200);
  assert.equal(deliverAttempt.body.status, "delivered");
  assert.equal(deliverAttempt.body.provider_message_id, "mock-2");

  const dlqAfter = await jsonRequest(`${baseUrl}/v1/outbox/dlq?kind=email`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(dlqAfter.response.status, 200);
  assert.equal(dlqAfter.body.entries.length, 0);
});

test("API supports idempotency key replay and conflict detection", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "Sender <sender@example.net>",
      rcpt_to: ["alice@node.test"],
      text: "idempotency test"
    })
  });
  assert.equal(inbound.response.status, 201);

  const key = "idem-email-outbox-1";
  const queuePayload = {
    envelope_id: inbound.body.envelope_id,
    to_email: ["alice@node.test"],
    smtp_from: "no-reply@node.test"
  };

  const firstQueue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "idempotency-key": key
    },
    body: JSON.stringify(queuePayload)
  });
  assert.equal(firstQueue.response.status, 201);

  const secondQueue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "idempotency-key": key
    },
    body: JSON.stringify(queuePayload)
  });
  assert.equal(secondQueue.response.status, 201);
  assert.equal(secondQueue.response.headers.get("x-loom-idempotency-replay"), "true");
  assert.equal(secondQueue.body.id, firstQueue.body.id);

  const outboxList = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(outboxList.response.status, 200);
  assert.equal(outboxList.body.outbox.length, 1);

  const conflictingQueue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "idempotency-key": key
    },
    body: JSON.stringify({
      ...queuePayload,
      smtp_from: "different-sender@node.test"
    })
  });
  assert.equal(conflictingQueue.response.status, 409);
  assert.equal(conflictingQueue.body.error.code, "IDEMPOTENCY_CONFLICT");
});

test("API supports webhook receipt delivery with signed callback", async (t) => {
  const received = [];
  const receiverServer = createHttpServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const raw = chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8") : "";
    received.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      raw
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise((resolve) => receiverServer.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => receiverServer.close(resolve)));
  const receiverAddress = receiverServer.address();
  const receiverUrl = `http://127.0.0.1:${receiverAddress.port}/hook`;

  const relay = {
    isEnabled: () => true,
    getStatus: () => ({
      enabled: true,
      mode: "mock",
      configured: true
    }),
    send: async (message) => ({
      provider_message_id: "mock-provider-id",
      accepted: message.rcpt_to,
      rejected: [],
      response: "250 queued",
      relay_mode: "mock"
    })
  };

  const { server, store } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token",
    emailRelay: relay
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const keys = generateSigningKeyPair();

  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://alice@node.test",
      key_id: "k_sign_alice_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);
  const accessToken = token.body.access_token;

  const webhookCreate = await jsonRequest(`${baseUrl}/v1/webhooks`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      url: receiverUrl,
      allow_private_network: true,
      events: ["email.outbox.process.delivered"],
      timeout_ms: 1000,
      max_attempts: 3
    })
  });
  assert.equal(webhookCreate.response.status, 201);

  const inbound = await jsonRequest(`${baseUrl}/v1/bridge/email/inbound`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      smtp_from: "Sender <sender@example.net>",
      rcpt_to: ["alice@node.test"],
      text: "webhook test message"
    })
  });
  assert.equal(inbound.response.status, 201);

  const queue = await jsonRequest(`${baseUrl}/v1/email/outbox`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      envelope_id: inbound.body.envelope_id,
      to_email: ["alice@node.test"],
      smtp_from: "no-reply@node.test"
    })
  });
  assert.equal(queue.response.status, 201);

  const deliverEmail = await jsonRequest(`${baseUrl}/v1/email/outbox/${queue.body.id}/process`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({})
  });
  assert.equal(deliverEmail.response.status, 200);
  assert.equal(deliverEmail.body.status, "delivered");

  const webhookQueue = await jsonRequest(`${baseUrl}/v1/webhooks/outbox?status=queued`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(webhookQueue.response.status, 200);
  assert.equal(webhookQueue.body.outbox.length >= 1, true);

  const processWebhook = await jsonRequest(`${baseUrl}/v1/webhooks/outbox/process`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      limit: 10
    })
  });
  assert.equal(processWebhook.response.status, 200);
  assert.equal(processWebhook.body.processed_count >= 1, true);
  assert.equal(processWebhook.body.processed[0].status, "delivered");

  assert.equal(received.length, 1);
  const callback = received[0];
  assert.equal(callback.method, "POST");
  assert.equal(callback.url, "/hook");
  assert.equal(callback.headers["x-loom-event-type"], "email.outbox.process.delivered");
  assert.equal(typeof callback.headers["x-loom-signature"], "string");
  assert.equal(typeof callback.headers["x-loom-key-id"], "string");
  assert.equal(typeof callback.headers["x-loom-nonce"], "string");
  assert.equal(typeof callback.headers["x-loom-timestamp"], "string");

  const body = JSON.parse(callback.raw);
  assert.equal(body.event_type, "email.outbox.process.delivered");
  assert.equal(body.node_id, "node.test");

  const parsedReceiverUrl = new URL(receiverUrl);
  const bodyHash = createHash("sha256").update(callback.raw, "utf-8").digest("hex");
  const canonical = `POST\n${parsedReceiverUrl.pathname}\n${bodyHash}\n${callback.headers["x-loom-timestamp"]}\n${callback.headers["x-loom-nonce"]}`;
  const signatureValid = verifyUtf8MessageSignature(
    store.systemSigningPublicKeyPem,
    canonical,
    callback.headers["x-loom-signature"]
  );
  assert.equal(signatureValid, true);

  const webhookDelivered = await jsonRequest(`${baseUrl}/v1/webhooks/outbox?status=delivered`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(webhookDelivered.response.status, 200);
  assert.equal(webhookDelivered.body.outbox.length >= 1, true);
});

test("API supports admin persistence schema backup and restore endpoints", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "admin-secret-token"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const deniedSchema = await jsonRequest(`${baseUrl}/v1/admin/persistence/schema`);
  assert.equal(deniedSchema.response.status, 403);
  assert.equal(deniedSchema.body.error.code, "CAPABILITY_DENIED");

  const schema = await jsonRequest(`${baseUrl}/v1/admin/persistence/schema`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(schema.response.status, 200);
  assert.equal(schema.body.backend, "memory");
  assert.equal(schema.body.initialized, false);

  const aliceKeys = generateSigningKeyPair();
  const register = await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@node.test",
      display_name: "Alice",
      signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
    })
  });
  assert.equal(register.response.status, 201);

  const backup = await jsonRequest(`${baseUrl}/v1/admin/persistence/backup`, {
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    }
  });
  assert.equal(backup.response.status, 200);
  assert.equal(backup.body.backend, "memory");
  assert.equal(Array.isArray(backup.body.state.identities), true);
  assert.equal(Array.isArray(backup.body.audit_entries), true);
  assert.equal(backup.body.audit_entries.length >= 1, true);

  const deniedRestore = await jsonRequest(`${baseUrl}/v1/admin/persistence/restore`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      backup: backup.body
    })
  });
  assert.equal(deniedRestore.response.status, 400);
  assert.equal(deniedRestore.body.error.code, "ENVELOPE_INVALID");

  const bobKeys = generateSigningKeyPair();
  const mutatedBackup = JSON.parse(JSON.stringify(backup.body));
  mutatedBackup.state.identities.push({
    id: "loom://bob@node.test",
    type: "human",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: bobKeys.publicKeyPem }],
    created_at: "2026-02-16T22:31:00Z",
    updated_at: "2026-02-16T22:31:00Z"
  });
  mutatedBackup.state.public_keys.push(["k_sign_bob_1", bobKeys.publicKeyPem]);

  const restore = await jsonRequest(`${baseUrl}/v1/admin/persistence/restore`, {
    method: "POST",
    headers: {
      "x-loom-admin-token": "admin-secret-token"
    },
    body: JSON.stringify({
      confirm: "restore",
      backup: mutatedBackup,
      replace_state: true
    })
  });
  assert.equal(restore.response.status, 200);
  assert.equal(restore.body.replaced_state, true);

  const bobIdentity = await jsonRequest(`${baseUrl}/v1/identity/${encodeURIComponent("loom://bob@node.test")}`);
  assert.equal(bobIdentity.response.status, 200);
  assert.equal(bobIdentity.body.id, "loom://bob@node.test");
});

test("API enforces federation challenge escalation and single-use challenge tokens", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationAbuseQuarantineThreshold: 50,
    federationAbuseDenyThreshold: 100,
    federationChallengeEscalationEnabled: true,
    federationChallengeThreshold: 1,
    federationChallengeDurationMs: 60_000
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const badNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelopeA = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G9PCA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G9PCB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:35:00Z",
      priority: "normal",
      content: {
        human: { text: "challenge required message A", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );
  const wrapperA = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelopeA]
  };
  const rawBodyA = JSON.stringify(wrapperA);

  function signFederationRequest(path, rawBody, nonce, privateKeyPem) {
    const timestamp = new Date().toISOString();
    const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
    const canonical = `POST\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
    return {
      timestamp,
      signature: signUtf8Message(privateKeyPem, canonical)
    };
  }

  const badDeliverSignature = signFederationRequest(
    "/v1/federation/deliver",
    rawBodyA,
    "nonce_test_federation_challenge_bad",
    badNodeKeys.privateKeyPem
  );
  const badDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": badDeliverSignature.timestamp,
      "x-loom-nonce": "nonce_test_federation_challenge_bad",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": badDeliverSignature.signature
    },
    body: rawBodyA
  });
  assert.equal(badDeliver.response.status, 401);
  assert.equal(badDeliver.body.error.code, "SIGNATURE_INVALID");

  const goodDeliverSignature = signFederationRequest(
    "/v1/federation/deliver",
    rawBodyA,
    "nonce_test_federation_challenge_no_token",
    remoteNodeKeys.privateKeyPem
  );
  const noTokenDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": goodDeliverSignature.timestamp,
      "x-loom-nonce": "nonce_test_federation_challenge_no_token",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": goodDeliverSignature.signature
    },
    body: rawBodyA
  });
  assert.equal(noTokenDeliver.response.status, 403);
  assert.equal(noTokenDeliver.body.error.code, "CAPABILITY_DENIED");
  assert.equal(noTokenDeliver.body.error.details.scope, "federation_challenge");

  const challengeBody = JSON.stringify({
    reason: "challenge-token-request"
  });
  const challengeSignature = signFederationRequest(
    "/v1/federation/challenge",
    challengeBody,
    "nonce_test_federation_challenge_issue",
    remoteNodeKeys.privateKeyPem
  );
  const issueChallenge = await jsonRequest(`${baseUrl}/v1/federation/challenge`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": challengeSignature.timestamp,
      "x-loom-nonce": "nonce_test_federation_challenge_issue",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": challengeSignature.signature
    },
    body: challengeBody
  });
  assert.equal(issueChallenge.response.status, 200);
  assert.equal(typeof issueChallenge.body.challenge_token, "string");

  const authorizedDeliverSignature = signFederationRequest(
    "/v1/federation/deliver",
    rawBodyA,
    "nonce_test_federation_challenge_with_token",
    remoteNodeKeys.privateKeyPem
  );
  const authorizedDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": authorizedDeliverSignature.timestamp,
      "x-loom-nonce": "nonce_test_federation_challenge_with_token",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": authorizedDeliverSignature.signature,
      "x-loom-challenge-token": issueChallenge.body.challenge_token
    },
    body: rawBodyA
  });
  assert.equal(authorizedDeliver.response.status, 202, JSON.stringify(authorizedDeliver.body));
  assert.equal(authorizedDeliver.body.accepted_count, 1);

  const remoteEnvelopeB = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G9PDA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G9PDB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:36:00Z",
      priority: "normal",
      content: {
        human: { text: "challenge required message B", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );
  const wrapperB = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelopeB]
  };
  const rawBodyB = JSON.stringify(wrapperB);
  const reusedTokenSignature = signFederationRequest(
    "/v1/federation/deliver",
    rawBodyB,
    "nonce_test_federation_challenge_reuse",
    remoteNodeKeys.privateKeyPem
  );
  const reusedTokenDeliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": reusedTokenSignature.timestamp,
      "x-loom-nonce": "nonce_test_federation_challenge_reuse",
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": reusedTokenSignature.signature,
      "x-loom-challenge-token": issueChallenge.body.challenge_token
    },
    body: rawBodyB
  });
  assert.equal(reusedTokenDeliver.response.status, 403);
  assert.equal(reusedTokenDeliver.body.error.code, "CAPABILITY_DENIED");
  assert.equal(reusedTokenDeliver.body.error.details.scope, "federation_challenge");
});

test("API enforces distributed federation node rate guard on first request in a window", async (t) => {
  const distributedRateCalls = [];
  const persistenceAdapter = {
    async loadStateAndAudit() {
      return {
        state: null,
        audit_entries: []
      };
    },
    async persistSnapshotAndAudit() {},
    async incrementFederationInboundRate({ nodeId, windowMs }) {
      distributedRateCalls.push({ nodeId, windowMs });
      if (nodeId === "remote.test") {
        return {
          count: 2,
          oldest_ms: Date.now() - 100
        };
      }
      return {
        count: 1,
        oldest_ms: Date.now() - 100
      };
    }
  };

  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    federationNodeRateWindowMs: 60_000,
    federationNodeRateMax: 1,
    federationGlobalRateWindowMs: 60_000,
    federationGlobalRateMax: 100,
    federationDistributedGuardsEnabled: true,
    persistenceAdapter
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const adminKeys = generateSigningKeyPair();
  const remoteNodeKeys = generateSigningKeyPair();
  const remoteSenderKeys = generateSigningKeyPair();

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://admin@node.test",
      display_name: "Admin",
      signing_keys: [{ key_id: "k_sign_admin_1", public_key_pem: adminKeys.publicKeyPem }]
    })
  });

  await jsonRequest(`${baseUrl}/v1/identity`, {
    method: "POST",
    body: JSON.stringify({
      id: "loom://alice@remote.test",

      imported_remote: true,
      display_name: "Remote Alice",
      signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
    })
  });

  const challenge = await jsonRequest(`${baseUrl}/v1/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1"
    })
  });
  assert.equal(challenge.response.status, 200);

  const token = await jsonRequest(`${baseUrl}/v1/auth/token`, {
    method: "POST",
    body: JSON.stringify({
      identity: "loom://admin@node.test",
      key_id: "k_sign_admin_1",
      challenge_id: challenge.body.challenge_id,
      signature: signUtf8Message(adminKeys.privateKeyPem, challenge.body.nonce)
    })
  });
  assert.equal(token.response.status, 200);

  const trustNode = await jsonRequest(`${baseUrl}/v1/federation/nodes`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.body.access_token}`
    },
    body: JSON.stringify({
      node_id: "remote.test",
      key_id: "k_node_sign_remote_1",
      public_key_pem: remoteNodeKeys.publicKeyPem,
      policy: "trusted"
    })
  });
  assert.equal(trustNode.response.status, 201);

  const remoteEnvelope = signEnvelope(
    {
      loom: "1.1",
      id: "env_01ARZ3NDEKTSV4RRFFQ69G9PEA",
      thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G9PEB",
      parent_id: null,
      type: "message",
      from: {
        identity: "loom://alice@remote.test",
        display: "Remote Alice",
        key_id: "k_sign_remote_alice_1",
        type: "human"
      },
      to: [{ identity: "loom://team@node.test", role: "primary" }],
      created_at: "2026-02-16T22:40:00Z",
      priority: "normal",
      content: {
        human: { text: "distributed rate first-request check", format: "markdown" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    remoteSenderKeys.privateKeyPem,
    "k_sign_remote_alice_1"
  );

  const wrapper = {
    loom: "1.1",
    sender_node: "remote.test",
    timestamp: new Date().toISOString(),
    envelopes: [remoteEnvelope]
  };

  const rawBody = JSON.stringify(wrapper);
  const timestamp = new Date().toISOString();
  const nonce = "nonce_test_federation_distributed_first";
  const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
  const canonical = `POST\n/v1/federation/deliver\n${bodyHash}\n${timestamp}\n${nonce}`;
  const requestSignature = signUtf8Message(remoteNodeKeys.privateKeyPem, canonical);

  const deliver = await jsonRequest(`${baseUrl}/v1/federation/deliver`, {
    method: "POST",
    headers: {
      "x-loom-node": "remote.test",
      "x-loom-timestamp": timestamp,
      "x-loom-nonce": nonce,
      "x-loom-key-id": "k_node_sign_remote_1",
      "x-loom-signature": requestSignature
    },
    body: rawBody
  });
  assert.equal(deliver.response.status, 429);
  assert.equal(deliver.body.error.code, "RATE_LIMIT_EXCEEDED");
  assert.equal(deliver.body.error.details.scope, "federation_node_distributed");
  assert.equal(
    distributedRateCalls.some((entry) => entry.nodeId === "__global__"),
    true
  );
  assert.equal(
    distributedRateCalls.some((entry) => entry.nodeId === "remote.test"),
    true
  );
});
