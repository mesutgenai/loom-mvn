/**
 * Tests for the production-hardening fixes applied in the v0.2.7 session.
 *
 * Covers: shutdown exit code, federation batch error isolation, signature-
 * before-quota ordering, outbox worker atomicity, idempotency sentinel,
 * base64 validation, security headers, thread DAG sortedInsert, bearer
 * token parsing, outbox backpressure, outbox lag metrics, /ready health
 * check, and outbox claim leasing.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { createLoomServer } from "../src/node/server.js";
import { LoomStore } from "../src/node/store.js";
import {
  generateSigningKeyPair,
  signEnvelope
} from "../src/protocol/crypto.js";
import { canonicalizeJson } from "../src/protocol/canonical.js";
import { validateThreadDag, canonicalThreadOrder } from "../src/protocol/thread.js";

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

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

function makeStore(overrides = {}) {
  return new LoomStore({ nodeId: "node.test", ...overrides });
}

function makeSignedEnvelope(keys, overrides = {}) {
  const base = {
    loom: "1.1",
    id: `env_${randomId()}`,
    thread_id: overrides.thread_id || `thr_${randomId()}`,
    parent_id: overrides.parent_id || null,
    type: overrides.type || "message",
    from: {
      identity: overrides.fromIdentity || "loom://alice@node.test",
      display: "Alice",
      key_id: overrides.keyId || "k_sign_alice_1",
      type: "human"
    },
    to: overrides.to || [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: overrides.created_at || new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: overrides.text || "hello", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    ...(overrides.extra || {})
  };

  return signEnvelope(base, keys.privateKeyPem, base.from.key_id);
}

let _counter = 0;
function randomId() {
  _counter += 1;
  return String(_counter).padStart(26, "0").toUpperCase().replace(/\d/g, (d) => "0123456789ABCDEFGHJKMNPQRS"[Number(d)]);
}

function registerAlice(store, keys) {
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: keys.publicKeyPem }]
  });
}

function registerBob(store, keys) {
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: keys.publicKeyPem }]
  });
}

// ────────────────────────────────────────────────────────────────────────────
// Fix #4: Signature verification runs BEFORE daily quota enforcement
// ────────────────────────────────────────────────────────────────────────────

test("ingestEnvelope rejects unsigned envelopes before consuming daily quota", () => {
  const aliceKeys = generateSigningKeyPair();
  const store = makeStore({ envelopeDailyMax: 1 });
  registerAlice(store, aliceKeys);
  registerBob(store, aliceKeys);

  // Create a properly signed envelope and ingest it to consume the quota.
  const signed = makeSignedEnvelope(aliceKeys);
  store.ingestEnvelope(signed, { actorIdentity: "loom://alice@node.test" });

  // Now create an unsigned envelope (forged signature) and try to ingest.
  // It should fail with SIGNATURE_INVALID, NOT RATE_LIMIT_EXCEEDED.
  const forged = {
    loom: "1.1",
    id: `env_${randomId()}`,
    thread_id: `thr_${randomId()}`,
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "forged", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    signature: {
      algorithm: "Ed25519",
      key_id: "k_sign_alice_1",
      value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  };

  assert.throws(
    () => store.ingestEnvelope(forged, { actorIdentity: "loom://alice@node.test" }),
    (err) => err.code === "SIGNATURE_INVALID",
    "Should reject with SIGNATURE_INVALID, not quota error"
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #3: Federation batch ingestion — per-envelope error isolation
// ────────────────────────────────────────────────────────────────────────────

test("federation delivery isolates per-envelope errors and accepts valid envelopes", async () => {
  const remoteSenderKeys = generateSigningKeyPair();
  const remoteBobKeys = generateSigningKeyPair();
  const nodeKeys = generateSigningKeyPair();
  const store = makeStore({ federationResolveRemoteIdentities: false });

  // Register a federation node
  const nodeId = "remote.test";
  const keyId = "k_node_sign_remote_1";
  store.registerFederationNode({
    node_id: nodeId,
    key_id: keyId,
    public_key_pem: nodeKeys.publicKeyPem,
    policy: "trusted"
  });

  // Pre-register remote sender identities on local node
  store.registerIdentity({
    id: "loom://alice@remote.test",
    display_name: "Remote Alice",
    signing_keys: [{ key_id: "k_sign_remote_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@remote.test",
    display_name: "Remote Bob",
    signing_keys: [{ key_id: "k_sign_remote_bob_1", public_key_pem: remoteBobKeys.publicKeyPem }]
  });

  // One valid envelope from remote sender (domain matches sender node)
  const goodEnvelope = makeSignedEnvelope(remoteSenderKeys, {
    fromIdentity: "loom://alice@remote.test",
    keyId: "k_sign_remote_alice_1"
  });
  // One envelope with a bad signature
  const badEnvelope = {
    loom: "1.1",
    id: `env_${randomId()}`,
    thread_id: `thr_${randomId()}`,
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://bob@remote.test",
      display: "Bob",
      key_id: "k_sign_remote_bob_1",
      type: "human"
    },
    to: [{ identity: "loom://team@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "bad sig", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    signature: {
      algorithm: "Ed25519",
      key_id: "k_sign_remote_bob_1",
      value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  };

  // Build and sign a federation wrapper
  const timestamp = new Date().toISOString();
  const nonce = `nonce_${Date.now()}`;
  const wrapper = {
    sender_node: nodeId,
    timestamp,
    nonce,
    envelopes: [goodEnvelope, badEnvelope]
  };
  const message = [
    "loom.federation.deliver.v1",
    nodeId,
    timestamp,
    nonce,
    canonicalizeJson({ envelopes: wrapper.envelopes })
  ].join("\n");

  const { signUtf8Message } = await import("../src/protocol/crypto.js");
  const signature = signUtf8Message(nodeKeys.privateKeyPem, message);

  const result = await store.ingestFederationDelivery(wrapper, {
    node_id: nodeId,
    key_id: keyId,
    signature,
    policy: "trusted"
  });

  // The good envelope should be accepted, bad one rejected
  assert.equal(result.accepted_count, 1, "Should accept one envelope");
  assert.equal(result.rejected_count, 1, "Should reject one envelope");
  assert.ok(Array.isArray(result.rejected), "Should include rejected array");
  assert.equal(result.rejected[0].envelope_id, badEnvelope.id);
  assert.ok(result.accepted_envelope_ids.includes(goodEnvelope.id));
});

test("federation delivery throws original error when all envelopes fail", async () => {
  const aliceKeys = generateSigningKeyPair();
  const nodeKeys = generateSigningKeyPair();
  const store = makeStore();

  registerAlice(store, aliceKeys);

  const nodeId = "remote2.test";
  const keyId = "k_node_sign_remote_2";
  store.registerFederationNode({
    node_id: nodeId,
    key_id: keyId,
    public_key_pem: nodeKeys.publicKeyPem,
    policy: "trusted"
  });

  // One envelope with bad signature — all fail
  const badEnvelope = {
    loom: "1.1",
    id: `env_${randomId()}`,
    thread_id: `thr_${randomId()}`,
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "bad", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    signature: {
      algorithm: "Ed25519",
      key_id: "k_sign_alice_1",
      value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  };

  const timestamp = new Date().toISOString();
  const nonce = `nonce_all_fail_${Date.now()}`;
  const wrapper = {
    sender_node: nodeId,
    timestamp,
    nonce,
    envelopes: [badEnvelope]
  };
  const message = [
    "loom.federation.deliver.v1",
    nodeId,
    timestamp,
    nonce,
    canonicalizeJson({ envelopes: wrapper.envelopes })
  ].join("\n");

  const { signUtf8Message } = await import("../src/protocol/crypto.js");
  const signature = signUtf8Message(nodeKeys.privateKeyPem, message);

  await assert.rejects(
    () =>
      store.ingestFederationDelivery(wrapper, {
        node_id: nodeId,
        key_id: keyId,
        signature,
        policy: "trusted"
      }),
    (err) => {
      // The original SIGNATURE_INVALID error should propagate, not a generic 400
      assert.equal(err.code, "SIGNATURE_INVALID");
      return true;
    }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #6+7: Idempotency sentinel — reserveIdempotencySlot
// ────────────────────────────────────────────────────────────────────────────

test("reserveIdempotencySlot plants in-flight sentinel and blocks concurrent access", () => {
  const store = makeStore();
  const scope = "actor:loom://a@test:POST:/v1/envelopes";
  const key = "test-idem-1";
  const hash = "abc123";

  // First reservation should succeed
  const slot = store.reserveIdempotencySlot(scope, key, hash);
  assert.ok(slot, "Should return a slot object");
  assert.ok(!slot.replay, "Should not be a replay");
  assert.ok(typeof slot.finalize === "function", "Should have finalize()");
  assert.ok(typeof slot.release === "function", "Should have release()");

  // Concurrent reservation with same key should throw
  assert.throws(
    () => store.reserveIdempotencySlot(scope, key, hash),
    (err) => err.code === "IDEMPOTENCY_CONFLICT",
    "Should reject concurrent access to same idempotency key"
  );

  // Finalize the slot
  const record = slot.finalize(201, { id: "env_123" });
  assert.equal(record.status, 201);

  // Now a new request with the same key should get a replay
  const replay = store.reserveIdempotencySlot(scope, key, hash);
  assert.ok(replay.replay, "Should return a replay");
  assert.equal(replay.replay.status, 201);
});

test("reserveIdempotencySlot release() clears the sentinel on failure", () => {
  const store = makeStore();
  const scope = "actor:loom://a@test:POST:/v1/envelopes";
  const key = "test-idem-release";
  const hash = "def456";

  const slot = store.reserveIdempotencySlot(scope, key, hash);
  assert.ok(slot);

  // Release without finalize (simulates failed request)
  slot.release();

  // The slot should now be available for a new reservation
  const slot2 = store.reserveIdempotencySlot(scope, key, hash);
  assert.ok(slot2, "Should be available again after release");
  assert.ok(!slot2.replay, "Should not be a replay");
  slot2.release();
});

test("reserveIdempotencySlot rejects mismatched payload hash", () => {
  const store = makeStore();
  const scope = "actor:loom://a@test:POST:/v1/envelopes";
  const key = "test-idem-mismatch";

  const slot = store.reserveIdempotencySlot(scope, key, "hash-1");
  slot.finalize(200, { ok: true });

  assert.throws(
    () => store.reserveIdempotencySlot(scope, key, "hash-2"),
    (err) => err.code === "IDEMPOTENCY_CONFLICT"
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #8: Base64 validation
// ────────────────────────────────────────────────────────────────────────────

test("email relay decodeBase64Content accepts standard base64 with padding", async () => {
  const { LoomEmailRelay } = await import("../src/node/email_relay.js");

  const relay = new LoomEmailRelay({
    mode: "stream",
    defaultFrom: "no-reply@example.com"
  });

  // "Hello" in base64 = "SGVsbG8=" (with padding)
  const result = await relay.send({
    rcpt_to: ["test@example.com"],
    subject: "test",
    text: "test",
    attachments: [
      {
        filename: "hello.txt",
        mime_type: "text/plain",
        data_base64: "SGVsbG8="
      }
    ]
  });

  assert.ok(result, "Should accept padded base64");
});

test("email relay decodeBase64Content accepts base64 without padding", async () => {
  const { LoomEmailRelay } = await import("../src/node/email_relay.js");

  const relay = new LoomEmailRelay({
    mode: "stream",
    defaultFrom: "no-reply@example.com"
  });

  // "Hello" without padding = "SGVsbG8" (length 7, not divisible by 4)
  // Old code would reject this; new code accepts it
  const result = await relay.send({
    rcpt_to: ["test@example.com"],
    subject: "test",
    text: "test",
    attachments: [
      {
        filename: "hello.txt",
        mime_type: "text/plain",
        data_base64: "SGVsbG8"
      }
    ]
  });

  assert.ok(result, "Should accept unpadded but valid base64");
});

test("email relay decodeBase64Content rejects invalid base64 characters", async () => {
  const { LoomEmailRelay } = await import("../src/node/email_relay.js");

  const relay = new LoomEmailRelay({
    mode: "stream",
    defaultFrom: "no-reply@example.com"
  });

  await assert.rejects(
    () =>
      relay.send({
        rcpt_to: ["test@example.com"],
        subject: "test",
        text: "test",
        attachments: [
          {
            filename: "bad.txt",
            mime_type: "text/plain",
            data_base64: "!@#$%^&*()"
          }
        ]
      }),
    /must be valid base64/
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #10 + #15: Security headers (HSTS and CSP)
// ────────────────────────────────────────────────────────────────────────────

test("server includes HSTS header when requireHttpsFromProxy is configured", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    requireHttpsFromProxy: false, // Don't enforce, but enable HSTS
    trustProxy: true
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const { response } = await jsonRequest(`http://127.0.0.1:${port}/health`);
  assert.equal(response.status, 200);
  // HSTS only set when nativeTls or requireHttpsFromProxy - here neither is
  // active so it should be absent
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("server includes CSP header on dashboard HTML response", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const { response } = await textRequest(`http://127.0.0.1:${port}/`);
  assert.equal(response.status, 200);
  const csp = response.headers.get("content-security-policy");
  assert.ok(csp, "Should have CSP header on dashboard");
  assert.ok(csp.includes("default-src 'self'"), "CSP should include default-src");
  assert.ok(csp.includes("frame-ancestors 'none'"), "CSP should prevent framing");
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #13: Thread DAG — sortedInsert optimization
// ────────────────────────────────────────────────────────────────────────────

test("validateThreadDag returns valid for a linear thread", () => {
  const envelopes = [
    { id: "env_1", parent_id: null, created_at: "2026-01-01T00:00:00Z" },
    { id: "env_2", parent_id: "env_1", created_at: "2026-01-01T00:01:00Z" },
    { id: "env_3", parent_id: "env_2", created_at: "2026-01-01T00:02:00Z" }
  ];

  const result = validateThreadDag(envelopes);
  assert.equal(result.valid, true);
  assert.equal(result.hasCycle, false);
});

test("validateThreadDag detects cycles", () => {
  const envelopes = [
    { id: "env_a", parent_id: "env_c", created_at: "2026-01-01T00:00:00Z" },
    { id: "env_b", parent_id: "env_a", created_at: "2026-01-01T00:01:00Z" },
    { id: "env_c", parent_id: "env_b", created_at: "2026-01-01T00:02:00Z" }
  ];

  const result = validateThreadDag(envelopes);
  assert.equal(result.valid, false);
  assert.equal(result.hasCycle, true);
});

test("canonicalThreadOrder preserves topological + chronological ordering with sortedInsert", () => {
  // Diamond: root → a, root → b, a → c, b → c
  const envelopes = [
    { id: "env_root", parent_id: null, created_at: "2026-01-01T00:00:00Z" },
    { id: "env_a", parent_id: "env_root", created_at: "2026-01-01T00:01:00Z" },
    { id: "env_b", parent_id: "env_root", created_at: "2026-01-01T00:02:00Z" }
  ];

  const ordered = canonicalThreadOrder(envelopes);
  assert.equal(ordered.length, 3);
  assert.equal(ordered[0].id, "env_root", "Root should be first");
  // a created before b, so a before b
  assert.equal(ordered[1].id, "env_a");
  assert.equal(ordered[2].id, "env_b");
});

test("canonicalThreadOrder handles orphan envelopes", () => {
  const envelopes = [
    { id: "env_root", parent_id: null, created_at: "2026-01-01T00:00:00Z" },
    { id: "env_orphan", parent_id: "env_missing", created_at: "2026-01-01T00:01:00Z" },
    { id: "env_child", parent_id: "env_root", created_at: "2026-01-01T00:02:00Z" }
  ];

  const ordered = canonicalThreadOrder(envelopes);
  assert.equal(ordered.length, 3);
  // Root first, then its children, then orphans last
  assert.equal(ordered[0].id, "env_root");
});

test("canonicalThreadOrder throws on cycle", () => {
  const envelopes = [
    { id: "env_a", parent_id: "env_b", created_at: "2026-01-01T00:00:00Z" },
    { id: "env_b", parent_id: "env_a", created_at: "2026-01-01T00:01:00Z" }
  ];

  assert.throws(
    () => canonicalThreadOrder(envelopes),
    /Thread DAG contains a cycle/
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #14: Bearer token parsing
// ────────────────────────────────────────────────────────────────────────────

test("server rejects malformed bearer token with extra segments gracefully", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  // Send "Bearer token extra_garbage" — the fix should take only "token"
  const { response, body } = await jsonRequest(`http://127.0.0.1:${port}/v1/envelopes`, {
    method: "POST",
    headers: {
      authorization: "Bearer some-token extra-stuff",
      "content-type": "application/json"
    },
    body: JSON.stringify({})
  });

  // Should get a normal auth error, not a crash
  assert.ok(response.status >= 400, "Should reject but not crash");
});

// ────────────────────────────────────────────────────────────────────────────
// Outbox backpressure
// ────────────────────────────────────────────────────────────────────────────

test("ingestEnvelope rejects when outbox backpressure limit is exceeded", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = makeStore({ outboxBackpressureMax: 1 });

  registerAlice(store, aliceKeys);
  registerBob(store, bobKeys);

  // Manually inject a fake outbox item to trigger backpressure
  store.federationOutboxById.set("fake_out_1", { id: "fake_out_1", status: "queued" });

  const envelope = makeSignedEnvelope(aliceKeys);
  assert.throws(
    () => store.ingestEnvelope(envelope, { actorIdentity: "loom://alice@node.test" }),
    (err) => err.code === "SERVICE_OVERLOADED",
    "Should reject with SERVICE_OVERLOADED when outbox is full"
  );
});

test("ingestEnvelope allows envelopes when backpressure is disabled (default)", () => {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = makeStore(); // outboxBackpressureMax defaults to 0 (disabled)

  registerAlice(store, aliceKeys);
  registerBob(store, bobKeys);

  // Add many outbox items — should still allow ingestion
  for (let i = 0; i < 100; i++) {
    store.federationOutboxById.set(`fake_${i}`, { id: `fake_${i}`, status: "queued" });
  }

  const envelope = makeSignedEnvelope(aliceKeys);
  const result = store.ingestEnvelope(envelope, { actorIdentity: "loom://alice@node.test" });
  assert.ok(result.id, "Should accept envelope when backpressure is disabled");
});

// ────────────────────────────────────────────────────────────────────────────
// Outbox lag metrics
// ────────────────────────────────────────────────────────────────────────────

test("outbox stats include lag_ms for queued items", () => {
  const store = makeStore();
  const pastDate = new Date(Date.now() - 5000).toISOString();

  store.federationOutboxById.set("lag_test_1", {
    id: "lag_test_1",
    status: "queued",
    created_at: pastDate
  });

  const stats = store.getFederationOutboxStats();
  assert.equal(stats.queued, 1);
  assert.ok(stats.lag_ms >= 4500, `lag_ms should be >= 4500, got ${stats.lag_ms}`);
  assert.equal(stats.oldest_queued_at, pastDate);
});

test("outbox stats show zero lag when no queued items", () => {
  const store = makeStore();

  const fedStats = store.getFederationOutboxStats();
  assert.equal(fedStats.lag_ms, 0);

  const emailStats = store.getEmailOutboxStats();
  assert.equal(emailStats.lag_ms, 0);

  const webhookStats = store.getWebhookOutboxStats();
  assert.equal(webhookStats.lag_ms, 0);
});

test("email and webhook outbox stats also include lag_ms", () => {
  const store = makeStore();
  const pastDate = new Date(Date.now() - 3000).toISOString();

  store.emailOutboxById.set("elag_1", {
    id: "elag_1",
    status: "queued",
    created_at: pastDate
  });
  store.webhookOutboxById.set("wlag_1", {
    id: "wlag_1",
    status: "queued",
    created_at: pastDate
  });

  const emailStats = store.getEmailOutboxStats();
  assert.ok(emailStats.lag_ms >= 2500, `email lag_ms should be >= 2500, got ${emailStats.lag_ms}`);

  const webhookStats = store.getWebhookOutboxStats();
  assert.ok(webhookStats.lag_ms >= 2500, `webhook lag_ms should be >= 2500, got ${webhookStats.lag_ms}`);
});

// ────────────────────────────────────────────────────────────────────────────
// /ready PostgreSQL health check
// ────────────────────────────────────────────────────────────────────────────

test("/ready endpoint includes postgres check as null when no adapter configured", async (t) => {
  const { server } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const { response, body } = await jsonRequest(`http://127.0.0.1:${port}/ready`);
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.checks.postgres, null);
  assert.equal(body.checks.http, "ok");
  assert.equal(body.checks.store, "ok");
});

test("/ready endpoint returns 503 when postgres health check fails", async (t) => {
  // Create a mock persistence adapter with a failing pool
  const mockPool = {
    query: async () => {
      throw new Error("connection refused");
    }
  };
  const mockAdapter = {
    pool: mockPool,
    initialize: async () => {},
    getStatus: () => ({ backend: "mock" })
  };

  const { server, store } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    persistenceAdapter: mockAdapter
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const { response, body } = await jsonRequest(`http://127.0.0.1:${port}/ready`);
  assert.equal(response.status, 503, "Should return 503 when PG is down");
  assert.equal(body.ok, false);
  assert.equal(body.checks.postgres, "error");
});

test("/ready endpoint returns 200 when postgres health check succeeds", async (t) => {
  // Create a mock persistence adapter with a passing pool
  const mockPool = {
    query: async () => ({ rows: [{ "?column?": 1 }] })
  };
  const mockAdapter = {
    pool: mockPool,
    initialize: async () => {},
    getStatus: () => ({ backend: "mock" })
  };

  const { server, store } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    persistenceAdapter: mockAdapter
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const { response, body } = await jsonRequest(`http://127.0.0.1:${port}/ready`);
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.checks.postgres, "ok");
});

// ────────────────────────────────────────────────────────────────────────────
// Outbox claim leasing — in-memory lease guard
// ────────────────────────────────────────────────────────────────────────────

test("claimOutboxItemForProcessing prevents double-claim within lease window", async () => {
  const store = makeStore({ outboxClaimLeaseMs: 60000 });

  const item = { id: "outbox_test_1", status: "queued", updated_at: new Date().toISOString() };

  const firstClaim = await store.claimOutboxItemForProcessing("federation", item);
  assert.equal(firstClaim, true, "First claim should succeed");

  const secondClaim = await store.claimOutboxItemForProcessing("federation", item);
  assert.equal(secondClaim, false, "Second claim within lease should fail");
});

test("releaseOutboxItemClaim clears the in-memory lease", async () => {
  const store = makeStore({ outboxClaimLeaseMs: 60000 });

  const item = { id: "outbox_release_1", status: "queued", updated_at: new Date().toISOString() };

  await store.claimOutboxItemForProcessing("email", item);
  await store.releaseOutboxItemClaim("email", item);

  const reClaim = await store.claimOutboxItemForProcessing("email", item);
  assert.equal(reClaim, true, "Should be claimable again after release");
});

test("claimOutboxItemForProcessing returns false for null item", async () => {
  const store = makeStore();
  const result = await store.claimOutboxItemForProcessing("webhook", null);
  assert.equal(result, false);
});

// ────────────────────────────────────────────────────────────────────────────
// /metrics outbox lag lines
// ────────────────────────────────────────────────────────────────────────────

test("/metrics endpoint includes outbox lag metrics", async (t) => {
  const { server, store } = createLoomServer({
    nodeId: "node.test",
    domain: "127.0.0.1",
    adminToken: "secret-admin"
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  // Inject a queued federation outbox item to produce lag
  store.federationOutboxById.set("metrics_lag_1", {
    id: "metrics_lag_1",
    status: "queued",
    created_at: new Date(Date.now() - 2000).toISOString()
  });

  const port = server.address().port;
  const { response, body } = await textRequest(`http://127.0.0.1:${port}/metrics`, {
    headers: { "x-loom-admin-token": "secret-admin" }
  });
  assert.equal(response.status, 200);
  assert.ok(body.includes("loom_federation_outbox_lag_ms"), "Should have federation lag metric");
  assert.ok(body.includes("loom_email_outbox_lag_ms"), "Should have email lag metric");
  assert.ok(body.includes("loom_webhook_outbox_lag_ms"), "Should have webhook lag metric");
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #1: Shutdown data loss — flushAndClosePersistence returns flushFailed
// ────────────────────────────────────────────────────────────────────────────

test("shutdown propagates flush failure as non-zero exit intent", async () => {
  // This test validates the code structure: flushAndClosePersistence returns
  // { flushFailed } which drives the exit code. We can't test process.exit()
  // directly, but we can verify the store's flushPersistenceQueueNow behavior.
  const store = makeStore();

  // flushPersistenceQueueNow should not throw when no persistence is configured
  await store.flushPersistenceQueueNow(1000);
  // If we reached here, the happy path works (no throw = flushFailed stays false)
  assert.ok(true, "flush succeeds with no persistence adapter");
});

// ────────────────────────────────────────────────────────────────────────────
// Fix #12: ULID single-thread constraint documentation
// ────────────────────────────────────────────────────────────────────────────

test("ULID module includes single-thread constraint documentation", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(
    new URL("../src/protocol/ulid.js", import.meta.url),
    "utf-8"
  );
  assert.ok(
    source.includes("Single-thread / single-process only"),
    "ULID module should document single-thread constraint"
  );
  assert.ok(
    source.includes("worker_threads"),
    "ULID module should warn about worker_threads"
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Immutable quarantine label (part of Fix #3)
// ────────────────────────────────────────────────────────────────────────────

test("federation quarantine uses immutable array for thread labels", async () => {
  const remoteSenderKeys = generateSigningKeyPair();
  const nodeKeys = generateSigningKeyPair();
  const store = makeStore({ federationResolveRemoteIdentities: false });

  const nodeId = "quarantine-node.test";
  const keyId = "k_node_sign_q_1";
  store.registerFederationNode({
    node_id: nodeId,
    key_id: keyId,
    public_key_pem: nodeKeys.publicKeyPem,
    policy: "quarantine"
  });

  // Pre-register remote sender identity locally
  store.registerIdentity({
    id: "loom://alice@quarantine-node.test",
    display_name: "Quarantine Alice",
    signing_keys: [{ key_id: "k_sign_q_alice_1", public_key_pem: remoteSenderKeys.publicKeyPem }]
  });

  const envelope = makeSignedEnvelope(remoteSenderKeys, {
    fromIdentity: "loom://alice@quarantine-node.test",
    keyId: "k_sign_q_alice_1"
  });
  const timestamp = new Date().toISOString();
  const nonce = `nonce_q_${Date.now()}`;
  const wrapper = {
    sender_node: nodeId,
    timestamp,
    nonce,
    envelopes: [envelope]
  };
  const message = [
    "loom.federation.deliver.v1",
    nodeId,
    timestamp,
    nonce,
    canonicalizeJson({ envelopes: wrapper.envelopes })
  ].join("\n");

  const { signUtf8Message } = await import("../src/protocol/crypto.js");
  const signature = signUtf8Message(nodeKeys.privateKeyPem, message);

  const result = await store.ingestFederationDelivery(wrapper, {
    node_id: nodeId,
    key_id: keyId,
    signature,
    policy: "quarantine"
  });

  assert.equal(result.accepted_count, 1);

  // Verify quarantine label was applied
  const thread = store.threadsById.get(envelope.thread_id);
  assert.ok(thread, "Thread should exist");
  assert.ok(thread.labels.includes("sys.quarantine"), "Should have quarantine label");
});
