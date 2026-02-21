import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";

function envId() {
  return `env_${generateUlid()}`;
}
function thrId() {
  return `thr_${generateUlid()}`;
}

function setupStore(options = {}) {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test", ...options });
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    type: "human",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    type: "human",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: bobKeys.publicKeyPem }]
  });
  return { store, aliceKeys, bobKeys };
}

function makeSignedEnvelope(privateKeyPem, keyId, overrides = {}) {
  const threadId = overrides.thread_id || thrId();
  const envelope = {
    loom: "1.1",
    id: envId(),
    thread_id: threadId,
    parent_id: overrides.parent_id || null,
    type: overrides.type || "message",
    from: overrides.from || {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: keyId,
      type: "human"
    },
    to: overrides.to || [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: overrides.created_at || new Date().toISOString(),
    priority: overrides.priority || "normal",
    content: overrides.content || {
      human: { text: "Hello Bob!", format: "plaintext" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: overrides.attachments || [],
    ...overrides
  };
  return signEnvelope(envelope, privateKeyPem, keyId);
}

// ══════════════════════════════════════════════════════════════════════════════
// Receipts Integration
// ══════════════════════════════════════════════════════════════════════════════

test("receipts: generateDeliveryReceipt creates and ingests a receipt", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  const receipt = store.generateDeliveryReceipt(original);
  assert.equal(receipt.type, "receipt");
  assert.equal(receipt.thread_id, threadId);
  assert.equal(receipt.parent_id, original.id);
  assert.equal(receipt.content.structured.intent, "receipt.delivered@v1");
  assert.equal(receipt.content.structured.parameters.original_envelope_id, original.id);
});

test("receipts: generateReadReceipt creates read receipt", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  const receipt = store.generateReadReceipt(original, {
    fromIdentity: "loom://bob@node.test",
    userConfirmed: true
  });
  assert.equal(receipt.content.structured.intent, "receipt.read@v1");
  assert.ok(receipt.content.structured.parameters.read_at);
});

test("receipts: generateFailureReceipt creates failure receipt", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  const receipt = store.generateFailureReceipt(original, {
    reason: "delivery_timeout",
    details: "Node unreachable"
  });
  assert.equal(receipt.content.structured.intent, "receipt.failed@v1");
  assert.equal(receipt.content.structured.parameters.reason, "delivery_timeout");
});

// ══════════════════════════════════════════════════════════════════════════════
// Deletion & Content Erasure Integration
// ══════════════════════════════════════════════════════════════════════════════

test("deletion: deleteEnvelopeContent erases content and retains skeleton", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  const erased = store.deleteEnvelopeContent(original.id, "loom://alice@node.test");
  assert.equal(erased.content.human.text, "[deleted]");
  assert.deepEqual(erased.content.structured.parameters, {});
  assert.equal(erased.meta.deleted, true);
  assert.ok(erased.meta.deleted_at);
  // Skeleton fields preserved
  assert.equal(erased.id, original.id);
  assert.equal(erased.thread_id, original.thread_id);
});

test("deletion: deleteEnvelopeContent throws for missing envelope", () => {
  const { store } = setupStore();
  assert.throws(() => store.deleteEnvelopeContent("env_nonexistent", "loom://alice@node.test"), {
    message: /not found/i
  });
});

test("deletion: deleteEnvelopeContent blocks on legal hold", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  // Add legal hold label to thread
  const thread = store.threadsById.get(threadId);
  thread.labels = [...(thread.labels || []), "sys.legal_hold"];

  assert.throws(() => store.deleteEnvelopeContent(original.id, "loom://alice@node.test"), {
    message: /LEGAL_HOLD/
  });
});

test("deletion: cryptoShredThread erases all thread envelopes", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed1 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed1);
  const signed2 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: signed1.id
  });
  store.ingestEnvelope(signed2);

  const record = store.cryptoShredThread(threadId, 1, "loom://alice@node.test");
  assert.equal(record.thread_id, threadId);
  assert.equal(record.keys_destroyed, true);

  // Both envelopes should be erased
  const env1 = store.envelopesById.get(signed1.id);
  const env2 = store.envelopesById.get(signed2.id);
  assert.equal(env1.content.human.text, "[deleted]");
  assert.equal(env2.content.human.text, "[deleted]");
});

// ══════════════════════════════════════════════════════════════════════════════
// Retention Enforcement Integration
// ══════════════════════════════════════════════════════════════════════════════

test("retention: enforceRetentionPolicies erases expired envelopes", () => {
  const { store, aliceKeys } = setupStore({
    retentionPolicies: [{ label: "sys.trash", retention_days: 1 }]
  });
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    created_at: new Date(Date.now() - 2 * 86400000).toISOString() // 2 days ago
  });
  const original = store.ingestEnvelope(signed);

  // Add trash label to thread
  const thread = store.threadsById.get(threadId);
  thread.labels = [...(thread.labels || []), "sys.trash"];

  const result = store.enforceRetentionPolicies();
  assert.equal(result.expired_count, 1);
  assert.equal(result.erased_count, 1);

  const erased = store.envelopesById.get(original.id);
  assert.equal(erased.meta.deleted, true);
});

test("retention: legal hold blocks retention enforcement", () => {
  const { store, aliceKeys } = setupStore({
    retentionPolicies: [{ label: "sys.trash", retention_days: 1 }]
  });
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    created_at: new Date(Date.now() - 2 * 86400000).toISOString()
  });
  store.ingestEnvelope(signed);

  const thread = store.threadsById.get(threadId);
  thread.labels = ["sys.trash", "sys.legal_hold"];

  const result = store.enforceRetentionPolicies();
  assert.equal(result.expired_count, 0);
  assert.equal(result.erased_count, 0);
});

// ══════════════════════════════════════════════════════════════════════════════
// Channel Rules Integration
// ══════════════════════════════════════════════════════════════════════════════

test("channel_rules: rules apply labels on ingestion", () => {
  const { store, aliceKeys } = setupStore({
    channelRules: [
      {
        condition: { intent: "message.general@v1" },
        action: { type: "label", add: ["sys.important"] }
      }
    ]
  });
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const thread = store.threadsById.get(threadId);
  assert.ok(thread.labels.includes("sys.important"));
});

test("channel_rules: quarantine rule adds quarantine label and meta", () => {
  const { store, aliceKeys } = setupStore({
    channelRules: [
      {
        condition: { sender: "loom://alice@node.test" },
        action: { type: "quarantine" }
      }
    ]
  });
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const stored = store.ingestEnvelope(signed);

  const thread = store.threadsById.get(threadId);
  assert.ok(thread.labels.includes("sys.quarantine"));
  assert.equal(stored.meta.quarantined, true);
});

test("channel_rules: setChannelRules updates rules", () => {
  const { store } = setupStore();
  store.setChannelRules([
    { condition: { intent: "x" }, action: { type: "label", add: ["y"] } }
  ]);
  assert.equal(store.channelRules.length, 1);
});

// ══════════════════════════════════════════════════════════════════════════════
// Autoresponder Integration
// ══════════════════════════════════════════════════════════════════════════════

test("autoresponder: auto-reply generated on ingestion", () => {
  const { store, aliceKeys } = setupStore();

  // Set autoresponder for Bob
  store.setAutoresponderRule("loom://bob@node.test", {
    message: "I'm out of office.",
    frequency_limit: "once_per_sender"
  });

  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  // Check that an auto-reply was ingested into the thread
  const thread = store.threadsById.get(threadId);
  assert.ok(thread.envelope_ids.length >= 2); // original + auto-reply
  const autoReply = store.envelopesById.get(thread.envelope_ids[1]);
  assert.equal(autoReply.type, "notification");
  assert.equal(autoReply.content.structured.intent, "notification.autoreply@v1");
  assert.equal(autoReply.content.human.text, "I'm out of office.");
});

test("autoresponder: does not auto-reply to auto-replies (loop prevention)", () => {
  const { store, aliceKeys } = setupStore();

  store.setAutoresponderRule("loom://bob@node.test", { message: "OOO" });
  store.setAutoresponderRule("loom://alice@node.test", { message: "Also OOO" });

  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  // Should have original + Bob's auto-reply, but NOT a loop from Alice
  const thread = store.threadsById.get(threadId);
  const types = thread.envelope_ids.map((id) => store.envelopesById.get(id).type);
  const autoReplies = types.filter((t) => t === "notification");
  // Only 1 auto-reply (Bob's), not 2 (would be a loop)
  assert.equal(autoReplies.length, 1);
});

test("autoresponder: once_per_sender frequency limiting", () => {
  const { store, aliceKeys } = setupStore();
  store.setAutoresponderRule("loom://bob@node.test", {
    message: "OOO",
    frequency_limit: "once_per_sender"
  });

  const threadId = thrId();
  const signed1 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed1);
  const signed2 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: signed1.id
  });
  store.ingestEnvelope(signed2);

  const thread = store.threadsById.get(threadId);
  const autoReplies = thread.envelope_ids
    .map((id) => store.envelopesById.get(id))
    .filter((e) => e.content?.structured?.intent === "notification.autoreply@v1");
  assert.equal(autoReplies.length, 1); // Only one auto-reply despite 2 messages
});

test("autoresponder: setAutoresponderRule validates rule", () => {
  const { store } = setupStore();
  assert.throws(() => store.setAutoresponderRule("loom://bob@node.test", { message: "" }), {
    message: /non-empty string/i
  });
});

test("autoresponder: remove rule with null", () => {
  const { store } = setupStore();
  store.setAutoresponderRule("loom://bob@node.test", { message: "OOO" });
  assert.ok(store.autoresponderRules.has("loom://bob@node.test"));
  store.setAutoresponderRule("loom://bob@node.test", null);
  assert.equal(store.autoresponderRules.has("loom://bob@node.test"), false);
});

// ══════════════════════════════════════════════════════════════════════════════
// Distribution / Team Routing Integration
// ══════════════════════════════════════════════════════════════════════════════

test("distribution: setIdentityRoutingPolicy stores policy", () => {
  const { store } = setupStore();
  const policy = store.setIdentityRoutingPolicy("loom://alice@node.test", {
    deliver_to_members: "all",
    reply_policy: "list"
  });
  assert.equal(policy.deliver_to_members, "all");
  assert.equal(policy.reply_policy, "list");
});

test("distribution: setIdentityRoutingPolicy throws for unknown identity", () => {
  const { store } = setupStore();
  assert.throws(
    () => store.setIdentityRoutingPolicy("loom://unknown@node.test", {}),
    { message: /not found/i }
  );
});

test("distribution: resolveDistributionRecipients expands team members", () => {
  const { store } = setupStore();
  const teamIdentity = store.identities.get("loom://alice@node.test");
  teamIdentity.routing_policy = { deliver_to_members: "all", reply_policy: "list", moderation: "none" };
  teamIdentity.members = [
    { identity: "loom://member1@node.test", role: "member" },
    { identity: "loom://member2@node.test", role: "owner" }
  ];

  const expanded = store.resolveDistributionRecipients({
    to: [{ identity: "loom://alice@node.test", role: "primary" }]
  });
  assert.equal(expanded.length, 2);
  assert.equal(expanded[0].identity, "loom://member1@node.test");
  assert.equal(expanded[0]._expanded_from, "loom://alice@node.test");
});

// ══════════════════════════════════════════════════════════════════════════════
// Search Validation Integration
// ══════════════════════════════════════════════════════════════════════════════

test("search: validateAndSearchEnvelopes validates query", () => {
  const { store } = setupStore();
  assert.throws(
    () => store.validateAndSearchEnvelopes({ limit: -5 }, "loom://alice@node.test"),
    { message: /integer between/i }
  );
});

test("search: validateAndSearchEnvelopes passes valid queries", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const result = store.validateAndSearchEnvelopes(
    { q: "Hello" },
    "loom://alice@node.test"
  );
  assert.equal(result.total, 1);
});

// ══════════════════════════════════════════════════════════════════════════════
// Import/Export Integration
// ══════════════════════════════════════════════════════════════════════════════

test("import/export: exportMailbox creates valid package", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const pkg = store.exportMailbox();
  assert.equal(pkg.loom, "1.1");
  assert.equal(pkg.format, "loom");
  assert.ok(pkg.thread_count > 0);
  assert.ok(pkg.envelope_count > 0);
  assert.ok(Array.isArray(pkg.threads));
  assert.ok(Array.isArray(pkg.envelopes));
});

test("import/export: exportMailbox with identity filter", () => {
  const { store, aliceKeys, bobKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const pkg = store.exportMailbox({ identityFilter: "loom://alice@node.test" });
  assert.ok(pkg.thread_count > 0);
});

test("import/export: importMailbox creates threads and envelopes", () => {
  const { store } = setupStore();
  const result = store.importMailbox({
    format: "loom",
    threads: [
      {
        id: "thr_import_1",
        subject: "Imported Thread",
        state: "active",
        participants: [{ identity: "loom://alice@node.test" }],
        labels: [],
        envelope_ids: ["env_import_1"],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ],
    envelopes: [
      {
        id: "env_import_1",
        thread_id: "thr_import_1",
        type: "message",
        from: { identity: "loom://alice@node.test" },
        to: [{ identity: "loom://bob@node.test", role: "primary" }],
        created_at: new Date().toISOString(),
        content: { human: { text: "imported message" } }
      }
    ]
  }, "loom://alice@node.test");

  assert.equal(result.thread_count, 1);
  assert.equal(result.envelope_count, 1);

  const thread = store.threadsById.get("thr_import_1");
  assert.ok(thread);
  assert.ok(thread.labels.includes("sys.imported"));

  const envelope = store.envelopesById.get("env_import_1");
  assert.ok(envelope);
  assert.equal(envelope.meta.imported, true);
});

test("import/export: importMailbox validates payload", () => {
  const { store } = setupStore();
  assert.throws(() => store.importMailbox(null, "loom://alice@node.test"), {
    message: /must be an object/i
  });
});

test("import/export: importMailbox skips duplicate envelopes", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);

  const result = store.importMailbox({
    format: "loom",
    threads: [],
    envelopes: [
      {
        id: original.id, // duplicate
        thread_id: threadId,
        type: "message",
        from: { identity: "loom://alice@node.test" },
        to: [],
        created_at: new Date().toISOString(),
        content: { human: { text: "dup" } }
      }
    ]
  }, "loom://alice@node.test");

  assert.equal(result.envelope_count, 0); // skipped
});

// ══════════════════════════════════════════════════════════════════════════════
// Event Log Integration
// ══════════════════════════════════════════════════════════════════════════════

test("events: envelope ingestion emits event", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const events = store.getEventsSince(null);
  assert.ok(events.length >= 1);
  const event = events.find((e) => e.payload.envelope_id === signed.id);
  assert.ok(event);
  assert.equal(event.type, "envelope.new");
  assert.equal(event.payload.thread_id, threadId);
});

test("events: getEventsSince with cursor returns subsequent events", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed1 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed1);

  const events1 = store.getEventsSince(null);
  const cursor = events1[0].cursor;

  const signed2 = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: signed1.id
  });
  store.ingestEnvelope(signed2);

  const events2 = store.getEventsSince(cursor);
  assert.ok(events2.length >= 1);
  assert.ok(events2.every((e) => e.event_id !== events1[0].event_id));
});

test("events: receipt generates receipt event type", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  const original = store.ingestEnvelope(signed);
  store.generateDeliveryReceipt(original);

  const events = store.getEventsSince(null);
  const receiptEvents = events.filter((e) => e.type === "receipt.delivered");
  assert.ok(receiptEvents.length >= 1);
});

// ══════════════════════════════════════════════════════════════════════════════
// State Serialization Integration
// ══════════════════════════════════════════════════════════════════════════════

test("state: channel rules survive serialization round-trip", () => {
  const { store } = setupStore({
    channelRules: [
      { condition: { intent: "task.create@v1" }, action: { type: "label", add: ["important"] } }
    ]
  });

  const state = store.toSerializableState();
  assert.ok(Array.isArray(state.channel_rules));
  assert.equal(state.channel_rules.length, 1);

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);
  assert.equal(store2.channelRules.length, 1);
});

test("state: retention policies survive serialization round-trip", () => {
  const { store } = setupStore({
    retentionPolicies: [{ label: "sys.trash", retention_days: 30 }]
  });

  const state = store.toSerializableState();
  assert.ok(Array.isArray(state.retention_policies));

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);
  assert.ok(store2.retentionPolicies.length > 0);
  assert.equal(store2.retentionPolicies[0].label, "sys.trash");
});

test("state: autoresponder rules survive serialization round-trip", () => {
  const { store } = setupStore();
  store.setAutoresponderRule("loom://bob@node.test", {
    message: "I'm out",
    frequency_limit: "once_per_sender"
  });

  const state = store.toSerializableState();
  assert.ok(Array.isArray(state.autoresponder_rules));
  assert.equal(state.autoresponder_rules.length, 1);
  assert.equal(state.autoresponder_rules[0].identity, "loom://bob@node.test");

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);
  assert.ok(store2.autoresponderRules.has("loom://bob@node.test"));
  assert.equal(store2.autoresponderRules.get("loom://bob@node.test").message, "I'm out");
});

test("state: autoresponder sent history survives round-trip", () => {
  const { store, aliceKeys } = setupStore();
  store.setAutoresponderRule("loom://bob@node.test", { message: "OOO" });

  const threadId = thrId();
  const signed = makeSignedEnvelope(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(signed);

  const state = store.toSerializableState();
  assert.ok(Array.isArray(state.autoresponder_sent_history));

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);
  assert.ok(store2.autoresponderSentHistory.has("loom://bob@node.test"));
});

// ══════════════════════════════════════════════════════════════════════════════
// Blob Validation Integration
// ══════════════════════════════════════════════════════════════════════════════

test("blob: validateBlobPayload returns errors for invalid input", () => {
  const { store } = setupStore();
  const errors = store.validateBlobPayload(null);
  assert.ok(errors.length > 0);
});

test("blob: validateBlobPayload accepts valid payload", () => {
  const { store } = setupStore();
  const errors = store.validateBlobPayload({
    filename: "test.pdf",
    mime_type: "application/pdf",
    size_bytes: 1024
  });
  assert.equal(errors.length, 0);
});

// ══════════════════════════════════════════════════════════════════════════════
// Rate Limit Headers Integration
// ══════════════════════════════════════════════════════════════════════════════

test("rate_limit: buildRateLimitResponseHeaders returns correct headers", () => {
  const { store } = setupStore();
  const headers = store.buildRateLimitResponseHeaders({
    limit: 100,
    remaining: 95,
    reset: "2025-06-01T12:00:00Z"
  });
  assert.equal(headers["X-LOOM-RateLimit-Limit"], "100");
  assert.equal(headers["X-LOOM-RateLimit-Remaining"], "95");
  assert.equal(headers["X-LOOM-RateLimit-Reset"], "2025-06-01T12:00:00Z");
});
