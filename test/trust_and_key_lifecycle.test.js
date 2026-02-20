import test from "node:test";
import assert from "node:assert/strict";

import { LoomStore } from "../src/node/store.js";
import { getSigningKeyLifecycleState, isSigningKeyUsableAt } from "../src/protocol/key_lifecycle.js";
import {
  isNodeAuthorizedForIdentity,
  parseLoomIdentityAuthority,
  parseTrustAnchorBindings
} from "../src/protocol/trust.js";

test("trust: parses identity authority from loom uri", () => {
  assert.equal(parseLoomIdentityAuthority("loom://alice@Agents.Example"), "agents.example");
  assert.equal(parseLoomIdentityAuthority("bridge://alice@example.com"), null);
});

test("trust: defaults to strict identity-domain equals sender-node authority", () => {
  const decision = isNodeAuthorizedForIdentity({
    identityUri: "loom://alice@agents.example",
    senderNodeId: "agents.example"
  });
  assert.equal(decision.valid, true);

  const denied = isNodeAuthorizedForIdentity({
    identityUri: "loom://alice@agents.example",
    senderNodeId: "mail-hub.partner.example"
  });
  assert.equal(denied.valid, false);
});

test("trust: supports curated trust-anchor bindings for federated authority", () => {
  const bindings = parseTrustAnchorBindings(
    "agents.example=fed-hub.partner.example|fed-hub-dr.partner.example"
  );
  const allowed = isNodeAuthorizedForIdentity({
    identityUri: "loom://alice@agents.example",
    senderNodeId: "fed-hub.partner.example",
    trustAnchorBindings: bindings
  });
  assert.equal(allowed.valid, true);

  const denied = isNodeAuthorizedForIdentity({
    identityUri: "loom://alice@agents.example",
    senderNodeId: "rogue.partner.example",
    trustAnchorBindings: bindings
  });
  assert.equal(denied.valid, false);
});

test("store: federated identity authority check honors trust-anchor bindings", () => {
  const store = new LoomStore({
    nodeId: "local.test",
    federationTrustAnchorBindings:
      "agents.example=fed-hub.partner.example|fed-hub-dr.partner.example"
  });

  const authority = store.assertFederatedEnvelopeIdentityAuthority(
    {
      from: {
        identity: "loom://alice@agents.example"
      }
    },
    {
      node_id: "fed-hub.partner.example"
    }
  );
  assert.equal(authority.identityDomain, "agents.example");

  assert.throws(
    () =>
      store.assertFederatedEnvelopeIdentityAuthority(
        {
          from: {
            identity: "loom://alice@agents.example"
          }
        },
        {
          node_id: "untrusted.partner.example"
        }
      ),
    (error) => error?.code === "SIGNATURE_INVALID"
  );
});

test("key lifecycle: signing keys honor activation and revocation windows", () => {
  const now = Date.parse("2026-02-19T12:00:00Z");

  const active = {
    key_id: "k_active",
    status: "active",
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2026-12-31T23:59:59Z"
  };
  assert.equal(getSigningKeyLifecycleState(active, now), "active");
  assert.equal(isSigningKeyUsableAt(active, now), true);

  const pending = {
    key_id: "k_pending",
    status: "active",
    not_before: "2026-03-01T00:00:00Z"
  };
  assert.equal(getSigningKeyLifecycleState(pending, now), "pending");
  assert.equal(isSigningKeyUsableAt(pending, now), false);

  const revoked = {
    key_id: "k_revoked",
    status: "active",
    revoked_at: "2026-02-18T00:00:00Z"
  };
  assert.equal(getSigningKeyLifecycleState(revoked, now), "revoked");
  assert.equal(isSigningKeyUsableAt(revoked, now), false);
});
