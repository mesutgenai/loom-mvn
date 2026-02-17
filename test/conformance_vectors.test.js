import test from "node:test";
import assert from "node:assert/strict";

import { canonicalizeEnvelope, canonicalizeJson } from "../src/protocol/canonical.js";
import { generateSigningKeyPair, signEnvelope, verifyEnvelopeSignature } from "../src/protocol/crypto.js";

const CANONICAL_JSON_VECTORS = [
  {
    name: "sorts object keys recursively",
    input: {
      z: 1,
      a: {
        y: true,
        b: [3, 2, 1]
      }
    },
    expected: '{"a":{"b":[3,2,1],"y":true},"z":1}'
  },
  {
    name: "preserves array order and normalized primitive encodings",
    input: {
      n: -0,
      list: ["x", 1.5, false, null]
    },
    expected: '{"list":["x",1.5,false,null],"n":0}'
  }
];

test("conformance vectors: canonical JSON golden outputs", () => {
  for (const vector of CANONICAL_JSON_VECTORS) {
    assert.equal(canonicalizeJson(vector.input), vector.expected, vector.name);
  }
});

test("conformance vectors: canonical JSON rejects lone surrogates", () => {
  assert.throws(
    () => canonicalizeJson({ bad: "\ud800" }),
    /unpaired surrogate/
  );
});

test("conformance vectors: envelope signing canonicalization is stable", () => {
  const keys = generateSigningKeyPair();
  const unsignedEnvelope = {
    loom: "1.1",
    id: "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    thread_id: "thr_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: "2026-02-17T00:00:00Z",
    priority: "normal",
    content: {
      human: { text: "Conformance vector", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: { hello: "world" } },
      encrypted: false
    },
    attachments: []
  };

  const signed = signEnvelope(unsignedEnvelope, keys.privateKeyPem, "k_sign_alice_1");
  assert.equal(
    verifyEnvelopeSignature(signed, {
      k_sign_alice_1: keys.publicKeyPem
    }),
    true
  );

  const canonicalA = canonicalizeEnvelope(signed);
  const canonicalB = canonicalizeEnvelope(signed);
  assert.equal(canonicalA, canonicalB);
  assert.equal(canonicalA.includes("signature"), false);
  assert.equal(canonicalA.includes("meta"), false);
});
