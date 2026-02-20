import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { LoomStore } from "../src/node/store.js";

function loadCorpus(name) {
  const fixtureUrl = new URL(`./fixtures/content_filter_corpus/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fixtureUrl, "utf-8"));
}

function makeAgentStore() {
  return new LoomStore({
    nodeId: "node.test",
    inboundContentFilterEnabled: true,
    inboundContentFilterProfileDefault: "balanced",
    inboundContentFilterProfileBridge: "strict",
    inboundContentFilterProfileFederation: "agent"
  });
}

test("content filter corpus: agent benign traffic avoids false positives", () => {
  const store = makeAgentStore();
  const corpus = loadCorpus("agent-benign-v1.json");
  let evaluated = 0;

  for (const vector of corpus.vectors) {
    const evaluation = store.evaluateInboundContentPolicy(
      {
        subject: vector.subject,
        text: vector.text,
        html: vector.html || "",
        attachments: Array.isArray(vector.attachments) ? vector.attachments : []
      },
      {
        source: "federation",
        actor: "loom://ops@remote.example",
        node_id: "remote.example"
      }
    );

    evaluated += 1;
    assert.equal(evaluation.profile, "agent", vector.id);
    assert.equal(evaluation.action, vector.expected_action || "allow", vector.id);
    assert.equal(evaluation.labels.includes("sys.quarantine"), false, `${vector.id} quarantine`);
    assert.equal(evaluation.labels.includes("sys.spam"), false, `${vector.id} spam label`);
  }

  const status = store.getInboundContentFilterStatus();
  assert.equal(status.profile_federation, "agent");
  assert.equal(status.rejected, 0);
  assert.equal(status.quarantined, 0);
  assert.equal(status.evaluated, evaluated);
});

test("content filter corpus: agent malicious traffic is still blocked", () => {
  const store = makeAgentStore();
  const corpus = loadCorpus("agent-malicious-v1.json");
  let expectedRejects = 0;
  let expectedQuarantines = 0;

  for (const vector of corpus.vectors) {
    if (vector.expected_action === "reject") {
      expectedRejects += 1;
    } else if (vector.expected_action === "quarantine") {
      expectedQuarantines += 1;
    }

    const evaluation = store.evaluateInboundContentPolicy(
      {
        subject: vector.subject,
        text: vector.text,
        html: vector.html || "",
        attachments: Array.isArray(vector.attachments) ? vector.attachments : []
      },
      {
        source: "federation",
        actor: "loom://attacker@remote.example",
        node_id: "remote.example"
      }
    );

    assert.equal(evaluation.profile, "agent", vector.id);
    assert.equal(evaluation.action, vector.expected_action, vector.id);
    assert.equal(evaluation.detected_categories.length > 0, true, `${vector.id} categories`);
  }

  const status = store.getInboundContentFilterStatus();
  assert.equal(status.rejected, expectedRejects);
  assert.equal(status.quarantined, expectedQuarantines);
});
