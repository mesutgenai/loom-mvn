import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";

const outDir = resolve(process.cwd(), "scripts", "output");
mkdirSync(outDir, { recursive: true });

const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();

const identity = {
  id: "loom://alice@node.test",
  type: "human",
  display_name: "Alice",
  signing_keys: [
    {
      key_id: "k_sign_alice_1",
      public_key_pem: publicKeyPem
    }
  ]
};

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
  created_at: new Date().toISOString(),
  priority: "normal",
  content: {
    human: {
      text: "Hello from LOOM MVN",
      format: "markdown"
    },
    structured: {
      intent: "message.general@v1",
      parameters: {}
    },
    encrypted: false
  },
  attachments: []
};

const envelope = signEnvelope(unsignedEnvelope, privateKeyPem, "k_sign_alice_1");

writeFileSync(resolve(outDir, "identity.json"), JSON.stringify(identity, null, 2));
writeFileSync(resolve(outDir, "envelope.json"), JSON.stringify(envelope, null, 2));
writeFileSync(resolve(outDir, "private_key.pem"), privateKeyPem);

console.log(`Wrote sample payloads to ${outDir}`);
