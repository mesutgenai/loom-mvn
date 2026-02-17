import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LoomEmailRelay, createEmailRelayFromEnv } from "../src/node/email_relay.js";

function generateRsaPrivateKeyPem() {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 1024,
    privateKeyEncoding: {
      type: "pkcs1",
      format: "pem"
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    }
  });

  return privateKey;
}

test("email relay enables DKIM config when complete options are provided", () => {
  const relay = new LoomEmailRelay({
    mode: "stream",
    smtpDkimDomainName: "example.com",
    smtpDkimKeySelector: "mail",
    smtpDkimPrivateKeyPem: generateRsaPrivateKeyPem()
  });

  const status = relay.getStatus();
  assert.equal(status.enabled, true);
  assert.equal(status.mode, "stream");
  assert.equal(status.dkim_enabled, true);
  assert.equal(status.dkim_domain, "example.com");
  assert.equal(status.dkim_selector, "mail");
});

test("email relay rejects partial DKIM configuration", () => {
  assert.throws(
    () =>
      new LoomEmailRelay({
        mode: "stream",
        smtpDkimDomainName: "example.com",
        smtpDkimKeySelector: "mail"
      }),
    /DKIM requires domain, selector, and private key/
  );
});

test("email relay loads DKIM private key from file", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "loom-relay-dkim-"));
  const keyFile = join(tempDir, "dkim.key");
  writeFileSync(keyFile, generateRsaPrivateKeyPem(), "utf-8");

  try {
    const relay = createEmailRelayFromEnv({
      mode: "stream",
      smtpDkimDomainName: "example.com",
      smtpDkimKeySelector: "mail",
      smtpDkimPrivateKeyFile: keyFile
    });

    const status = relay.getStatus();
    assert.equal(status.enabled, true);
    assert.equal(status.dkim_enabled, true);
    assert.equal(status.dkim_domain, "example.com");
    assert.equal(status.dkim_selector, "mail");
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
