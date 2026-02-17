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

test("email relay maps rendered attachments into nodemailer mail payload", async () => {
  const relay = new LoomEmailRelay({
    mode: "stream",
    defaultFrom: "no-reply@example.com"
  });

  let sentMail = null;
  relay.transporter = {
    sendMail: async (mail) => {
      sentMail = mail;
      return {
        messageId: "relay-msg-1",
        accepted: ["alice@example.com"],
        rejected: [],
        response: "250 queued"
      };
    }
  };

  const result = await relay.send({
    smtp_from: "no-reply@example.com",
    rcpt_to: ["alice@example.com"],
    subject: "Attachment test",
    text: "hello",
    attachments: [
      {
        filename: "note.txt",
        mime_type: "text/plain",
        disposition: "inline",
        content_id: "cid-note",
        data_base64: Buffer.from("hello attachment", "utf-8").toString("base64")
      }
    ]
  });

  assert.equal(result.provider_message_id, "relay-msg-1");
  assert.equal(Array.isArray(sentMail?.attachments), true);
  assert.equal(sentMail.attachments.length, 1);
  assert.equal(sentMail.attachments[0].filename, "note.txt");
  assert.equal(sentMail.attachments[0].contentType, "text/plain");
  assert.equal(sentMail.attachments[0].contentDisposition, "inline");
  assert.equal(sentMail.attachments[0].cid, "cid-note");
  assert.equal(sentMail.attachments[0].content.toString("utf-8"), "hello attachment");
});

test("email relay rejects invalid attachment base64 payloads", async () => {
  const relay = new LoomEmailRelay({
    mode: "stream",
    defaultFrom: "no-reply@example.com"
  });
  relay.transporter = {
    sendMail: async () => ({ messageId: "relay-msg-2", accepted: [], rejected: [], response: "250 queued" })
  };

  await assert.rejects(
    relay.send({
      smtp_from: "no-reply@example.com",
      rcpt_to: ["alice@example.com"],
      subject: "Invalid attachment",
      text: "test",
      attachments: [
        {
          filename: "broken.txt",
          mime_type: "text/plain",
          data_base64: "%%%invalid-base64%%%"
        }
      ]
    }),
    /valid base64/
  );
});
