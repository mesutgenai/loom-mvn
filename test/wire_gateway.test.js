import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { connect as connectTcp } from "node:net";
import { connect as connectTls } from "node:tls";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { LoomStore } from "../src/node/store.js";
import { generateSigningKeyPair, signUtf8Message } from "../src/protocol/crypto.js";
import { LoomWireGateway } from "../src/node/wire_gateway.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_TLS_KEY_PEM = readFileSync(join(__dirname, "fixtures", "wire_tls_key.pem"), "utf-8");
const TEST_TLS_CERT_PEM = readFileSync(join(__dirname, "fixtures", "wire_tls_cert.pem"), "utf-8");

function createLineWaiter(socket) {
  let buffer = "";
  const lines = [];
  const waiters = [];

  const flushWaiters = () => {
    for (let index = 0; index < waiters.length; ) {
      const waiter = waiters[index];
      const matchIndex = lines.findIndex(waiter.predicate);
      if (matchIndex >= 0) {
        const [line] = lines.splice(matchIndex, 1);
        waiters.splice(index, 1);
        clearTimeout(waiter.timer);
        waiter.resolve(line);
        continue;
      }
      index += 1;
    }
  };

  socket.setEncoding("utf-8");
  socket.on("data", (chunk) => {
    buffer += chunk;
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const line = buffer.slice(0, index).replace(/\r$/, "");
      buffer = buffer.slice(index + 1);
      lines.push(line);
      index = buffer.indexOf("\n");
    }
    flushWaiters();
  });

  return function waitFor(predicate, timeoutMs = 3000) {
    return new Promise((resolve, reject) => {
      const matchIndex = lines.findIndex(predicate);
      if (matchIndex >= 0) {
        const [line] = lines.splice(matchIndex, 1);
        resolve(line);
        return;
      }

      const timer = setTimeout(() => {
        const index = waiters.findIndex((entry) => entry.resolve === resolve);
        if (index >= 0) {
          waiters.splice(index, 1);
        }
        reject(new Error("Timed out waiting for gateway response"));
      }, timeoutMs);

      waiters.push({
        predicate,
        resolve,
        timer
      });
    });
  };
}

function waitForSocketTermination(socket, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    if (socket.destroyed) {
      resolve();
      return;
    }
    socket.resume();

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for socket to close"));
    }, timeoutMs);
    const onClose = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      resolve();
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("close", onClose);
      socket.off("error", onError);
    };
    socket.once("close", onClose);
    socket.once("error", onError);
  });
}

function createIdentityAndToken(store, identity, keyId, keys) {
  store.registerIdentity({
    id: identity,
    display_name: identity,
    signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
  });

  const challenge = store.createAuthChallenge({
    identity,
    key_id: keyId
  });

  const token = store.exchangeAuthToken({
    identity,
    key_id: keyId,
    challenge_id: challenge.challenge_id,
    signature: signUtf8Message(keys.privateKeyPem, challenge.nonce)
  });

  return token.access_token;
}

test("wire gateway refuses authenticated mode without TLS by default", () => {
  const store = new LoomStore({ nodeId: "node.test" });
  assert.throws(
    () =>
      new LoomWireGateway({
        store,
        enabled: true,
        host: "127.0.0.1",
        smtpEnabled: true,
        imapEnabled: false,
        requireAuth: true,
        tlsEnabled: false
      }),
    /Refusing authenticated wire gateway without TLS/
  );
});

test("wire gateway refuses insecure auth override on public bind without explicit confirmation", () => {
  const store = new LoomStore({ nodeId: "node.test" });
  assert.throws(
    () =>
      new LoomWireGateway({
        store,
        enabled: true,
        host: "0.0.0.0",
        smtpEnabled: true,
        imapEnabled: false,
        requireAuth: true,
        allowInsecureAuth: true,
        tlsEnabled: true,
        tlsKeyPem: TEST_TLS_KEY_PEM,
        tlsCertPem: TEST_TLS_CERT_PEM
      }),
    /LOOM_WIRE_ALLOW_INSECURE_AUTH=true on public bind/
  );
});

test("wire SMTP gateway accepts AUTH and submits envelope into store", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const token = createIdentityAndToken(store, "loom://alice@node.test", "k_sign_alice_1", keys);

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: true,
    smtpPort: 0,
    imapEnabled: false,
    requireAuth: true,
    allowInsecureAuth: true
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.smtp.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitFor = createLineWaiter(socket);
  await waitFor((line) => line.startsWith("220 "));

  socket.write("EHLO localhost\r\n");
  await waitFor((line) => line.startsWith("250 SIZE "));

  const plain = Buffer.from(`\u0000loom://alice@node.test\u0000${token}`, "utf-8").toString("base64");
  socket.write(`AUTH PLAIN ${plain}\r\n`);
  await waitFor((line) => line.startsWith("235 "));

  socket.write("MAIL FROM:<alice@node.test>\r\n");
  await waitFor((line) => line.startsWith("250 "));

  socket.write("RCPT TO:<bob@node.test>\r\n");
  await waitFor((line) => line.startsWith("250 "));

  socket.write("DATA\r\n");
  await waitFor((line) => line.startsWith("354 "));

  socket.write("Subject: Wire SMTP Test\r\n");
  socket.write("To: bob@node.test\r\n");
  socket.write("\r\n");
  socket.write("hello from wire smtp\r\n");
  socket.write(".\r\n");
  await waitFor((line) => line.startsWith("250 "));

  socket.write("QUIT\r\n");
  await waitFor((line) => line.startsWith("221 "));

  const threads = store.listThreads();
  assert.equal(threads.length, 1);
  const envelopes = store.getThreadEnvelopes(threads[0].id);
  assert.equal(envelopes.length, 1);
  assert.equal(envelopes[0].from.identity, "loom://alice@node.test");
});

test("wire IMAP gateway supports LOGIN LIST SELECT FETCH flow", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const identity = "loom://alice@node.test";
  const token = createIdentityAndToken(store, identity, "k_sign_alice_1", keys);

  store.submitGatewaySmtp(
    {
      to: ["bob@node.test"],
      subject: "Wire IMAP Test",
      text: "hello from imap flow"
    },
    identity
  );

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: false,
    imapEnabled: true,
    imapPort: 0,
    requireAuth: true,
    allowInsecureAuth: true
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.imap.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitFor = createLineWaiter(socket);
  await waitFor((line) => line.startsWith("* OK"));

  socket.write(`a1 LOGIN "loom://alice@node.test" "${token}"\r\n`);
  await waitFor((line) => line.startsWith("a1 OK"));

  socket.write('a2 LIST "" "*"\r\n');
  await waitFor((line) => line.startsWith("* LIST"));
  await waitFor((line) => line.startsWith("a2 OK"));

  socket.write('a3 SELECT "Sent"\r\n');
  await waitFor((line) => line.includes(" EXISTS"));
  await waitFor((line) => line.startsWith("a3 OK"));

  socket.write("a4 FETCH 1:* (UID FLAGS BODY[])\r\n");
  await waitFor((line) => line.includes(" FETCH (UID "));
  await waitFor((line) => line.startsWith("a4 OK"));

  socket.write("a5 LOGOUT\r\n");
  await waitFor((line) => line.startsWith("* BYE"));
  await waitFor((line) => line.startsWith("a5 OK"));
});

test("wire IMAP gateway supports IDLE, APPEND, MOVE, UID MOVE, and sectioned FETCH", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const identity = "loom://alice@node.test";
  const token = createIdentityAndToken(store, identity, "k_sign_alice_1", keys);

  store.createBridgeInboundEnvelope(
    {
      smtp_from: "sender@example.net",
      rcpt_to: ["alice@node.test"],
      subject: "IMAP Inbox Message",
      text: "hello inbox"
    },
    "bridge://relay@example.net"
  );

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: false,
    imapEnabled: true,
    imapPort: 0,
    requireAuth: true,
    allowInsecureAuth: true
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.imap.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitFor = createLineWaiter(socket);
  const wait = async (predicate, label) => {
    try {
      return await waitFor(predicate);
    } catch {
      throw new Error(`Timed out waiting for ${label}`);
    }
  };
  await wait((line) => line.startsWith("* OK"), "IMAP greeting");

  socket.write(`b1 LOGIN "loom://alice@node.test" "${token}"\r\n`);
  await wait((line) => line.startsWith("b1 OK"), "LOGIN completion");

  socket.write('b2 SELECT "INBOX"\r\n');
  await wait((line) => line.includes(" EXISTS"), "SELECT INBOX exists");
  await wait((line) => line.startsWith("b2 OK"), "SELECT INBOX completion");

  socket.write("b3 FETCH 1:* (UID FLAGS BODY[HEADER])\r\n");
  await wait((line) => line.includes("BODY[HEADER]"), "FETCH header payload");
  await wait((line) => line.startsWith("b3 OK"), "FETCH completion");

  socket.write("b4 IDLE\r\n");
  await wait((line) => line === "+ idling", "IDLE continuation");
  socket.write("DONE\r\n");
  await wait((line) => line.startsWith("b4 OK IDLE completed"), "IDLE completion");

  socket.write('b5 MOVE 1:* "Archive"\r\n');
  await wait((line) => line.startsWith("b5 OK MOVE completed"), "MOVE completion");

  socket.write('b6 STATUS "Archive" (MESSAGES)\r\n');
  const archiveStatus = await wait((line) => line.startsWith('* STATUS "Archive"'), "Archive STATUS payload");
  assert.match(archiveStatus, /MESSAGES\s+1\b/);
  await wait((line) => line.startsWith("b6 OK"), "Archive STATUS completion");

  socket.write('b7 SELECT "Archive"\r\n');
  await wait((line) => line.includes(" EXISTS"), "SELECT Archive exists");
  await wait((line) => line.startsWith("b7 OK"), "SELECT Archive completion");

  socket.write("b8 UID FETCH 1:* (UID BODY[TEXT])\r\n");
  await wait((line) => line.includes("BODY[TEXT]"), "UID FETCH text payload");
  await wait((line) => line.startsWith("b8 OK UID FETCH completed"), "UID FETCH completion");

  socket.write('b9 UID MOVE 1:* "Trash"\r\n');
  await wait((line) => line.startsWith("b9 OK UID MOVE completed"), "UID MOVE completion");

  socket.write('b10 STATUS "Trash" (MESSAGES)\r\n');
  const trashStatus = await wait((line) => line.startsWith('* STATUS "Trash"'), "Trash STATUS payload");
  assert.match(trashStatus, /MESSAGES\s+1\b/);
  await wait((line) => line.startsWith("b10 OK"), "Trash STATUS completion");

  socket.write('b11 APPEND "Sent" "hello appended via imap"\r\n');
  await wait((line) => line.startsWith("b11 OK APPEND completed"), "APPEND completion");

  socket.write('b12 STATUS "Sent" (MESSAGES)\r\n');
  const sentStatus = await wait((line) => line.startsWith('* STATUS "Sent"'), "Sent STATUS payload");
  assert.match(sentStatus, /MESSAGES\s+[1-9]\d*\b/);
  await wait((line) => line.startsWith("b12 OK"), "Sent STATUS completion");

  socket.write('b13 COPY 1:* "INBOX"\r\n');
  await wait((line) => line.startsWith("b13 NO COPY not supported"), "COPY limitation response");

  socket.write('b14 UID COPY 1:* "INBOX"\r\n');
  await wait((line) => line.startsWith("b14 NO UID COPY not supported"), "UID COPY limitation response");

  socket.write("b15 LOGOUT\r\n");
  await wait((line) => line.startsWith("* BYE"), "LOGOUT BYE");
  await wait((line) => line.startsWith("b15 OK"), "LOGOUT completion");
});

test("wire SMTP gateway supports STARTTLS upgrade", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const token = createIdentityAndToken(store, "loom://alice@node.test", "k_sign_alice_1", keys);

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: true,
    smtpPort: 0,
    imapEnabled: false,
    requireAuth: true,
    tlsEnabled: true,
    tlsKeyPem: TEST_TLS_KEY_PEM,
    tlsCertPem: TEST_TLS_CERT_PEM
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.smtp.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitForPlain = createLineWaiter(socket);
  await waitForPlain((line) => line.startsWith("220 "));

  socket.write("EHLO localhost\r\n");
  await waitForPlain((line) => line.includes("STARTTLS"));
  await waitForPlain((line) => line.startsWith("250 SIZE "));

  const plain = Buffer.from(`\u0000loom://alice@node.test\u0000${token}`, "utf-8").toString("base64");
  socket.write(`AUTH PLAIN ${plain}\r\n`);
  await waitForPlain((line) => line.startsWith("538 "));

  socket.write("STARTTLS\r\n");
  await waitForPlain((line) => line.startsWith("220 "));

  const tlsSocket = connectTls({
    socket,
    rejectUnauthorized: false
  });
  await once(tlsSocket, "secureConnect");
  t.after(() => {
    tlsSocket.destroy();
  });

  const waitForTls = createLineWaiter(tlsSocket);
  tlsSocket.write("EHLO localhost\r\n");
  await waitForTls((line) => line.startsWith("250 SIZE "));

  tlsSocket.write(`AUTH PLAIN ${plain}\r\n`);
  await waitForTls((line) => line.startsWith("235 "));
  tlsSocket.write("QUIT\r\n");
  await waitForTls((line) => line.startsWith("221 "));
});

test("wire IMAP gateway supports STARTTLS and extended mailbox commands", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const identity = "loom://alice@node.test";
  const token = createIdentityAndToken(store, identity, "k_sign_alice_1", keys);

  store.submitGatewaySmtp(
    {
      to: ["bob@node.test"],
      subject: "Wire IMAP STARTTLS Test",
      text: "message for STARTTLS"
    },
    identity
  );

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: false,
    imapEnabled: true,
    imapPort: 0,
    requireAuth: true,
    tlsEnabled: true,
    tlsKeyPem: TEST_TLS_KEY_PEM,
    tlsCertPem: TEST_TLS_CERT_PEM
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.imap.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitForPlain = createLineWaiter(socket);
  await waitForPlain((line) => line.startsWith("* OK"));

  socket.write("a1 CAPABILITY\r\n");
  await waitForPlain((line) => line.includes("STARTTLS"));
  await waitForPlain((line) => line.startsWith("a1 OK"));

  socket.write(`a1b LOGIN "loom://alice@node.test" "${token}"\r\n`);
  await waitForPlain((line) => line.startsWith("a1b NO [PRIVACYREQUIRED]"));

  socket.write("a2 STARTTLS\r\n");
  await waitForPlain((line) => line.startsWith("a2 OK"));

  const tlsSocket = connectTls({
    socket,
    rejectUnauthorized: false
  });
  await once(tlsSocket, "secureConnect");
  t.after(() => {
    tlsSocket.destroy();
  });

  const waitForTls = createLineWaiter(tlsSocket);
  tlsSocket.write("a3 CAPABILITY\r\n");
  const capabilityLine = await waitForTls((line) => line.startsWith("* CAPABILITY "));
  assert.equal(capabilityLine.includes("STARTTLS"), false);
  await waitForTls((line) => line.startsWith("a3 OK"));

  tlsSocket.write(`a4 LOGIN "loom://alice@node.test" "${token}"\r\n`);
  await waitForTls((line) => line.startsWith("a4 OK"));

  tlsSocket.write("a5 NAMESPACE\r\n");
  await waitForTls((line) => line.startsWith("* NAMESPACE "));
  await waitForTls((line) => line.startsWith("a5 OK"));

  tlsSocket.write('a6 SELECT "Sent"\r\n');
  await waitForTls((line) => line.includes(" EXISTS"));
  await waitForTls((line) => line.startsWith("a6 OK"));

  tlsSocket.write('a7 STATUS "Sent" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n');
  await waitForTls((line) => line.startsWith("* STATUS "));
  await waitForTls((line) => line.startsWith("a7 OK"));

  tlsSocket.write("a8 SEARCH UNSEEN\r\n");
  const unseenBefore = await waitForTls((line) => line.startsWith("* SEARCH"));
  assert.match(unseenBefore, /\* SEARCH\s+1\b/);
  await waitForTls((line) => line.startsWith("a8 OK"));

  tlsSocket.write("a9 STORE 1 +FLAGS (\\Seen)\r\n");
  await waitForTls((line) => line.includes("FETCH (FLAGS (\\Seen"));
  await waitForTls((line) => line.startsWith("a9 OK"));

  tlsSocket.write("a10 SEARCH UNSEEN\r\n");
  const unseenAfter = await waitForTls((line) => line.startsWith("* SEARCH"));
  assert.equal(unseenAfter.trim(), "* SEARCH");
  await waitForTls((line) => line.startsWith("a10 OK"));

  tlsSocket.write("a11 LOGOUT\r\n");
  await waitForTls((line) => line.startsWith("* BYE"));
  await waitForTls((line) => line.startsWith("a11 OK"));
});

test("wire gateway enforces global connection cap across SMTP and IMAP", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: true,
    smtpPort: 0,
    imapEnabled: true,
    imapPort: 0,
    requireAuth: false,
    allowInsecureAuth: true,
    maxConnections: 1,
    smtpMaxConnections: 10,
    imapMaxConnections: 10
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const smtpSocket = connectTcp(status.smtp.bound_port, "127.0.0.1");
  await once(smtpSocket, "connect");
  t.after(() => {
    smtpSocket.destroy();
  });
  const waitForSmtp = createLineWaiter(smtpSocket);
  await waitForSmtp((line) => line.startsWith("220 "));

  const imapSocket = connectTcp(status.imap.bound_port, "127.0.0.1");
  t.after(() => {
    imapSocket.destroy();
  });
  await waitForSocketTermination(imapSocket);

  assert.equal(status.max_connections.total, 1);
  const refreshedStatus = gateway.getStatus();
  assert.equal(refreshedStatus.active_connections.total, 1);
  assert.equal(refreshedStatus.active_connections.smtp, 1);
  assert.equal(refreshedStatus.active_connections.imap, 0);
});

test("wire SMTP gateway enforces message size during DATA streaming", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const keys = generateSigningKeyPair();
  const token = createIdentityAndToken(store, "loom://alice@node.test", "k_sign_alice_1", keys);

  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: true,
    smtpPort: 0,
    imapEnabled: false,
    requireAuth: true,
    allowInsecureAuth: true,
    maxMessageBytes: 64
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.smtp.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitFor = createLineWaiter(socket);
  await waitFor((line) => line.startsWith("220 "));
  socket.write("EHLO localhost\r\n");
  await waitFor((line) => line.startsWith("250 SIZE "));

  const plain = Buffer.from(`\u0000loom://alice@node.test\u0000${token}`, "utf-8").toString("base64");
  socket.write(`AUTH PLAIN ${plain}\r\n`);
  await waitFor((line) => line.startsWith("235 "));

  socket.write("MAIL FROM:<alice@node.test>\r\n");
  await waitFor((line) => line.startsWith("250 "));
  socket.write("RCPT TO:<bob@node.test>\r\n");
  await waitFor((line) => line.startsWith("250 "));
  socket.write("DATA\r\n");
  await waitFor((line) => line.startsWith("354 "));

  socket.write(`${"x".repeat(256)}\r\n`);
  await waitFor((line) => line.startsWith("552 "));

  socket.write("QUIT\r\n");
  await waitFor((line) => line.startsWith("221 "));
  assert.equal(store.listThreads().length, 0);
});

test("wire gateway closes oversized unterminated SMTP line buffers", async (t) => {
  const store = new LoomStore({ nodeId: "node.test" });
  const gateway = new LoomWireGateway({
    store,
    enabled: true,
    host: "127.0.0.1",
    smtpEnabled: true,
    smtpPort: 0,
    imapEnabled: false,
    requireAuth: false,
    allowInsecureAuth: true,
    lineBufferMaxBytes: 64,
    lineMaxBytes: 64
  });
  await gateway.start();
  t.after(async () => {
    await gateway.stop();
  });

  const status = gateway.getStatus();
  const socket = connectTcp(status.smtp.bound_port, "127.0.0.1");
  await once(socket, "connect");
  t.after(() => {
    socket.destroy();
  });

  const waitFor = createLineWaiter(socket);
  await waitFor((line) => line.startsWith("220 "));

  const closed = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Expected wire gateway to close oversized socket"));
    }, 2500);
    socket.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });

  socket.write("EHLO ");
  socket.write("x".repeat(1024));
  await closed;
});
