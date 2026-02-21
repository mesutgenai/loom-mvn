import test from "node:test";
import assert from "node:assert/strict";

import {
  parseLoomSrvRecord,
  parseLoomTxtRecord,
  validateDiscoveryResult,
  buildSrvQueryName,
  buildTxtQueryName,
  buildWellKnownUrl
} from "../src/protocol/discovery.js";

// ─── parseLoomSrvRecord ────────────────────────────────────────────────────

test("parseLoomSrvRecord: parses valid SRV record", () => {
  const result = parseLoomSrvRecord({ priority: 10, weight: 5, port: 8443, name: "loom.example.com." });
  assert.equal(result.priority, 10);
  assert.equal(result.weight, 5);
  assert.equal(result.port, 8443);
  assert.equal(result.target, "loom.example.com"); // trailing dot removed
});

test("parseLoomSrvRecord: uses target field", () => {
  const result = parseLoomSrvRecord({ priority: 0, weight: 0, port: 443, target: "host.example.com" });
  assert.equal(result.target, "host.example.com");
});

test("parseLoomSrvRecord: defaults for missing fields", () => {
  const result = parseLoomSrvRecord({});
  assert.equal(result.priority, 0);
  assert.equal(result.weight, 0);
  assert.equal(result.port, 443);
  assert.equal(result.target, "");
});

test("parseLoomSrvRecord: returns null for invalid input", () => {
  assert.equal(parseLoomSrvRecord(null), null);
  assert.equal(parseLoomSrvRecord("string"), null);
});

// ─── parseLoomTxtRecord ────────────────────────────────────────────────────

test("parseLoomTxtRecord: parses complete TXT record", () => {
  const result = parseLoomTxtRecord(["v=LOOM1.1; api=https://api.example.com; ws=wss://ws.example.com; wellknown=https://example.com/.well-known/loom.json"]);
  assert.equal(result.version, "LOOM1.1");
  assert.equal(result.api, "https://api.example.com");
  assert.equal(result.ws, "wss://ws.example.com");
  assert.equal(result.wellknown, "https://example.com/.well-known/loom.json");
});

test("parseLoomTxtRecord: handles split array parts", () => {
  const result = parseLoomTxtRecord(["v=LOOM1.1;", " api=https://api.example.com"]);
  assert.equal(result.version, "LOOM1.1");
  assert.equal(result.api, "https://api.example.com");
});

test("parseLoomTxtRecord: handles nested arrays", () => {
  const result = parseLoomTxtRecord([["v=LOOM1.1; api=https://api.example.com"]]);
  assert.equal(result.version, "LOOM1.1");
  assert.equal(result.api, "https://api.example.com");
});

test("parseLoomTxtRecord: handles missing fields", () => {
  const result = parseLoomTxtRecord(["v=LOOM1.1"]);
  assert.equal(result.version, "LOOM1.1");
  assert.equal(result.api, null);
  assert.equal(result.ws, null);
});

// ─── validateDiscoveryResult ───────────────────────────────────────────────

test("validateDiscoveryResult: valid result passes", () => {
  const errors = validateDiscoveryResult({
    version: "LOOM1.1",
    api: "https://api.example.com",
    ws: "wss://ws.example.com",
    wellknown: "https://example.com/.well-known/loom.json"
  });
  assert.equal(errors.length, 0);
});

test("validateDiscoveryResult: missing version", () => {
  const errors = validateDiscoveryResult({ api: "https://api.example.com" });
  assert.ok(errors.some((e) => e.field === "v"));
});

test("validateDiscoveryResult: version must start with LOOM", () => {
  const errors = validateDiscoveryResult({
    version: "SMTP1.0",
    api: "https://api.example.com"
  });
  assert.ok(errors.some((e) => e.field === "v" && e.reason.includes("LOOM")));
});

test("validateDiscoveryResult: API must use HTTPS", () => {
  const errors = validateDiscoveryResult({
    version: "LOOM1.1",
    api: "http://api.example.com"
  });
  assert.ok(errors.some((e) => e.field === "api"));
});

test("validateDiscoveryResult: WS must use WSS", () => {
  const errors = validateDiscoveryResult({
    version: "LOOM1.1",
    api: "https://api.example.com",
    ws: "ws://ws.example.com"
  });
  assert.ok(errors.some((e) => e.field === "ws"));
});

test("validateDiscoveryResult: wellknown must use HTTPS", () => {
  const errors = validateDiscoveryResult({
    version: "LOOM1.1",
    api: "https://api.example.com",
    wellknown: "http://example.com/.well-known/loom.json"
  });
  assert.ok(errors.some((e) => e.field === "wellknown"));
});

// ─── Query name builders ───────────────────────────────────────────────────

test("buildSrvQueryName", () => {
  assert.equal(buildSrvQueryName("example.com"), "_loom._tcp.example.com");
});

test("buildTxtQueryName", () => {
  assert.equal(buildTxtQueryName("example.com"), "_loom.example.com");
});

test("buildWellKnownUrl", () => {
  assert.equal(buildWellKnownUrl("example.com"), "https://example.com/.well-known/loom.json");
});
