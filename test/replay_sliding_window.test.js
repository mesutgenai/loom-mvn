import test from "node:test";
import assert from "node:assert/strict";
import { createReplayTracker, checkReplayCounter, acceptReplayCounter, replayStateKey } from "../src/protocol/replay.js";

test("replay: accepts sequential delivery", () => {
  const tracker = createReplayTracker(8);
  for (let i = 0; i < 10; i++) {
    const result = acceptReplayCounter(tracker, i);
    assert.equal(result.accepted, true, `counter ${i} should be accepted`);
  }
  assert.equal(tracker.max_seen, 9);
});

test("replay: accepts out-of-order delivery within window", () => {
  const tracker = createReplayTracker(8);
  assert.equal(acceptReplayCounter(tracker, 0).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 2).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 1).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 5).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 3).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 4).accepted, true);
  assert.equal(tracker.max_seen, 5);
});

test("replay: rejects duplicate counter", () => {
  const tracker = createReplayTracker(8);
  assert.equal(acceptReplayCounter(tracker, 0).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 1).accepted, true);
  const dup = acceptReplayCounter(tracker, 1);
  assert.equal(dup.accepted, false);
  assert.equal(dup.reason, "duplicate_counter");
});

test("replay: rejects counter too old (below window floor)", () => {
  const tracker = createReplayTracker(4);
  for (let i = 0; i < 10; i++) {
    acceptReplayCounter(tracker, i);
  }
  // max_seen = 9, window_size = 4, floor = 9 - 4 + 1 = 6
  const old = acceptReplayCounter(tracker, 5);
  assert.equal(old.accepted, false);
  assert.equal(old.reason, "counter_too_old");

  // Counter 6 should still be in window but already seen
  const dup = acceptReplayCounter(tracker, 6);
  assert.equal(dup.accepted, false);
  assert.equal(dup.reason, "duplicate_counter");
});

test("replay: rejects invalid counters", () => {
  const tracker = createReplayTracker(8);
  assert.equal(checkReplayCounter(tracker, -1).accepted, false);
  assert.equal(checkReplayCounter(tracker, 1.5).accepted, false);
  assert.equal(checkReplayCounter(tracker, NaN).accepted, false);
});

test("replay: large gap forward is accepted", () => {
  const tracker = createReplayTracker(8);
  assert.equal(acceptReplayCounter(tracker, 0).accepted, true);
  assert.equal(acceptReplayCounter(tracker, 100).accepted, true);
  assert.equal(tracker.max_seen, 100);
  // Old counter below new window floor
  assert.equal(acceptReplayCounter(tracker, 5).accepted, false);
  // Counter within new window
  assert.equal(acceptReplayCounter(tracker, 95).accepted, true);
});

test("replay: checkReplayCounter is non-mutating", () => {
  const tracker = createReplayTracker(8);
  acceptReplayCounter(tracker, 0);
  const before = tracker.max_seen;
  checkReplayCounter(tracker, 5);
  assert.equal(tracker.max_seen, before);
});

test("replay: replayStateKey combines identity and device", () => {
  assert.equal(replayStateKey("loom://alice@node.test", "device-1"), "loom://alice@node.test:device-1");
  assert.equal(replayStateKey("loom://alice@node.test", null), "loom://alice@node.test:default");
  assert.equal(replayStateKey("loom://alice@node.test", undefined), "loom://alice@node.test:default");
});
