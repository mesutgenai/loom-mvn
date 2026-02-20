/**
 * Sliding-window replay protection for store-and-forward delivery.
 *
 * Tolerates out-of-order delivery, retries, and multi-device sending
 * while bounding memory usage. Each tracker is keyed on
 * (sender_identity, sender_device_id, epoch).
 *
 * Algorithm:
 *   - counter > max_seen: accept and advance window
 *   - counter in [max_seen - W + 1, max_seen] and not seen: accept
 *   - counter < max_seen - W + 1: reject (too old)
 *   - counter already seen: reject (duplicate)
 */

const DEFAULT_WINDOW_SIZE = 64;

export function createReplayTracker(windowSize = DEFAULT_WINDOW_SIZE) {
  return {
    max_seen: -1,
    window: new Set(),
    window_size: windowSize
  };
}

export function checkReplayCounter(tracker, counter) {
  if (!Number.isInteger(counter) || counter < 0) {
    return { accepted: false, reason: "invalid_counter" };
  }

  // First message ever
  if (tracker.max_seen < 0) {
    return { accepted: true };
  }

  // Counter ahead of window: always accept
  if (counter > tracker.max_seen) {
    return { accepted: true };
  }

  // Counter too old: below window floor
  const windowFloor = tracker.max_seen - tracker.window_size + 1;
  if (counter < windowFloor) {
    return { accepted: false, reason: "counter_too_old" };
  }

  // Duplicate: already seen within window
  if (tracker.window.has(counter)) {
    return { accepted: false, reason: "duplicate_counter" };
  }

  // Within window and not seen: accept
  return { accepted: true };
}

export function acceptReplayCounter(tracker, counter) {
  const result = checkReplayCounter(tracker, counter);
  if (!result.accepted) {
    return result;
  }

  if (counter > tracker.max_seen) {
    // Advance window, prune entries that fall below new floor
    const newFloor = counter - tracker.window_size + 1;
    if (newFloor > 0) {
      for (const seen of tracker.window) {
        if (seen < newFloor) {
          tracker.window.delete(seen);
        }
      }
    }
    tracker.max_seen = counter;
  }

  tracker.window.add(counter);
  return { accepted: true };
}

export function replayStateKey(senderIdentity, deviceId) {
  const device = String(deviceId || "default").trim();
  return `${senderIdentity}:${device}`;
}
