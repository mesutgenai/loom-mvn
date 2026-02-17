import { randomBytes } from "node:crypto";

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RANDOM_BITS = 80n;
const RANDOM_MASK = (1n << RANDOM_BITS) - 1n;

function encodeBase32(value, length) {
  let output = "";
  for (let idx = length - 1; idx >= 0; idx -= 1) {
    const mod = value % 32n;
    output = ENCODING[Number(mod)] + output;
    value /= 32n;
  }
  return output;
}

function encodeTime(nowMs) {
  return encodeBase32(BigInt(nowMs), 10);
}

function seedRandom() {
  const bytes = randomBytes(16);
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value & RANDOM_MASK;
}

let lastTimestamp = 0;
let lastRandom = 0n;

export function generateUlid() {
  const now = Date.now();

  if (now === lastTimestamp) {
    // Same millisecond — increment the random portion for monotonicity.
    lastRandom += 1n;
    if (lastRandom > RANDOM_MASK) {
      // Overflow: extremely unlikely (2^80 calls in 1 ms), but handle it.
      throw new Error("ULID random overflow within the same millisecond");
    }
  } else {
    lastTimestamp = now;
    lastRandom = seedRandom();
  }

  return `${encodeTime(now)}${encodeBase32(lastRandom, 16)}`;
}
