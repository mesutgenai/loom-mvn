import { randomBytes } from "node:crypto";

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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

function encodeRandom() {
  const bytes = randomBytes(16);
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }

  // Keep 80 bits for the randomness portion.
  const mask = (1n << 80n) - 1n;
  return encodeBase32(value & mask, 16);
}

export function generateUlid() {
  return `${encodeTime(Date.now())}${encodeRandom()}`;
}
