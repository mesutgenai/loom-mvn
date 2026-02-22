export const LOOM_VERSION = "1.1";
export const LOOM_RELEASE_VERSION = "0.4.1";

export const ID_PREFIX = {
  envelope: "env_",
  thread: "thr_",
  attachment: "att_",
  blob: "blob_",
  capability: "cap_",
  event: "evt_",
  signingKey: "k_sign_",
  encryptionKey: "k_enc_",
  nodeSigningKey: "k_node_sign_",
  mcpRequest: "mcp_req_"
};

export const ENVELOPE_TYPES = new Set([
  "message",
  "task",
  "approval",
  "event",
  "notification",
  "handoff",
  "data",
  "receipt",
  "workflow",
  "thread_op"
]);

export const IDENTITY_TYPES = new Set([
  "human",
  "agent",
  "team",
  "service",
  "bridge"
]);

export const RECIPIENT_ROLES = new Set([
  "primary",
  "cc",
  "observer",
  "bcc"
]);

export const PRIORITIES = new Set(["low", "normal", "high", "urgent"]);

export const THREAD_STATES = new Set([
  "active",
  "resolved",
  "archived",
  "locked",
  "merged"
]);

export const AUDIENCE_MODES = new Set(["thread", "recipients", "custom"]);
