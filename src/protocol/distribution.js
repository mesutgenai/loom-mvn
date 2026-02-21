// ─── Distribution List / Team Routing — Section 20.3 ────────────────────────
//
// Team identity routing policies for mailing list-like behavior.

const VALID_DELIVER_MODES = new Set(["all", "owners_only", "on_call"]);
const VALID_REPLY_POLICIES = new Set(["list", "sender", "all"]);
const VALID_MODERATION_MODES = new Set(["none", "owners", "agent"]);

export function validateRoutingPolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    errors.push({ field: "routing_policy", reason: "must be an object" });
    return errors;
  }

  if (policy.deliver_to_members !== undefined && !VALID_DELIVER_MODES.has(policy.deliver_to_members)) {
    errors.push({
      field: "routing_policy.deliver_to_members",
      reason: `must be one of: ${[...VALID_DELIVER_MODES].join(", ")}`
    });
  }

  if (policy.reply_policy !== undefined && !VALID_REPLY_POLICIES.has(policy.reply_policy)) {
    errors.push({
      field: "routing_policy.reply_policy",
      reason: `must be one of: ${[...VALID_REPLY_POLICIES].join(", ")}`
    });
  }

  if (policy.moderation !== undefined && !VALID_MODERATION_MODES.has(policy.moderation)) {
    errors.push({
      field: "routing_policy.moderation",
      reason: `must be one of: ${[...VALID_MODERATION_MODES].join(", ")}`
    });
  }

  return errors;
}

export function normalizeRoutingPolicy(policy) {
  if (!policy || typeof policy !== "object") {
    return {
      deliver_to_members: "all",
      reply_policy: "list",
      moderation: "none"
    };
  }

  return {
    deliver_to_members: VALID_DELIVER_MODES.has(policy.deliver_to_members)
      ? policy.deliver_to_members
      : "all",
    reply_policy: VALID_REPLY_POLICIES.has(policy.reply_policy)
      ? policy.reply_policy
      : "list",
    moderation: VALID_MODERATION_MODES.has(policy.moderation)
      ? policy.moderation
      : "none"
  };
}

export function resolveTeamRecipients(teamIdentity, routingPolicy) {
  const members = Array.isArray(teamIdentity.members) ? teamIdentity.members : [];

  switch (routingPolicy.deliver_to_members) {
    case "owners_only":
      return members.filter((m) =>
        typeof m === "object" ? m.role === "owner" : false
      );
    case "on_call":
      return members.filter((m) =>
        typeof m === "object" ? m.on_call === true : false
      );
    case "all":
    default:
      return members.map((m) => (typeof m === "object" ? m.identity : m));
  }
}

export function resolveReplyTarget(envelope, teamIdentity, routingPolicy) {
  switch (routingPolicy.reply_policy) {
    case "sender":
      return [envelope.from?.identity].filter(Boolean);
    case "all":
      return [
        envelope.from?.identity,
        teamIdentity.id
      ].filter(Boolean);
    case "list":
    default:
      return [teamIdentity.id];
  }
}

export function requiresModeration(routingPolicy) {
  return routingPolicy.moderation !== "none";
}
