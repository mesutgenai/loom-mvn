// ─── MLS Codec — Serialization/Deserialization for Wire Format and Persistence ─

export function serializeMlsGroupState(groupState) {
  if (!groupState || typeof groupState !== "object") {
    return null;
  }
  return {
    group_id: groupState.group_id,
    epoch: groupState.epoch,
    cipher_suite: groupState.cipher_suite,
    tree: (groupState.tree || []).map((leaf) =>
      leaf
        ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation || 0 }
        : null
    ),
    epoch_secret: groupState.epoch_secret,
    application_secret: groupState.application_secret,
    sender_generations: { ...groupState.sender_generations },
    retained_epoch_secrets: (groupState.retained_epoch_secrets || []).map((entry) => ({
      epoch: entry.epoch,
      secret: entry.secret
    })),
    retained_epoch_limit: groupState.retained_epoch_limit,
    tree_hash: groupState.tree_hash
  };
}

export function deserializeMlsGroupState(data) {
  if (!data || typeof data !== "object") {
    return null;
  }
  return {
    group_id: data.group_id || null,
    epoch: Number(data.epoch) || 0,
    cipher_suite: data.cipher_suite || "AES-128-GCM",
    tree: Array.isArray(data.tree)
      ? data.tree.map((leaf) =>
          leaf && typeof leaf === "object"
            ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation || 0 }
            : null
        )
      : [],
    epoch_secret: data.epoch_secret || null,
    application_secret: data.application_secret || null,
    sender_generations: data.sender_generations && typeof data.sender_generations === "object"
      ? { ...data.sender_generations }
      : {},
    retained_epoch_secrets: Array.isArray(data.retained_epoch_secrets)
      ? data.retained_epoch_secrets
          .filter((entry) => entry && typeof entry === "object")
          .map((entry) => ({
            epoch: Number(entry.epoch) || 0,
            secret: entry.secret || null
          }))
      : [],
    retained_epoch_limit: Number(data.retained_epoch_limit) || 3,
    tree_hash: data.tree_hash || null
  };
}

export function serializeMlsWelcome(welcome) {
  if (!welcome || typeof welcome !== "object") {
    return null;
  }
  return {
    group_id: welcome.group_id,
    epoch: welcome.epoch,
    tree: (welcome.tree || []).map((leaf) =>
      leaf
        ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation || 0 }
        : null
    ),
    group_secrets: (welcome.group_secrets || []).map((gs) => ({
      to: gs.to,
      encrypted_epoch_secret: gs.encrypted_epoch_secret
    })),
    tree_hash: welcome.tree_hash,
    retained_epoch_limit: welcome.retained_epoch_limit
  };
}

export function deserializeMlsWelcome(data) {
  if (!data || typeof data !== "object") {
    return null;
  }
  return {
    group_id: data.group_id || null,
    epoch: Number(data.epoch) || 0,
    tree: Array.isArray(data.tree)
      ? data.tree.map((leaf) =>
          leaf && typeof leaf === "object"
            ? { identity: leaf.identity, public_key: leaf.public_key, generation: leaf.generation || 0 }
            : null
        )
      : [],
    group_secrets: Array.isArray(data.group_secrets)
      ? data.group_secrets
          .filter((gs) => gs && typeof gs === "object")
          .map((gs) => ({
            to: gs.to,
            encrypted_epoch_secret: gs.encrypted_epoch_secret
          }))
      : [],
    tree_hash: data.tree_hash || null,
    retained_epoch_limit: data.retained_epoch_limit
  };
}

export function serializeMlsCommit(commit) {
  if (!commit || typeof commit !== "object") {
    return null;
  }
  return {
    sender_leaf_index: commit.sender_leaf_index,
    new_leaf_public_key: commit.new_leaf_public_key,
    path_secrets: (commit.path_secrets || []).map((ps) => ({
      target_leaf_index: ps.target_leaf_index,
      encrypted_secret: ps.encrypted_secret
    })),
    tree_hash: commit.tree_hash
  };
}

export function deserializeMlsCommit(data) {
  if (!data || typeof data !== "object") {
    return null;
  }
  return {
    sender_leaf_index: Number(data.sender_leaf_index) || 0,
    new_leaf_public_key: data.new_leaf_public_key || null,
    path_secrets: Array.isArray(data.path_secrets)
      ? data.path_secrets
          .filter((ps) => ps && typeof ps === "object")
          .map((ps) => ({
            target_leaf_index: Number(ps.target_leaf_index) || 0,
            encrypted_secret: ps.encrypted_secret || null
          }))
      : [],
    tree_hash: data.tree_hash || null
  };
}
