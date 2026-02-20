import { verifyEnvelopeSignature } from "../../protocol/crypto.js";
import { verifyDelegationChainOrThrow } from "../../protocol/delegation.js";
import { validateEnvelopeOrThrow } from "../../protocol/envelope.js";
import { LoomError } from "../../protocol/errors.js";
import { isIdentity } from "../../protocol/ids.js";
import { canonicalThreadOrder, validateThreadDag } from "../../protocol/thread.js";
import { resolveE2eeProfile, validateEncryptedContentShape, validateEncryptionEpochParameters } from "../../protocol/e2ee.js";

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

const THREAD_OP_TO_GRANT = {
  "thread.add_participant@v1": "add_participant",
  "thread.remove_participant@v1": "remove_participant",
  "thread.update@v1": "label",
  "thread.resolve@v1": "resolve",
  "thread.archive@v1": "archive",
  "thread.lock@v1": "lock",
  "thread.reopen@v1": "admin",
  "thread.delegate@v1": "delegate",
  "thread.fork@v1": "fork",
  "thread.merge@v1": "merge",
  "thread.link@v1": "forward",
  "encryption.epoch@v1": "admin",
  "encryption.rotate@v1": "admin",
  "capability.revoked@v1": "admin",
  "capability.spent@v1": "admin"
};

function ensureSenderReplayStateMap(thread) {
  if (!thread.encryption || typeof thread.encryption !== "object" || Array.isArray(thread.encryption)) {
    thread.encryption = {
      enabled: false,
      profile: null,
      key_epoch: 0,
      sender_replay: {}
    };
  }
  const senderReplay = thread.encryption.sender_replay;
  if (!senderReplay || typeof senderReplay !== "object" || Array.isArray(senderReplay)) {
    thread.encryption.sender_replay = {};
  }
  return thread.encryption.sender_replay;
}

function normalizeSenderReplayStateEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return null;
  }
  const epoch = Number(entry.epoch);
  const replayCounter = Number(entry.replay_counter);
  const profileCommitment = String(entry.profile_commitment || "").trim();
  const profile = String(entry.profile || "").trim();
  if (!Number.isInteger(epoch) || epoch < 0) {
    return null;
  }
  if (!Number.isInteger(replayCounter) || replayCounter < 0) {
    return null;
  }
  if (!profileCommitment) {
    return null;
  }
  return {
    epoch,
    replay_counter: replayCounter,
    profile_commitment: profileCommitment,
    profile: profile || null
  };
}

function recordSenderReplayStateOrThrow(thread, envelope, profileId, epoch, options = {}) {
  const senderIdentity = String(envelope?.from?.identity || "").trim();
  if (!senderIdentity) {
    throw new LoomError("ENVELOPE_INVALID", "Encrypted envelope sender identity is missing", 400, {
      thread_id: thread.id,
      field: "from.identity"
    });
  }

  const replayCounter = Number(envelope?.content?.replay_counter);
  const profileCommitment = String(envelope?.content?.profile_commitment || "").trim();
  const senderReplayStateMap = ensureSenderReplayStateMap(thread);
  const previousState = normalizeSenderReplayStateEntry(senderReplayStateMap[senderIdentity]);
  const assertProfileMigrationPolicy =
    typeof options.assertProfileMigrationPolicy === "function" ? options.assertProfileMigrationPolicy : null;

  if (!Number.isInteger(replayCounter) || replayCounter < 0) {
    throw new LoomError(
      "ENVELOPE_INVALID",
      "Encrypted envelope replay_counter must be a non-negative integer",
      400,
      {
        thread_id: thread.id,
        field: "content.replay_counter"
      }
    );
  }
  if (!profileCommitment) {
    throw new LoomError(
      "ENVELOPE_INVALID",
      "Encrypted envelope profile_commitment is required",
      400,
      {
        thread_id: thread.id,
        field: "content.profile_commitment"
      }
    );
  }

  if (!previousState) {
    if (replayCounter !== 0) {
      throw new LoomError(
        "ENVELOPE_INVALID",
        "First encrypted envelope from sender in an epoch must start replay_counter at 0",
        400,
        {
          thread_id: thread.id,
          sender: senderIdentity,
          epoch,
          replay_counter: replayCounter
        }
      );
    }
  } else {
    if (previousState.profile && previousState.profile !== profileId) {
      if (epoch <= previousState.epoch) {
        throw new LoomError("STATE_TRANSITION_INVALID", "Encrypted envelope profile change requires epoch increase", 409, {
          thread_id: thread.id,
          sender: senderIdentity,
          previous_profile: previousState.profile,
          envelope_profile: profileId,
          previous_epoch: previousState.epoch,
          envelope_epoch: epoch
        });
      }
      if (assertProfileMigrationPolicy) {
        assertProfileMigrationPolicy(previousState.profile, profileId, {
          thread_id: thread.id,
          sender: senderIdentity,
          envelope_id: envelope?.id || null,
          previous_epoch: previousState.epoch,
          envelope_epoch: epoch
        });
      }
    }
    if (epoch < previousState.epoch) {
      throw new LoomError("STATE_TRANSITION_INVALID", "Encrypted envelope epoch rollback detected", 409, {
        thread_id: thread.id,
        sender: senderIdentity,
        previous_epoch: previousState.epoch,
        envelope_epoch: epoch
      });
    }
    if (epoch === previousState.epoch) {
      if (profileCommitment !== previousState.profile_commitment) {
        throw new LoomError(
          "ENVELOPE_INVALID",
          "Encrypted envelope profile_commitment mismatch for sender epoch state",
          400,
          {
            thread_id: thread.id,
            sender: senderIdentity,
            epoch,
            previous_profile_commitment: previousState.profile_commitment,
            envelope_profile_commitment: profileCommitment
          }
        );
      }
      if (replayCounter <= previousState.replay_counter) {
        throw new LoomError(
          "STATE_TRANSITION_INVALID",
          "Encrypted envelope replay_counter must strictly increase for sender epoch state",
          409,
          {
            thread_id: thread.id,
            sender: senderIdentity,
            epoch,
            previous_replay_counter: previousState.replay_counter,
            envelope_replay_counter: replayCounter
          }
        );
      }
    } else if (replayCounter !== 0) {
      throw new LoomError(
        "ENVELOPE_INVALID",
        "Encrypted envelope replay_counter must reset to 0 when sender advances to a new epoch",
        400,
        {
          thread_id: thread.id,
          sender: senderIdentity,
          previous_epoch: previousState.epoch,
          envelope_epoch: epoch,
          envelope_replay_counter: replayCounter
        }
      );
    }
  }

  senderReplayStateMap[senderIdentity] = {
    profile: profileId,
    epoch,
    replay_counter: replayCounter,
    profile_commitment: profileCommitment,
    envelope_id: envelope.id,
    updated_at: nowIso()
  };
}

function assertTransition(thread, allowedFrom, nextState) {
  if (!allowedFrom.includes(thread.state)) {
    throw new LoomError("STATE_TRANSITION_INVALID", `Cannot transition thread ${thread.id} from ${thread.state} to ${nextState}`, 409, {
      thread_id: thread.id,
      current_state: thread.state,
      next_state: nextState
    });
  }
}

export function resolvePendingParentsForThreadCore(thread, parentEnvelopeId) {
  if (!thread || !parentEnvelopeId) {
    return 0;
  }

  let resolved = 0;
  for (const envelopeId of thread.envelope_ids || []) {
    if (envelopeId === parentEnvelopeId) {
      continue;
    }

    const envelope = this.envelopesById.get(envelopeId);
    if (!envelope || envelope.parent_id !== parentEnvelopeId) {
      continue;
    }

    if (!envelope.meta?.pending_parent) {
      continue;
    }

    envelope.meta = {
      ...envelope.meta,
      pending_parent: false,
      parent_resolved_at: nowIso()
    };
    resolved += 1;
  }

  if (resolved > 0) {
    thread.pending_parent_count = Math.max(0, Number(thread.pending_parent_count || 0) - resolved);
  }

  return resolved;
}

export function enforceThreadEnvelopeEncryptionPolicyCore(thread, envelope, isNewThread) {
  if (!thread || !envelope || envelope.type === "thread_op") {
    return;
  }

  const encrypted = envelope?.content?.encrypted === true;
  const profile = String(envelope?.content?.profile || "").trim();
  const profileId = resolveE2eeProfile(profile)?.id || profile;
  const epoch = envelope?.content?.epoch;

  if (isNewThread) {
    if (encrypted) {
      const initialParticipants = Array.from(
        new Set(
          [
            String(envelope?.from?.identity || "").trim(),
            ...(Array.isArray(envelope?.to) ? envelope.to.map((recipient) => String(recipient?.identity || "").trim()) : [])
          ].filter(Boolean)
        )
      );
      if (initialParticipants.some((identity) => identity.startsWith("bridge://"))) {
        throw new LoomError(
          "CAPABILITY_DENIED",
          "Encrypted threads cannot include bridge identities; use non-encrypted delivery wrappers for bridged recipients",
          403,
          {
            thread_id: thread.id
          }
        );
      }
      const encryptedContentErrors = validateEncryptedContentShape(envelope.content, {
        verifyPayloadCiphertextStructure: true,
        verifyWrappedKeyPayloadStructure: true,
        enforceReplayMetadata: true,
        resolveRecipientEncryptionKey: (recipientIdentity, keyId) =>
          this.resolveIdentityEncryptionKey(recipientIdentity, keyId)
      });

      const initialEpochErrors = validateEncryptionEpochParameters(
        {
          profile: profileId,
          epoch,
          wrapped_keys: envelope?.content?.wrapped_keys
        },
        {
          requiredRecipients: initialParticipants,
          verifyWrappedKeyPayloadStructure: true,
          resolveRecipientEncryptionKey: (recipientIdentity, keyId) =>
            this.resolveIdentityEncryptionKey(recipientIdentity, keyId)
        }
      );
      const encryptionErrors = [...encryptedContentErrors, ...initialEpochErrors];
      const bridgeWrappedRecipient = Array.isArray(envelope?.content?.wrapped_keys)
        ? envelope.content.wrapped_keys.find((entry) =>
            String(entry?.to || "").trim().startsWith("bridge://")
          )
        : null;
      if (bridgeWrappedRecipient) {
        encryptionErrors.push({
          field: "content.wrapped_keys",
          reason: "bridge recipients are not allowed in encrypted key distribution"
        });
      }
      if (encryptionErrors.length > 0) {
        throw new LoomError("ENVELOPE_INVALID", "Encrypted thread bootstrap key distribution is invalid", 400, {
          errors: encryptionErrors
        });
      }
      thread.encryption = {
        enabled: true,
        profile: profileId,
        key_epoch: epoch,
        sender_replay: ensureSenderReplayStateMap(thread)
      };
      recordSenderReplayStateOrThrow(thread, envelope, profileId, epoch, {
        assertProfileMigrationPolicy: (fromProfile, toProfile, migrationContext) => {
          if (typeof this.assertE2eeProfileMigrationPolicy === "function") {
            this.assertE2eeProfileMigrationPolicy(fromProfile, toProfile, migrationContext);
          }
        }
      });
    }
    return;
  }

  const threadEncryption = thread.encryption || {
    enabled: false,
    profile: null,
    key_epoch: 0,
    sender_replay: {}
  };

  if (!threadEncryption.enabled) {
    if (encrypted) {
      throw new LoomError(
        "STATE_TRANSITION_INVALID",
        "Cannot submit encrypted envelope to non-encrypted thread without encryption thread operation",
        409,
        {
          thread_id: thread.id,
          required_intent: "encryption.epoch@v1"
        }
      );
    }
    return;
  }

  const activeParticipants = this.getActiveParticipantIdentities(thread);
  if (activeParticipants.some((identity) => identity.startsWith("bridge://"))) {
    throw new LoomError(
      "CAPABILITY_DENIED",
      "Encrypted threads cannot include bridge identities; remove bridged participants before encrypted delivery",
      403,
      {
        thread_id: thread.id
      }
    );
  }

  const threadProfileId = resolveE2eeProfile(threadEncryption.profile)?.id || threadEncryption.profile;
  if (!encrypted) {
    throw new LoomError("ENCRYPTION_REQUIRED", "Thread requires encrypted envelope content", 403, {
      thread_id: thread.id,
      required_profile: threadProfileId,
      required_epoch: threadEncryption.key_epoch
    });
  }

  if (profileId !== threadProfileId) {
    throw new LoomError("ENVELOPE_INVALID", "Encrypted envelope profile does not match thread profile", 400, {
      thread_id: thread.id,
      envelope_profile: profileId,
      thread_profile: threadProfileId
    });
  }

  if (!Number.isInteger(epoch) || epoch !== threadEncryption.key_epoch) {
    throw new LoomError("ENVELOPE_INVALID", "Encrypted envelope epoch does not match thread epoch", 400, {
      thread_id: thread.id,
      envelope_epoch: epoch,
      thread_epoch: threadEncryption.key_epoch
    });
  }

  const wrappedKeyErrors = validateEncryptedContentShape(envelope.content, {
    verifyPayloadCiphertextStructure: true,
    verifyWrappedKeyPayloadStructure: true,
    enforceReplayMetadata: true,
    resolveRecipientEncryptionKey: (recipientIdentity, keyId) =>
      this.resolveIdentityEncryptionKey(recipientIdentity, keyId)
  });
  if (wrappedKeyErrors.length > 0) {
    throw new LoomError("ENVELOPE_INVALID", "Encrypted envelope wrapped key payload is invalid", 400, {
      errors: wrappedKeyErrors
    });
  }

  recordSenderReplayStateOrThrow(thread, envelope, threadProfileId, epoch, {
    assertProfileMigrationPolicy: (fromProfile, toProfile, migrationContext) => {
      if (typeof this.assertE2eeProfileMigrationPolicy === "function") {
        this.assertE2eeProfileMigrationPolicy(fromProfile, toProfile, migrationContext);
      }
    }
  });
}

export function prepareThreadOperationCore(thread, envelope, actorIdentity, context = {}) {
  const intent = envelope.content?.structured?.intent;
  const parameters = envelope.content?.structured?.parameters || {};

  if (!intent || typeof intent !== "string") {
    throw new LoomError("ENVELOPE_INVALID", "thread_op requires content.structured.intent", 400, {
      field: "content.structured.intent"
    });
  }

  const payloadCapabilityTokenRaw = parameters.capability_token;
  const payloadPortableCapabilityToken =
    payloadCapabilityTokenRaw &&
    typeof payloadCapabilityTokenRaw === "object" &&
    !Array.isArray(payloadCapabilityTokenRaw)
      ? payloadCapabilityTokenRaw
      : null;
  const payloadCapabilityTokenValue =
    typeof payloadCapabilityTokenRaw === "string" ? payloadCapabilityTokenRaw.trim() : "";
  const headerCapabilityTokenValue = String(context?.capabilityPresentationToken || "").trim();
  const capabilityTokenValue = headerCapabilityTokenValue || payloadCapabilityTokenValue;
  const capabilityTokenId =
    typeof parameters.capability_id === "string" && parameters.capability_id.trim()
      ? parameters.capability_id.trim()
      : null;

  const validatedToken = this.validateCapabilityForThreadOperation({
    thread,
    intent,
    actorIdentity,
    capabilityTokenValue,
    capabilityTokenId,
    portableCapabilityToken: payloadPortableCapabilityToken,
    context
  });

  if (
    context?.requirePortableThreadOpCapability === true &&
    !this.isThreadOwner(thread, actorIdentity) &&
    validatedToken?.kind !== "portable"
  ) {
    throw new LoomError(
      "CAPABILITY_DENIED",
      "Portable signed capability_token payload is required for non-owner thread operations",
      403,
      {
        intent,
        actor: actorIdentity,
        field: "content.structured.parameters.capability_token"
      }
    );
  }

  return () => {
    switch (intent) {
      case "thread.add_participant@v1": {
        const participantIdentity = parameters.identity;
        if (!isIdentity(participantIdentity)) {
          throw new LoomError("ENVELOPE_INVALID", "thread.add_participant requires valid parameters.identity", 400, {
            field: "content.structured.parameters.identity"
          });
        }

        const existing = thread.participants.find(
          (participant) => participant.identity === participantIdentity
        );

        if (!existing) {
          thread.participants.push({
            identity: participantIdentity,
            role: parameters.role || "participant",
            joined_at: envelope.created_at,
            left_at: null
          });
        } else {
          existing.left_at = null;
          existing.role = parameters.role || existing.role;
        }
        break;
      }

      case "thread.remove_participant@v1": {
        const participantIdentity = parameters.identity;
        const existing = thread.participants.find(
          (participant) => participant.identity === participantIdentity
        );

        if (!existing) {
          throw new LoomError("ENVELOPE_INVALID", "Participant not found for removal", 400, {
            participant: participantIdentity
          });
        }

        if (existing.role === "owner") {
          throw new LoomError("STATE_TRANSITION_INVALID", "Cannot remove thread owner directly", 409, {
            participant: participantIdentity
          });
        }

        existing.left_at = existing.left_at || envelope.created_at;
        break;
      }

      case "thread.update@v1": {
        if (typeof parameters.subject === "string") {
          thread.subject = parameters.subject;
        }

        if (Array.isArray(parameters.labels)) {
          thread.labels = Array.from(
            new Set(parameters.labels.map((label) => String(label).trim()).filter(Boolean))
          );
        }
        break;
      }

      case "thread.resolve@v1":
        assertTransition(thread, ["active"], "resolved");
        thread.state = "resolved";
        break;

      case "thread.archive@v1":
        assertTransition(thread, ["resolved"], "archived");
        thread.state = "archived";
        break;

      case "thread.lock@v1":
        assertTransition(thread, ["active", "resolved"], "locked");
        thread.state = "locked";
        break;

      case "thread.reopen@v1":
        assertTransition(thread, ["resolved", "locked"], "active");
        thread.state = "active";
        break;

      case "thread.delegate@v1": {
        const delegateIdentity = parameters.identity;
        if (!isIdentity(delegateIdentity)) {
          throw new LoomError("ENVELOPE_INVALID", "thread.delegate requires valid parameters.identity", 400, {
            field: "content.structured.parameters.identity"
          });
        }

        for (const participant of thread.participants) {
          if (participant.role === "owner" && participant.left_at == null) {
            participant.role = "participant";
          }
        }

        const existing = thread.participants.find(
          (participant) => participant.identity === delegateIdentity
        );

        if (!existing) {
          thread.participants.push({
            identity: delegateIdentity,
            role: "owner",
            joined_at: envelope.created_at,
            left_at: null
          });
        } else {
          existing.left_at = null;
          existing.role = "owner";
        }

        break;
      }

      case "capability.revoked@v1": {
        const capabilityId = parameters.capability_id;
        const target = this.capabilitiesById.get(capabilityId);
        if (!target || target.thread_id !== thread.id) {
          throw new LoomError("ENVELOPE_INVALID", "Capability token not found for revocation", 400, {
            capability_id: capabilityId
          });
        }

        if (!target.revoked) {
          target.revoked = true;
          target.revoked_at = envelope.created_at;
          thread.cap_epoch += 1;
        }
        break;
      }

      case "capability.spent@v1": {
        const capabilityId = parameters.capability_id;
        const target = this.capabilitiesById.get(capabilityId);
        if (!target || target.thread_id !== thread.id) {
          throw new LoomError("ENVELOPE_INVALID", "Capability token not found for spend update", 400, {
            capability_id: capabilityId
          });
        }

        if (!target.spent) {
          target.spent = true;
          target.spent_at = envelope.created_at;
        }
        break;
      }

      case "thread.fork@v1":
      case "thread.merge@v1":
      case "thread.link@v1":
        // MVP behavior: accept operation and preserve it in authoritative event-log.
        break;

      case "encryption.epoch@v1": {
        const nextProfile = String(parameters.profile || "").trim();
        const nextProfileId = resolveE2eeProfile(nextProfile)?.id || nextProfile;
        const nextEpoch = Number(parameters.epoch);
        const activeParticipants = this.getActiveParticipantIdentities(thread);
        if (activeParticipants.some((identity) => identity.startsWith("bridge://"))) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Encrypted threads cannot include bridge identities; remove bridged participants before enabling encryption",
            403,
            {
              thread_id: thread.id
            }
          );
        }

        const epochParameterErrors = validateEncryptionEpochParameters(parameters, {
          requiredRecipients: activeParticipants,
          verifyWrappedKeyPayloadStructure: true,
          resolveRecipientEncryptionKey: (recipientIdentity, keyId) =>
            this.resolveIdentityEncryptionKey(recipientIdentity, keyId)
        });
        const bridgeWrappedRecipient = Array.isArray(parameters.wrapped_keys)
          ? parameters.wrapped_keys.find((entry) => String(entry?.to || "").trim().startsWith("bridge://"))
          : null;
        if (bridgeWrappedRecipient) {
          epochParameterErrors.push({
            field: "content.structured.parameters.wrapped_keys",
            reason: "bridge recipients are not allowed in encrypted key distribution"
          });
        }
        if (epochParameterErrors.length > 0) {
          throw new LoomError("ENVELOPE_INVALID", "encryption.epoch parameters are invalid", 400, {
            errors: epochParameterErrors
          });
        }

        const currentProfileId = resolveE2eeProfile(thread.encryption.profile)?.id || thread.encryption.profile;
        const profileMigrationRequested =
          thread.encryption.enabled && currentProfileId && currentProfileId !== nextProfileId;
        if (profileMigrationRequested) {
          if (!Number.isInteger(nextEpoch) || nextEpoch <= thread.encryption.key_epoch) {
            throw new LoomError(
              "STATE_TRANSITION_INVALID",
              "encryption.epoch profile migration requires epoch strictly greater than current key epoch",
              409,
              {
                thread_id: thread.id,
                current_profile: currentProfileId,
                next_profile: nextProfileId,
                current_epoch: thread.encryption.key_epoch,
                next_epoch: nextEpoch
              }
            );
          }
          if (typeof this.assertE2eeProfileMigrationPolicy === "function") {
            this.assertE2eeProfileMigrationPolicy(currentProfileId, nextProfileId, {
              thread_id: thread.id,
              envelope_id: envelope?.id || null,
              actor: actorIdentity,
              current_epoch: thread.encryption.key_epoch,
              next_epoch: nextEpoch
            });
          }
        }
        if (thread.encryption.enabled && !profileMigrationRequested && nextEpoch < thread.encryption.key_epoch) {
          throw new LoomError("STATE_TRANSITION_INVALID", "encryption.epoch cannot decrease key epoch", 409, {
            thread_id: thread.id,
            current_epoch: thread.encryption.key_epoch,
            next_epoch: nextEpoch
          });
        }
        thread.encryption.enabled = true;
        thread.encryption.profile = nextProfileId;
        thread.encryption.key_epoch = nextEpoch;
        break;
      }

      case "encryption.rotate@v1": {
        if (!thread.encryption.enabled || !thread.encryption.profile) {
          throw new LoomError("STATE_TRANSITION_INVALID", "encryption.rotate requires an enabled thread encryption profile", 409, {
            thread_id: thread.id
          });
        }

        const activeParticipants = this.getActiveParticipantIdentities(thread);
        if (activeParticipants.some((identity) => identity.startsWith("bridge://"))) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Encrypted threads cannot include bridge identities; remove bridged participants before rotating encryption",
            403,
            {
              thread_id: thread.id
            }
          );
        }

        const currentProfileId = resolveE2eeProfile(thread.encryption.profile)?.id || thread.encryption.profile;
        const requestedProfileRaw =
          parameters.profile == null ? currentProfileId : String(parameters.profile).trim();
        const requestedProfileId =
          resolveE2eeProfile(requestedProfileRaw)?.id || requestedProfileRaw;
        if (requestedProfileId !== currentProfileId) {
          throw new LoomError("STATE_TRANSITION_INVALID", "encryption.rotate cannot change profile; use current thread profile", 409, {
            thread_id: thread.id,
            current_profile: currentProfileId,
            requested_profile: requestedProfileId
          });
        }

        const requestedEpoch =
          parameters.epoch == null || parameters.epoch === ""
            ? thread.encryption.key_epoch + 1
            : Number(parameters.epoch);
        if (!Number.isInteger(requestedEpoch) || requestedEpoch <= thread.encryption.key_epoch) {
          throw new LoomError("ENVELOPE_INVALID", "encryption.rotate requires parameters.epoch greater than current key epoch", 400, {
            thread_id: thread.id,
            current_epoch: thread.encryption.key_epoch,
            requested_epoch: parameters.epoch
          });
        }

        const rotateErrors = validateEncryptionEpochParameters(
          {
            profile: currentProfileId,
            epoch: requestedEpoch,
            wrapped_keys: parameters.wrapped_keys
          },
          {
            requiredRecipients: activeParticipants,
            verifyWrappedKeyPayloadStructure: true,
            resolveRecipientEncryptionKey: (recipientIdentity, keyId) =>
              this.resolveIdentityEncryptionKey(recipientIdentity, keyId)
          }
        );
        const bridgeWrappedRecipient = Array.isArray(parameters.wrapped_keys)
          ? parameters.wrapped_keys.find((entry) => String(entry?.to || "").trim().startsWith("bridge://"))
          : null;
        if (bridgeWrappedRecipient) {
          rotateErrors.push({
            field: "content.structured.parameters.wrapped_keys",
            reason: "bridge recipients are not allowed in encrypted key distribution"
          });
        }
        if (rotateErrors.length > 0) {
          throw new LoomError("ENVELOPE_INVALID", "encryption.rotate parameters are invalid", 400, {
            errors: rotateErrors
          });
        }

        thread.encryption.key_epoch = requestedEpoch;
        break;
      }

      default:
        throw new LoomError("ENVELOPE_INVALID", `Unsupported thread operation intent: ${intent}`, 400, {
          intent
        });
    }

    if (validatedToken?.kind === "local") {
      const token = validatedToken.token;
      if (token?.single_use && !token.spent) {
        token.spent = true;
        token.spent_at = envelope.created_at;
      }
    } else if (validatedToken?.kind === "portable" && validatedToken.single_use) {
      const localToken = validatedToken.localToken;
      if (localToken) {
        if (!localToken.spent) {
          localToken.spent = true;
          localToken.spent_at = envelope.created_at;
        }
      } else {
        this.consumedPortableCapabilityIds.add(validatedToken.id);
      }
    }
  };
}

export function resolveEnvelopeSignaturePublicKeyCore(envelope, signatureKeyId, context = {}) {
  const normalizedSignatureKeyId = String(signatureKeyId || "").trim();
  const normalizedFromKeyId = String(envelope?.from?.key_id || "").trim();
  if (!normalizedFromKeyId || normalizedFromKeyId !== normalizedSignatureKeyId) {
    throw new LoomError("SIGNATURE_INVALID", "from.key_id must match signature.key_id", 401, {
      field: "from.key_id"
    });
  }

  const fromIdentity = this.normalizeIdentityReference(envelope?.from?.identity);
  if (!fromIdentity) {
    throw new LoomError("SIGNATURE_INVALID", "Envelope sender identity is missing", 401, {
      field: "from.identity"
    });
  }

  if (fromIdentity.startsWith("bridge://")) {
    if (normalizedSignatureKeyId !== this.systemSigningKeyId) {
      throw new LoomError("SIGNATURE_INVALID", "Bridge identities must be signed by system signing key", 401, {
        field: "signature.key_id",
        identity: fromIdentity
      });
    }
    const systemPublicKey = this.resolvePublicKey(this.systemSigningKeyId);
    if (!systemPublicKey) {
      throw new LoomError("SIGNATURE_INVALID", "System signing key is not available for verification", 401, {
        field: "signature.key_id"
      });
    }
    return systemPublicKey;
  }

  if (context.allowSystemSignatureOverride === true && normalizedSignatureKeyId === this.systemSigningKeyId) {
    const systemPublicKey = this.resolvePublicKey(this.systemSigningKeyId);
    if (!systemPublicKey) {
      throw new LoomError("SIGNATURE_INVALID", "System signing key is not available for verification", 401, {
        field: "signature.key_id"
      });
    }
    return systemPublicKey;
  }

  const identityPublicKey = this.resolveIdentitySigningPublicKey(fromIdentity, normalizedSignatureKeyId);
  if (!identityPublicKey) {
    throw new LoomError(
      "SIGNATURE_INVALID",
      `Signing key is not registered for envelope sender identity: ${normalizedSignatureKeyId}`,
      401,
      {
        field: "signature.key_id",
        identity: fromIdentity
      }
    );
  }

  return identityPublicKey;
}

export function resolveAuthoritativeEnvelopeSenderTypeCore(envelope) {
  const fromIdentity = this.normalizeIdentityReference(envelope?.from?.identity);
  if (!fromIdentity) {
    throw new LoomError("SIGNATURE_INVALID", "Envelope sender identity is missing", 401, {
      field: "from.identity"
    });
  }

  const claimedType = String(envelope?.from?.type || "").trim();
  if (!claimedType) {
    throw new LoomError("ENVELOPE_INVALID", "Envelope sender type is missing", 400, {
      field: "from.type"
    });
  }

  if (fromIdentity.startsWith("bridge://")) {
    if (claimedType !== "bridge") {
      throw new LoomError("DELEGATION_INVALID", "Bridge sender identities must use from.type=bridge", 403, {
        field: "from.type",
        identity: fromIdentity,
        expected_type: "bridge",
        actual_type: claimedType
      });
    }
    return "bridge";
  }

  const senderIdentity = this.resolveIdentity(fromIdentity);
  if (!senderIdentity) {
    throw new LoomError("SIGNATURE_INVALID", "Envelope sender identity is not registered", 401, {
      field: "from.identity",
      identity: fromIdentity
    });
  }

  const registeredType = String(senderIdentity.type || "human").trim() || "human";
  if (registeredType !== claimedType) {
    throw new LoomError(
      "DELEGATION_INVALID",
      "Envelope sender type does not match registered identity type",
      403,
      {
        field: "from.type",
        identity: fromIdentity,
        expected_type: registeredType,
        actual_type: claimedType
      }
    );
  }

  return registeredType;
}

export function ingestEnvelopeCore(envelope, context = {}) {
  validateEnvelopeOrThrow(envelope);

  const actorIdentity = this.normalizeIdentityReference(context.actorIdentity || envelope.from?.identity);
  const fromIdentity = this.normalizeIdentityReference(envelope.from?.identity);
  if (!fromIdentity || actorIdentity !== fromIdentity) {
    throw new LoomError("CAPABILITY_DENIED", "Authenticated actor must match envelope.from.identity", 403, {
      actor: actorIdentity,
      from: fromIdentity || envelope.from?.identity || null
    });
  }

  const authoritativeSenderType = this.resolveAuthoritativeEnvelopeSenderType(envelope);

  this.enforceThreadRecipientFanout(envelope);

  if (this.envelopesById.has(envelope.id)) {
    throw new LoomError("ENVELOPE_DUPLICATE", `Envelope already exists: ${envelope.id}`, 409, {
      envelope_id: envelope.id
    });
  }

  // Verify signature before spending any rate-limit or quota budget so that
  // unauthenticated envelopes cannot exhaust another identity's quotas.
  verifyEnvelopeSignature(envelope, (keyId, signedEnvelope) =>
    this.resolveEnvelopeSignaturePublicKey(signedEnvelope, keyId, context)
  );

  this.enforceEnvelopeDailyQuota(actorIdentity, envelope.created_at);

  // Backpressure: reject new envelopes when outbox queues exceed the
  // configured high-water mark so the node doesn't accumulate unbounded
  // outbox state.
  if (this.outboxBackpressureMax > 0) {
    const outboxDepth =
      this.federationOutboxById.size + this.emailOutboxById.size + this.webhookOutboxById.size;
    if (outboxDepth >= this.outboxBackpressureMax) {
      throw new LoomError("SERVICE_OVERLOADED", "Outbox backpressure limit reached — try again later", 503, {
        outbox_depth: outboxDepth,
        backpressure_max: this.outboxBackpressureMax
      });
    }
  }

  if (authoritativeSenderType === "agent") {
    const contextRequiredActions = Array.isArray(context.requiredActions)
      ? context.requiredActions
      : context.requiredAction
        ? [context.requiredAction]
        : [];
    const requiredActions =
      contextRequiredActions.length > 0
        ? Array.from(new Set(contextRequiredActions.map((value) => String(value || "").trim()).filter(Boolean)))
        : this.resolveDelegationRequiredActions(envelope);
    verifyDelegationChainOrThrow(envelope, {
      resolveIdentity: (identity) => this.resolveIdentity(identity),
      resolvePublicKey: (keyId) => this.resolvePublicKey(keyId),
      isDelegationRevoked: (link) => this.isDelegationRevoked(link),
      now: nowMs(),
      requiredActions
    });
  }

  const threadId = envelope.thread_id;
  const existingThread = this.threadsById.get(threadId);

  if (existingThread?.state === "locked" && envelope.type !== "thread_op") {
    throw new LoomError("THREAD_LOCKED", `Thread is locked: ${threadId}`, 409, {
      thread_id: threadId
    });
  }

  if (existingThread && envelope.type !== "thread_op" && !this.isActiveParticipant(existingThread, actorIdentity)) {
    throw new LoomError("CAPABILITY_DENIED", "Sender is not an active participant of the thread", 403, {
      thread_id: threadId,
      actor: actorIdentity
    });
  }

  if (envelope.type === "thread_op" && !existingThread) {
    throw new LoomError("THREAD_NOT_FOUND", `thread_op requires an existing thread: ${threadId}`, 404, {
      thread_id: threadId
    });
  }

  const isNewThread = !existingThread;
  const thread =
    existingThread ||
    {
      id: threadId,
      root_envelope_id: envelope.parent_id ? null : envelope.id,
      subject: null,
      state: "active",
      created_at: envelope.created_at,
      updated_at: nowIso(),
      participants: [],
      mailbox_state: {},
      labels: [],
      cap_epoch: 0,
      encryption: {
        enabled: false,
        profile: null,
        key_epoch: 0,
        sender_replay: {}
      },
      event_seq_counter: 0,
      envelope_ids: [],
      pending_parent_count: 0
    };

  const threadSnapshot = !isNewThread ? structuredClone(thread) : null;

  this.enforceThreadEnvelopeEncryptionPolicy(thread, envelope, isNewThread);

  const operationMutation =
    envelope.type === "thread_op" ? this.prepareThreadOperation(thread, envelope, actorIdentity, context) : null;

  const pendingParent = !!(envelope.parent_id && !this.envelopesById.has(envelope.parent_id));
  if (pendingParent) {
    thread.pending_parent_count = Number(thread.pending_parent_count || 0) + 1;
  }
  thread.event_seq_counter += 1;

  const storedEnvelope = {
    ...envelope,
    meta: {
      ...(envelope.meta || {}),
      node_id: this.nodeId,
      received_at: nowIso(),
      event_seq: thread.event_seq_counter,
      origin_event_seq: envelope.meta?.origin_event_seq ?? thread.event_seq_counter,
      pending_parent: pendingParent
    }
  };

  thread.envelope_ids.push(storedEnvelope.id);
  thread.updated_at = nowIso();

  if (!thread.root_envelope_id && !storedEnvelope.parent_id) {
    thread.root_envelope_id = storedEnvelope.id;
  }

  if (isNewThread) {
    const participantUris = new Set([
      storedEnvelope.from.identity,
      ...(storedEnvelope.to || []).map((recipient) => recipient.identity)
    ]);

    thread.participants = Array.from(participantUris).map((identityUri, index) => ({
      identity: identityUri,
      role: index === 0 ? "owner" : "participant",
      joined_at: storedEnvelope.created_at,
      left_at: null
    }));
    for (const participant of thread.participants) {
      this.ensureMailboxState(thread, participant.identity);
    }
  }

  this.envelopesById.set(storedEnvelope.id, storedEnvelope);
  this.threadsById.set(thread.id, thread);

  const rollback = () => {
    this.envelopesById.delete(storedEnvelope.id);

    if (isNewThread) {
      this.threadsById.delete(thread.id);
    } else if (threadSnapshot) {
      this.threadsById.set(thread.id, threadSnapshot);
    }
  };

  const threadEnvelopes = thread.envelope_ids.map((id) => this.envelopesById.get(id));
  const dagResult = validateThreadDag(threadEnvelopes);

  if (!dagResult.valid) {
    rollback();
    throw new LoomError("ENVELOPE_INVALID", "Thread DAG contains a cycle", 400, {
      thread_id: thread.id,
      envelope_id: storedEnvelope.id
    });
  }

  try {
    if (operationMutation) {
      operationMutation();
      thread.updated_at = nowIso();
    }
  } catch (error) {
    rollback();
    throw error;
  }

  const resolvedPendingParents = this.resolvePendingParentsForThread(thread, storedEnvelope.id);
  const deliveryWrappers = this.ensureDeliveryWrappersForEnvelope(storedEnvelope);
  this.trackEnvelopeDailyQuota(storedEnvelope.from?.identity, storedEnvelope.created_at);

  this.persistAndAudit("envelope.ingest", {
    envelope_id: storedEnvelope.id,
    thread_id: storedEnvelope.thread_id,
    type: storedEnvelope.type,
    pending_parent: pendingParent,
    resolved_pending_parents: resolvedPendingParents,
    delivery_wrapper_count: deliveryWrappers.length,
    actor: actorIdentity
  });

  return storedEnvelope;
}

export function getThreadEnvelopesCore(threadId) {
  const thread = this.threadsById.get(threadId);
  if (!thread) {
    return null;
  }

  const envelopes = thread.envelope_ids.map((id) => this.envelopesById.get(id));
  return canonicalThreadOrder(envelopes);
}
