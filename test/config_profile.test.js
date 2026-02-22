import test from "node:test";
import assert from "node:assert/strict";

import {
  applyConfigProfileEnvDefaults,
  applyConfigProfileOptionDefaults,
  resolveConfigProfileName
} from "../src/node/config_profile.js";

test("config profile aliases normalize to secure_public", () => {
  assert.equal(resolveConfigProfileName("secure_public"), "secure_public");
  assert.equal(resolveConfigProfileName("secure-public"), "secure_public");
  assert.equal(resolveConfigProfileName("secure"), "secure_public");
});

test("config profile rejects unknown profile id", () => {
  assert.throws(() => resolveConfigProfileName("unknown_profile"), /Unknown LOOM config profile/);
});

test("secure_public env defaults are applied for missing values only", () => {
  const env = {
    LOOM_CONFIG_PROFILE: "secure_public",
    LOOM_PUBLIC_SERVICE: "false",
    LOOM_METRICS_PUBLIC: "true"
  };
  const active = applyConfigProfileEnvDefaults(env, env.LOOM_CONFIG_PROFILE);
  assert.equal(active, "secure_public");
  assert.equal(env.LOOM_PUBLIC_SERVICE, "false");
  assert.equal(env.LOOM_METRICS_PUBLIC, "true");
  assert.equal(env.LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS, "true");
  assert.equal(env.LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION, "false");
});

test("secure_public option defaults honor explicit options and env overrides", () => {
  const env = {
    LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS: "false"
  };
  const options = {
    configProfile: "secure_public",
    bridgeInboundEnabled: false
  };
  const active = applyConfigProfileOptionDefaults(options, env);
  assert.equal(active, "secure_public");
  assert.equal(options.bridgeInboundEnabled, false);
  assert.equal(options.requireExternalSigningKeys, undefined);
  assert.equal(options.federationTrustMode, "public_dns_webpki");
  assert.equal(options.bridgeInboundRequireAdminToken, true);
});
