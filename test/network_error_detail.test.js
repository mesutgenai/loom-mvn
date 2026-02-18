import test from "node:test";
import assert from "node:assert/strict";

import { describeNetworkRequestError } from "../scripts/lib/network_error_detail.js";

test("describeNetworkRequestError formats abort timeouts with method and URL", () => {
  const abortError = new Error("The operation was aborted");
  abortError.name = "AbortError";

  const message = describeNetworkRequestError({
    error: abortError,
    method: "post",
    url: "https://loom-staging.internal/v1/federation/challenge",
    timeoutMs: 12345
  });

  assert.match(message, /timed out after 12345ms/i);
  assert.match(message, /POST https:\/\/loom-staging\.internal\/v1\/federation\/challenge/);
});

test("describeNetworkRequestError includes cause code/syscall/address details", () => {
  const cause = new Error("getaddrinfo ENOTFOUND loom-staging.internal");
  cause.code = "ENOTFOUND";
  cause.syscall = "getaddrinfo";
  cause.hostname = "loom-staging.internal";

  const error = new Error("fetch failed");
  error.cause = cause;

  const message = describeNetworkRequestError({
    error,
    method: "get",
    url: "https://loom-staging.internal/.well-known/loom.json",
    timeoutMs: 15000
  });

  assert.match(message, /Request failed/i);
  assert.match(message, /code=ENOTFOUND/);
  assert.match(message, /syscall=getaddrinfo/);
  assert.match(message, /address=loom-staging\.internal/);
});

test("describeNetworkRequestError adds TLS classification when certificate errors appear", () => {
  const cause = new Error("self signed certificate");
  cause.code = "DEPTH_ZERO_SELF_SIGNED_CERT";

  const error = new Error("fetch failed");
  error.cause = cause;

  const message = describeNetworkRequestError({
    error,
    method: "get",
    url: "https://loom-preprod.internal/.well-known/loom.json",
    timeoutMs: 15000
  });

  assert.match(message, /tls=certificate-validation-failed/);
});
