import test from "node:test";
import assert from "node:assert/strict";

import { AuditLogger } from "./index.mjs";

function stubFetch(captured, response = {}) {
  const { status = 201, body = '{"index":1}' } = response;
  return async (url, options) => {
    captured.push({ url, options });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body
    };
  };
}

test("sends a bearer token when one is configured", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured),
    authToken: "alog_1111111111111111_secret"
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal(captured.length, 1);
  assert.equal(
    captured[0].options.headers.authorization,
    "Bearer alog_1111111111111111_secret"
  );
});

test("omits the authorization header when no token is configured", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured)
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal("authorization" in captured[0].options.headers, false);
});

test("trims surrounding whitespace from the token", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured),
    authToken: "  alog_1111111111111111_secret  "
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal(
    captured[0].options.headers.authorization,
    "Bearer alog_1111111111111111_secret"
  );
});

test("does not retry a 401 — a bad token will never become good", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured, { status: 401, body: '{"error":"unauthorized"}' }),
    authToken: "alog_1111111111111111_wrong",
    retry: { maxAttempts: 5, initialBackoffMs: 1 }
  });

  await assert.rejects(
    () => logger.writeLog({ app: "a", level: "INFO", message: "m" }),
    /401/
  );
  assert.equal(captured.length, 1, "a 401 must not be retried");
});

test("retries a 5xx up to maxAttempts — a transient outage must not drop the entry silently", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured, { status: 503, body: '{"error":"unavailable"}' }),
    retry: { maxAttempts: 3, initialBackoffMs: 1 }
  });

  await assert.rejects(
    () => logger.writeLog({ app: "a", level: "INFO", message: "m" }),
    /503/
  );
  assert.equal(captured.length, 3, "a 503 must be retried up to maxAttempts");
});

test("retries a network-level fetch rejection — a dropped connection must not drop the entry silently", async () => {
  const captured = [];
  let calls = 0;
  const fetchImpl = async (url, options) => {
    calls += 1;
    captured.push({ url, options });
    if (calls < 3) {
      throw new Error("network unreachable");
    }
    return { ok: true, status: 201, text: async () => '{"index":1}' };
  };
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl,
    retry: { maxAttempts: 3, initialBackoffMs: 1 }
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal(captured.length, 3, "a plain network error must be retried, not treated as non-retryable");
});
