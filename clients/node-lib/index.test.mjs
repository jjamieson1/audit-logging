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
