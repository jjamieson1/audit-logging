export class AuditLogger {
  constructor({
    endpoint = "http://localhost:8090/v1/logs",
    fetchImpl = globalThis.fetch,
    authToken = "",
    retry = {}
  } = {}) {
    if (!fetchImpl) {
      throw new Error("fetch implementation is required");
    }

    this.endpoint = endpoint;
    this.fetchImpl = fetchImpl;
    this.authToken = String(authToken ?? "").trim();
    this.retry = {
      maxAttempts: Number(retry.maxAttempts ?? 1),
      initialBackoffMs: Number(retry.initialBackoffMs ?? 100),
      maxBackoffMs: Number(retry.maxBackoffMs ?? 2000),
      maxJitterMs: Number(retry.maxJitterMs ?? 100),
      jitterStrategy: normalizeJitterStrategy(retry.jitterStrategy)
    };
  }

  async writeLog(payload) {
    const app = String(payload?.app ?? "").trim();
    const level = String(payload?.level ?? "").trim();
    const message = String(payload?.message ?? "").trim();
    const metadata = payload?.metadata && typeof payload.metadata === "object" ? payload.metadata : {};

    if (!app || !level || !message) {
      throw new Error("app, level, and message are required");
    }

    const maxAttempts = Number.isFinite(this.retry.maxAttempts) && this.retry.maxAttempts > 0
      ? this.retry.maxAttempts
      : 1;
    let backoffMs = Number.isFinite(this.retry.initialBackoffMs) && this.retry.initialBackoffMs > 0
      ? this.retry.initialBackoffMs
      : 100;
    const maxBackoffMs = Number.isFinite(this.retry.maxBackoffMs) && this.retry.maxBackoffMs > 0
      ? this.retry.maxBackoffMs
      : 2000;
    const maxJitterMs = Number.isFinite(this.retry.maxJitterMs) && this.retry.maxJitterMs >= 0
      ? this.retry.maxJitterMs
      : 100;
    const jitterStrategy = normalizeJitterStrategy(this.retry.jitterStrategy);

    let lastError;
    let previousDelayMs = backoffMs;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await this.fetchImpl(this.endpoint, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            // Spread so the header is absent, not empty, when unconfigured.
            ...(this.authToken ? { authorization: `Bearer ${this.authToken}` } : {})
          },
          body: JSON.stringify({ app, level, message, metadata })
        });

        const textBody = await response.text();
        if (!response.ok) {
          const error = new Error(`audit service returned ${response.status}: ${textBody}`);
          if (!shouldRetryStatus(response.status)) {
            // Non-retryable status (e.g. 401): mark it so the catch below
            // rethrows immediately instead of treating it like a transient
            // failure and looping through the remaining attempts.
            error.retryable = false;
          }
          if (!shouldRetryStatus(response.status) || attempt === maxAttempts) {
            throw error;
          }
          lastError = error;
        } else {
          try {
            return JSON.parse(textBody);
          } catch {
            return { raw: textBody };
          }
        }
      } catch (error) {
        lastError = error;
        if (attempt === maxAttempts || error?.retryable === false) {
          throw error;
        }
      }

      const delayMs = computeRetryDelayMs({
        strategy: jitterStrategy,
        backoffMs,
        previousDelayMs,
        initialBackoffMs: Number.isFinite(this.retry.initialBackoffMs) && this.retry.initialBackoffMs > 0
          ? this.retry.initialBackoffMs
          : 100,
        maxBackoffMs,
        maxJitterMs
      });
      await sleep(delayMs);
      previousDelayMs = delayMs;
      backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
    }

    throw lastError ?? new Error("failed to write log");
  }
}

export function createAuditLogger(options) {
  return new AuditLogger(options);
}

function shouldRetryStatus(statusCode) {
  return statusCode === 429 || statusCode >= 500;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomJitterMs(max) {
  if (max <= 0) {
    return 0;
  }

  return Math.floor(Math.random() * (max + 1));
}

function normalizeJitterStrategy(strategy) {
  if (strategy === "equal" || strategy === "decorrelated") {
    return strategy;
  }

  return "full";
}

function computeRetryDelayMs({ strategy, backoffMs, previousDelayMs, initialBackoffMs, maxBackoffMs, maxJitterMs }) {
  if (strategy === "equal") {
    const half = Math.floor(maxJitterMs / 2);
    return backoffMs + half + randomJitterMs(half);
  }

  if (strategy === "decorrelated") {
    const lower = initialBackoffMs;
    let upper = Math.min(maxBackoffMs, Math.max(lower, previousDelayMs * 3));
    if (maxJitterMs > 0) {
      upper = Math.min(upper, lower + maxJitterMs);
    }
    return randomBetween(lower, upper);
  }

  return backoffMs + randomJitterMs(maxJitterMs);
}

function randomBetween(min, max) {
  if (max <= min) {
    return min;
  }
  return min + Math.floor(Math.random() * (max - min + 1));
}
