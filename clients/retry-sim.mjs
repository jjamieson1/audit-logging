const config = {
  attempts: Number(process.env.SIM_ATTEMPTS || 6),
  initialBackoffMs: Number(process.env.SIM_INITIAL_BACKOFF_MS || 200),
  maxBackoffMs: Number(process.env.SIM_MAX_BACKOFF_MS || 2000),
  maxJitterMs: Number(process.env.SIM_MAX_JITTER_MS || 100)
};

const strategies = ["full", "equal", "decorrelated"];

for (const strategy of strategies) {
  const delays = simulate(strategy, config);
  const total = delays.reduce((sum, value) => sum + value, 0);
  console.log(`\n${strategy.toUpperCase()} jitter`);
  console.log(`delays(ms): ${delays.join(", ")}`);
  console.log(`total wait(ms): ${total}`);
}

function simulate(strategy, { attempts, initialBackoffMs, maxBackoffMs, maxJitterMs }) {
  const result = [];
  let backoffMs = initialBackoffMs;
  let previousDelayMs = initialBackoffMs;

  for (let i = 1; i < attempts; i += 1) {
    const delayMs = computeRetryDelayMs({
      strategy,
      backoffMs,
      previousDelayMs,
      initialBackoffMs,
      maxBackoffMs,
      maxJitterMs
    });

    result.push(delayMs);
    previousDelayMs = delayMs;
    backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
  }

  return result;
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

function randomJitterMs(max) {
  if (max <= 0) {
    return 0;
  }

  return Math.floor(Math.random() * (max + 1));
}

function randomBetween(min, max) {
  if (max <= min) {
    return min;
  }

  return min + Math.floor(Math.random() * (max - min + 1));
}
