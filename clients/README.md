# Producer Clients

This folder contains reusable client libraries and runnable producer examples.

## Go library

Library path: `clients/go-lib/client.go`

Example usage:

```go
package main

import (
	"context"
	"time"
	auditclient "audit-logging/clients/go-lib"
)

func main() {
	client := auditclient.New("http://localhost:8080/v1/logs", nil)
	client.Retry = auditclient.RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     2 * time.Second,
		MaxJitter:      100 * time.Millisecond,
		JitterStrategy: auditclient.JitterDecorrelated,
	}
	_, _ = client.WriteLog(context.Background(), auditclient.LogRequest{
		App: "mininghub-service",
		Level: "INFO",
		Message: "order created",
		Metadata: map[string]any{"orderId": "o-123"},
	})
}
```

Retry defaults (Go):

- `MaxAttempts: 1` (no retries)
- `InitialBackoff: 100ms`
- `MaxBackoff: 2s`
- `MaxJitter: 100ms`
- `JitterStrategy: full`
- Strategy options: `full`, `equal`, `decorrelated`

## Node library

Library path: `clients/node-lib/index.mjs`

Example usage:

```js
import { createAuditLogger } from "./clients/node-lib/index.mjs";

const client = createAuditLogger({
  endpoint: "http://localhost:8080/v1/logs",
  retry: {
    maxAttempts: 3,
    initialBackoffMs: 200,
    maxBackoffMs: 2000,
    maxJitterMs: 100,
    jitterStrategy: "decorrelated",
  },
});
await client.writeLog({
  app: "payments-service",
  level: "INFO",
  message: "payment approved",
  metadata: { paymentId: "p-123" },
});
```

Retry defaults (Node):

- `maxAttempts: 1` (no retries)
- `initialBackoffMs: 100`
- `maxBackoffMs: 2000`
- `maxJitterMs: 100`
- `jitterStrategy: "full"`
- Strategy options: `"full"`, `"equal"`, `"decorrelated"`

## Runnable producers

Go producer:

```bash
go run ./clients/go-producer
```

Node producer:

```bash
node ./clients/node-producer/index.mjs
```

Environment variables for both producers:

- `AUDIT_LOG_URL` (default: `http://localhost:8080/v1/logs`)
- `AUDIT_APP_NAME` (default: language-specific producer name)

## curl examples

Set a base URL:

```bash
AUDIT_BASE_URL="http://localhost:8080"
```

Health check:

```bash
curl -s "$AUDIT_BASE_URL/v1/health"
```

Write a log entry:

```bash
curl -s -X POST "$AUDIT_BASE_URL/v1/logs" \
	-H "content-type: application/json" \
	-d '{
		"app":"mininghub-service",
		"level":"INFO",
		"message":"order created",
		"metadata":{"orderId":"o-123","actor":"svc-orders"}
	}'
```

Write an error log entry:

```bash
curl -s -X POST "$AUDIT_BASE_URL/v1/logs" \
	-H "content-type: application/json" \
	-d '{
		"app":"payments-api",
		"level":"ERROR",
		"message":"payment gateway timeout",
		"metadata":{"paymentId":"p-456","retry":true}
	}'
```

Verify chain integrity:

```bash
curl -s "$AUDIT_BASE_URL/v1/verify"
```

Example invalid payload (missing `message`) to confirm validation:

```bash
curl -s -X POST "$AUDIT_BASE_URL/v1/logs" \
	-H "content-type: application/json" \
	-d '{"app":"orders-api","level":"INFO"}'
```

## Retry simulation

Use this helper to visualize retry delay patterns for `full`, `equal`, and `decorrelated` jitter strategies:

```bash
node ./clients/retry-sim.mjs
```

Optional environment variables:

- `SIM_ATTEMPTS` (default: `6`)
- `SIM_INITIAL_BACKOFF_MS` (default: `200`)
- `SIM_MAX_BACKOFF_MS` (default: `2000`)
- `SIM_MAX_JITTER_MS` (default: `100`)

Preset guidance:

| Preset | Use when                                                                   | Command                 |
| ------ | -------------------------------------------------------------------------- | ----------------------- |
| fast   | Low-latency internal networks where quick retry convergence is preferred   | `make retry-sim-fast`   |
| slow   | Conservative retry pacing for fragile dependencies                         | `make retry-sim-slow`   |
| bursty | Traffic spikes or unstable networks where high jitter helps spread retries | `make retry-sim-bursty` |
