# Audit Logging Service (Go)

Centralized infrastructure audit-logging service where all applications can write logs.

## Guarantees

- Append-only writes supported with two backends:
  - `file`: JSONL file (`data/audit.log.jsonl`) using `O_APPEND`
  - `postgres`: sequential rows with transaction-level advisory lock
- Tamper-evident hash chain per record:
  - `payloadHash = sha256(canonical(record))`
  - `entryHash = sha256(index|timestamp|payloadHash|prevHash)`
- Chain verification endpoint detects edits, deletions, re-ordering, or injected lines.

> Note: cryptographic chaining makes logs tamper-evident. For stronger tamper-proof posture, also replicate to immutable/WORM storage and restrict host access.

## API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /v1/health` | none | Liveness. The only unauthenticated endpoint. |
| `POST /v1/logs` | bearer token | Append an entry, stamped with the caller's client id. |
| `GET /v1/logs` | bearer token | Read your entries. |
| `GET /v1/logs/search` | bearer token | Free-text search over your entries. |
| `GET /v1/verify` | bearer token | Verify the chain. The result is global. |

All authenticated endpoints take `Authorization: Bearer <token>`. See
[docs/authorization.md](docs/authorization.md) for how to get a token, and
[docs/querying.md](docs/querying.md) for paging.

## Authorization

Every client is registered by an operator, which mints a token shown exactly
once. The client sends it as a bearer token; the server stamps the client's id
into each entry it writes and confines each read to that client's own entries.
An `admin` client reads across all of them.

```bash
audit clients register --name payments-api      # mint a token
audit clients list                              # who is registered
audit clients rotate --id <clientId>            # replace a token
audit clients revoke --id <clientId>            # disable a token
```

Registration is local-only — there is no HTTP endpoint for it.

Full guide: [docs/authorization.md](docs/authorization.md).

### View/search logs

Query params:

- `app` exact app filter
- `level` exact level filter
- `q` or `text` free-text search over message/metadata
- `limit` page size (defaults to `DEFAULT_QUERY_LIMIT`, clamped to `MAX_QUERY_LIMIT`)
- `cursor` opaque page token from the previous response's `nextCursor`
- `count` set to `true` to include an exact `total` (expensive; off by default)
- `offset` still supported, but bounded by `MAX_QUERY_OFFSET`; prefer `cursor`
- `clientId` admin tokens only; narrows to one client

Responses carry `nextCursor`, which is `null` on the last page.

```bash
curl -s "http://localhost:8080/v1/logs?limit=20" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs?app=payments-api&level=ERROR" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs/search?q=timeout&limit=10" -H "authorization: Bearer $AUDIT_TOKEN"
```

Full paging guide: [docs/querying.md](docs/querying.md).

### Example write

```bash
curl -s -X POST http://localhost:8080/v1/logs \
  -H "authorization: Bearer $AUDIT_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "app":"payments-api",
    "level":"INFO",
    "message":"invoice created",
    "metadata":{"invoiceId":"inv_123","actor":"svc-payments"}
  }'
```

### Verify chain

```bash
curl -s http://localhost:8080/v1/verify -H "authorization: Bearer $AUDIT_TOKEN"
```

## Run

The client registry always lives in PostgreSQL, so `DATABASE_URL` is required
even when log entries go to a file:

```bash
export DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable'
go run ./cmd/server
```

Register a client to get a token:

```bash
go run ./cmd/server clients register --name my-service
```

## Run with Docker Compose

```bash
docker compose up --build
```

Service endpoints:

- `http://localhost:8080/v1/health`
- `http://localhost:8080/v1/logs`
- `http://localhost:8080/v1/verify`

Stop stack:

```bash
docker compose down
```

## Make targets

```bash
make up
make down
make test
make logs
make ps
make restart
make clean
make health
make verify
make sample-log
make smoke
make retry-sim
make retry-sim-fast
make retry-sim-slow
make retry-sim-bursty
make test-node
```

## Deploy to a server

Deployment to an Ubuntu 24.04 host lives in `deployment/`:

```bash
./deployment/provision.sh <ssh-host>   # one-time: PostgreSQL, service user, systemd unit
./deployment/deploy.sh <ssh-host>      # build, ship, restart, health-check
```

See `deployment/README.md` for the server layout, rollback, tunnelling and
credential rotation.

## Producer Clients

For producer client usage, reusable Go/Node client libraries, retry tuning options, and retry simulation presets, see `clients/README.md`.

## Log Forwarder Agent (M6)

A new log-forwarder command is available with file-based config loading, checkpoint resume, inode-aware file following, line parsing/normalization, REST delivery, durable checkpoint persistence, and runtime observability.

For complete usage and operations details, see `cmd/log-forwarder/README.md`.

Run config validation:

```bash
go run ./cmd/log-forwarder -config ./configs/log-forwarder.example.json -validate-only
```

Run the process:

```bash
go run ./cmd/log-forwarder -config ./configs/log-forwarder.example.json
```

Use the example config at `configs/log-forwarder.example.json` as a starting point.

Parser-related config:

- `parser_mode`: `json`, `regex`, or `custom`
- `regex_pattern`: required when `parser_mode=regex`
- `default_level`: used when parsed line does not include a level

M6 config:

- `metrics_port`: bind port for `/healthz` (set `0` to disable)
- `metrics_report_interval_ms`: interval for metrics summary log lines
- `verify_interval_ms`: interval for remote integrity checks against `/v1/verify`

Delivery behavior:

- Writes to the configured audit endpoint using the shared Go client retry policy
- Sends bearer auth via `auth_bearer_token`
- Computes and sends `x-idempotency-key` per line
- On delivery failure after retries, appends an entry to `dead_letter_path` and continues

Observability and integrity:

- Periodic metrics logs include sent, retried, failed, dead-lettered, and duplicate-key indicators
- Optional health endpoint at `/healthz` on `metrics_port`
- Periodic integrity checks call `GET /v1/verify` based on `verify_interval_ms`

Current status:

- implemented: config load/validate + startup runtime shell
- implemented: file tailing with checkpoint offsets and rename/truncate handling
- implemented: parser modes (`json`, `regex`, `custom`) and normalized payload mapping
- implemented: HTTP send loop with retry + bearer auth + idempotency header and dead-letter fallback
- implemented: atomic checkpoint writes with temp-file sync and directory sync
- implemented: runtime metrics counters + health endpoint + periodic integrity verification

### Run with PostgreSQL

```bash
export STORAGE_BACKEND=postgres
export DATABASE_URL='postgres://user:password@localhost:5432/audit?sslmode=disable'
go run ./cmd/server
```

## Config

- `PORT` (default `8080`)
- `BIND_ADDR` (default empty, listening on all interfaces; set `127.0.0.1` for loopback only)
- `DATABASE_URL` (**required**, always — the client registry lives in PostgreSQL whatever `STORAGE_BACKEND` is)
- `STORAGE_BACKEND` (default `file`; options: `file`, `postgres`) — where log *entries* go
- `DATA_DIR` (default `./data`)
- `LOG_FILE` (default `./data/audit.log.jsonl`)
- `MAX_PAYLOAD_BYTES` (default `32768`)
- `DEFAULT_QUERY_LIMIT` (default `50`) page size when a read omits `limit`
- `MAX_QUERY_LIMIT` (default `500`) ceiling; a larger `limit` is clamped
- `MAX_QUERY_OFFSET` (default `10000`) largest accepted `offset` before `400`

## Multi-instance note

For horizontal scaling, use `STORAGE_BACKEND=postgres` so all service instances append to the same chain safely.
