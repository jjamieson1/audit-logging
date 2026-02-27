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

- `POST /v1/logs`
- `GET /v1/logs`
- `GET /v1/logs/search`
- `GET /v1/verify`
- `GET /v1/health`

### View/search logs

Query params:

- `app` exact app filter
- `level` exact level filter
- `q` or `text` free-text search over message/metadata
- `limit` page size (default `50`, max `500`)
- `offset` pagination offset (default `0`)

Examples:

```bash
curl -s "http://localhost:8080/v1/logs?limit=20&offset=0"
curl -s "http://localhost:8080/v1/logs?app=payments-api&level=ERROR"
curl -s "http://localhost:8080/v1/logs/search?q=timeout&limit=10"
```

### Example write

```bash
curl -s -X POST http://localhost:8080/v1/logs \
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
curl -s http://localhost:8080/v1/verify
```

## Run

```bash
go run ./cmd/server
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
```

## Producer Clients

For producer client usage, reusable Go/Node client libraries, retry tuning options, and retry simulation presets, see `clients/README.md`.

### Run with PostgreSQL

```bash
export STORAGE_BACKEND=postgres
export DATABASE_URL='postgres://user:password@localhost:5432/audit?sslmode=disable'
go run ./cmd/server
```

## Config

- `PORT` (default `8080`)
- `STORAGE_BACKEND` (default `file`; options: `file`, `postgres`)
- `DATABASE_URL` (required when `STORAGE_BACKEND=postgres`)
- `DATA_DIR` (default `./data`)
- `LOG_FILE` (default `./data/audit.log.jsonl`)
- `MAX_PAYLOAD_BYTES` (default `32768`)

## Multi-instance note

For horizontal scaling, use `STORAGE_BACKEND=postgres` so all service instances append to the same chain safely.
