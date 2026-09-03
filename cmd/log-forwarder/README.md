# Log Forwarder

A server-side Go agent that tails a local log file and forwards each line to the audit logging service over REST.

Current implementation status:

- M1: config loading and validation
- M2: inode-aware file following with checkpoint resume
- M3: parser modes (`json`, `regex`, `custom`) and normalization
- M4: HTTP delivery with retries, bearer auth, idempotency key, and dead-letter fallback
- M5: durable checkpoint writes (atomic replace + sync)
- M6: metrics, health endpoint, and periodic `/v1/verify` integrity checks

## Prerequisites

- Go 1.22+
- Running audit logging service endpoint (for example `http://localhost:8090/v1/logs`)
- Read access to source log file path

## Quick Start

1. Copy the example config and edit it for your environment.

```bash
cp ./configs/log-forwarder.example.json ./configs/log-forwarder.json
```

2. Validate the config.

```bash
go run ./cmd/log-forwarder -config ./configs/log-forwarder.json -validate-only
```

3. Run the forwarder.

```bash
go run ./cmd/log-forwarder -config ./configs/log-forwarder.json
```

## Command Flags

- `-config`: path to JSON config file
- `-validate-only`: validate config and exit

## Config Reference

Required fields:

- `server_url`: audit service logs endpoint (for example `http://localhost:8090/v1/logs`)
- `auth_bearer_token`: the forwarder's registered client token. An operator
  mints it on the audit host with `audit clients register --name <forwarder>`;
  it is shown once. Every entry the forwarder delivers is attributed to that
  client, and the forwarder's `/v1/verify` integrity checks use the same token.
  A rotation is a hard cutover: update this value and restart the forwarder.
  See [../../docs/authorization.md](../../docs/authorization.md).
- `source_file`: absolute or relative path to tailed log file
- `app_name`: app name attached to outbound payloads
- `timestamp_field`: source timestamp field name (used by parser)

Parser settings:

- `parser_mode`: `json`, `regex`, or `custom`
- `regex_pattern`: required when `parser_mode=regex`
- `default_level`: fallback level when not parsed from line

Tailing/checkpoint settings:

- `poll_interval_ms`: file polling interval
- `checkpoint_path`: path to checkpoint JSON

Delivery settings:

- `retry_max_attempts`
- `retry_initial_backoff_ms`
- `retry_max_backoff_ms`
- `request_timeout_ms`
- `dead_letter_path`

Observability settings:

- `metrics_port`: port for health endpoint (`/healthz`), set `0` to disable
- `metrics_report_interval_ms`: interval for periodic metrics logs
- `verify_interval_ms`: interval for integrity checks against `/v1/verify`

## Runtime Behavior

For each tailed line:

1. Parse according to `parser_mode`.
2. Normalize to audit payload (`app`, `level`, `message`, `metadata`).
3. Compute idempotency key and send `x-idempotency-key` header.
4. Send to `server_url` with retry/backoff policy.
5. If delivery ultimately fails, append record to `dead_letter_path` and continue.
6. Persist checkpoint offset so restarts resume from last committed position.

## Health and Metrics

If `metrics_port > 0`, the forwarder serves:

- `GET /healthz` returning status and current metrics counters

Periodic logs include counters for:

- lines read
- parse success/failure
- delivery success/failure
- dead-letter writes
- retries
- duplicate idempotency keys

## Integrity Verification

At `verify_interval_ms`, the forwarder calls `/v1/verify` (derived from `server_url`) and logs the result.

Example:

- `server_url: http://localhost:8090/v1/logs`
- verify endpoint: `http://localhost:8090/v1/verify`

## Dead-Letter Format

Dead-letter entries are JSON Lines at `dead_letter_path`, containing:

- creation time
- error message
- source file and offset
- full payload that failed delivery

## Troubleshooting

- `invalid config`: run with `-validate-only` and fix reported field errors
- no lines forwarded: verify `source_file` path and append activity
- repeated delivery failures: check token, endpoint, and service availability
- parse failures: adjust `parser_mode`, `timestamp_field`, and `regex_pattern`
- no metrics endpoint: ensure `metrics_port` is set to a non-zero valid port
