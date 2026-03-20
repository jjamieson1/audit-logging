# Log Forwarder Implementation Plan

## 1. Requirements Summary

A Go agent runs on a server, tails a local log file, and forwards new log records to the audit logging REST API.

Required behavior:

- Config file driven startup
- Configurable destination REST endpoint
- Configurable source log file path
- Configurable source timestamp field name (`timestamp`)
- Configurable application name to attach to outbound payloads
- Timestamp-aware sequential sending
- No data loss across crash/restart
- No duplicate sends in normal operation
- Integrity checks between local source and remote log service

Decisions captured from clarification:

- Delivery model: at-least-once
- Source format: mixed/custom (parser must be pluggable)
- Rotation style: rename + create new file
- API auth: Bearer token

## 2. Delivery Semantics

Target guarantee:

- At-least-once delivery from source file to REST API
- Ordering preserved per source file read order

Implications:

- Duplicates can happen during retry/restart windows
- Dedupe should be done with an idempotency key in each request

Recommended idempotency key:

- `sha256(app + source_file + source_offset + normalized_line)`

## 3. Architecture

Components:

1. Config Loader
2. File Follower (tail + rotation handling)
3. Parser Pipeline (mixed/custom support)
4. Sequencer and Outbox Queue
5. HTTP Sender with retry/backoff
6. Durable Checkpoint Store
7. Integrity Verifier
8. Metrics and Health

### 3.1 Config

Suggested config fields:

- `server_url`
- `auth_bearer_token`
- `source_file`
- `app_name`
- `timestamp_field`
- `parser_mode` (`json`, `regex`, `custom`)
- `regex_pattern` (optional)
- `level_mapping` (optional)
- `poll_interval_ms`
- `batch_size`
- `flush_interval_ms`
- `checkpoint_path`
- `retry_max_attempts`
- `retry_initial_backoff_ms`
- `retry_max_backoff_ms`
- `dead_letter_path`

### 3.2 File Following and Rotation

- Open file and seek to checkpointed byte offset.
- Read append-only updates incrementally.
- Detect rotation by inode change or file shrink.
- On rename+new-file:
  - finish unread data from old inode if accessible
  - switch to new inode at offset 0
- Persist checkpoint after successful remote ack.

### 3.3 Parser Strategy for Mixed/Custom Logs

Parser chain per line:

1. Try JSON decode
2. If JSON fails and regex configured, parse via regex named groups
3. Fallback to plain text message

Normalized outbound event:

- app (from config)
- level (from parsed data or default INFO)
- message
- metadata

Include in metadata:

- source_file
- source_offset
- source_timestamp_raw
- parser_mode
- idempotency_key

### 3.4 HTTP Sender

- POST to `/v1/logs`
- Use context timeout per request
- Retry with exponential backoff + jitter on network and 5xx errors
- Do not retry 4xx validation failures; route to dead-letter
- Add headers:
  - `content-type: application/json`
  - `authorization: Bearer <token>`
  - `x-idempotency-key: <computed key>`

## 4. Checkpointing and Crash Recovery

Store durable state (JSON file):

- inode
- file_path
- byte_offset
- last_source_timestamp
- last_idempotency_key
- updated_at

Rules:

- Move checkpoint only after successful server response.
- fsync checkpoint writes (write temp + rename) to avoid corruption.
- On restart, resume from checkpoint offset.

## 5. Integrity Model

Integrity checks to implement:

- Count parity over windows: compare local sent count vs accepted responses
- Spot check hash parity:
  - local line hash recorded in metadata
  - remote retrieval sample via `/v1/logs` query and compare
- Optional periodic `/v1/verify` call for remote chain health

Note:

- Full end-to-end exact parity requires remote query features by source idempotency key.

## 5.1 API Capability Gaps to Close

Current server accepts `app`, `level`, `message`, and `metadata` on write.

To support robust dedupe and traceability, add at least one of:

- A first-class `idempotency_key` field in write payload, enforced unique per source
- Support for `x-idempotency-key` header with idempotent write semantics

Recommended additional query support:

- Filter logs by idempotency key in `GET /v1/logs`
- Filter logs by source file and source offset from metadata

## 6. Milestones

### M1: Core Skeleton and Config

- Build CLI process with config load and validation
- Add structured internal logs
- Acceptance: process starts with valid config and rejects invalid config

### M2: Reliable File Follower

- Implement tailing, offset tracking, rotation handling
- Acceptance: no missed lines across rotation and restart in local tests

### M3: Parser and Event Normalization

- Implement parser chain (json/regex/plain)
- Acceptance: mixed sample file converts to valid outbound events

### M4: Sender + Retry + Dead-letter

- Integrate HTTP sender with backoff and auth header
- Acceptance: retries on transient failures and dead-letters permanent failures

### M5: Checkpoint Durability

- Atomic checkpoint persistence and resume behavior
- Acceptance: crash/restart test confirms no data loss

### M6: Integrity and Observability

- Add counters, health endpoint, integrity spot checks
- Acceptance: dashboard/log output shows sent, retried, failed, duplicated indicators

## 7. Testing Plan

Unit tests:

- Config validation
- Parser behavior for json/regex/plain
- Idempotency key determinism
- Retry policy behavior

Integration tests:

- File append flow to test server
- Rotation rename + new file
- Crash mid-batch and restart resume
- 5xx retry and eventual success
- 4xx dead-letter path

Failure/chaos tests:

- Network timeout and connection resets
- Server unavailable for prolonged period
- Corrupt checkpoint file recovery

## 8. Risks and Mitigations

Risk: mixed/custom logs break parse assumptions
Mitigation: parser chain + explicit dead-letter with raw line capture

Risk: duplicates during retry windows
Mitigation: idempotency key + metadata traceability

Risk: log rotation race conditions
Mitigation: inode-aware follower and checkpoint-after-ack discipline

## 9. Implementation Order (Practical)

1. Reuse existing Go client library for write path where possible.
2. Build standalone agent binary under a new command path.
3. Add fixture logs and end-to-end tests against local audit service.
4. Add metrics and runbook docs before production rollout.
