# API Authorization for Audit Logging Clients

Date: 2026-09-02
Status: Approved, pending implementation plan

## Problem

The audit logging service has no authorization. Every endpoint on
`cmd/server/main.go` is open: anyone who can reach the port may write entries
under any `app` name and read every entry any other application has written.

Producer clients already send `Authorization: Bearer <token>` --
`clients/go-lib/client.go:126` sets the header and `cmd/log-forwarder` requires
`auth_bearer_token` in its config -- but the server ignores it. The wire format
for authorization exists; the enforcement does not.

## Goals

1. A client authenticates with a token on every logging and query call.
2. Every entry a client writes is bound to that client, tamper-evidently.
3. A client reading the log sees only its own entries.
4. An operator can register a client, mint its token, rotate it, and revoke it.
5. Read latency stays flat as the log grows, rather than degrading with table
   size or page depth.

## Non-goals

Deliberately excluded to keep the change reviewable:

- Token expiry. Tokens live until rotated or revoked.
- Any permission model finer than the two roles `client` and `admin`.
- An HTTP registration endpoint. Registration is local-only, by design.
- Rate limiting or per-client quotas.
- Retro-attributing the entries already in the chain. They keep an empty
  `clientId` forever; rewriting them would break the hash chain, which is the
  point of the chain.
- An admin filter that selects *only* legacy entries. Admin sees everything or
  one named client.
- Descending (newest-first) result order. Reads stay ascending by `entry_index`
  as they are today. Adding a `DESC` cursor is a natural follow-up but is not
  in this change.
- A trigram index for free-text `q` search. That predicate stays a scan.
- A byte-offset index for the file backend. Its reads stay linear; see the
  honest-limits note in section 10.

## Decisions

These were settled during brainstorming and are not open for re-litigation
during implementation:

| Decision | Choice |
|---|---|
| Identity model | The client is the tenant. `app` remains a free-text sub-label; one client may write many apps. |
| Registry storage | Always PostgreSQL, regardless of `STORAGE_BACKEND`. |
| Registration | Local CLI only. No HTTP registration endpoint. |
| Enforcement | Hard requirement on all log endpoints, plus an `admin` role that reads across all clients. |
| Token format | Opaque random secret, SHA-256 hashed at rest. |
| Pagination | Cursor-first (keyset on `entry_index`). `offset` retained for existing callers but bounded. Exact `total` becomes opt-in via `?count=true`. |

## Design

### 1. Data model

One new table, created by the same `ensureSchema()` idempotent-DDL pattern
already used for `audit_log_entries`:

```sql
CREATE TABLE IF NOT EXISTS audit_clients (
    client_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'client',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
```

`role` is constrained in application code to `client` or `admin`.
`revoked_at` non-null means the token no longer authenticates; the row is kept
so historical entries stay attributable to a named client.

### 2. Token format

```
alog_<clientId>_<secret>
```

- `clientId`: 16 lowercase hex characters (8 bytes from `crypto/rand`). Hex so
  that the `_` separator is unambiguous.
- `secret`: 32 bytes from `crypto/rand`, base64url-encoded without padding
  (43 characters). Note that the base64url alphabet **includes `_`**, so the
  secret may itself contain underscores. Parsing must therefore use
  `strings.SplitN(token, "_", 3)`, which splits on the first two underscores
  only and leaves the remainder intact as the secret. Splitting on every
  underscore is a bug that will intermittently reject valid tokens.
- Stored: `sha256Hex([]byte(secret))` in `token_hash`. The secret itself is
  never persisted and never recoverable. It is printed once, at registration or
  rotation.

Authentication:

1. Split the presented token into exactly three parts on the first two `_`.
2. Reject unless part one is the literal `alog`.
3. Primary-key lookup of part two in `audit_clients` -- one indexed read, not a
   table scan.
4. Reject if `revoked_at` is non-null.
5. `subtle.ConstantTimeCompare(sha256Hex(secret), token_hash)`.

A database leak yields only hashes of 256-bit random secrets, which are not
usefully attackable.

### 3. Binding the client to the event

`clientId` is added to `LogRecord` as the first field, with `omitempty`:

```go
type LogRecord struct {
    ClientID string         `json:"clientId,omitempty"`
    App      string         `json:"app"`
    Level    string         `json:"level"`
    Message  string         `json:"message"`
    Metadata map[string]any `json:"metadata,omitempty"`
}
```

The field lives *inside* the record, so it is covered by `payloadHash` and
therefore by `entryHash` and the chain. The client-to-event link is
tamper-evident rather than a mutable column.

**Backward compatibility.** `omitempty` makes this safe for the entries already
written. Both verification paths were checked:

- `FileStore.verifyChainUnsafe` re-marshals the parsed `entry.Record`, so Go
  struct field order determines the bytes. A legacy entry unmarshals with an
  empty `ClientID`, `omitempty` drops it, and the remaining fields marshal in
  their existing order -- byte-identical payload, identical hash.
- `PostgresStore.Verify` re-hashes the stored `record_json` text and is
  unaffected by struct changes entirely.

An explicit regression test locks this in (see Testing).

**Anti-forgery.** The `POST /v1/logs` handler assigns
`input.ClientID = principal.ClientID` *after* unmarshalling and before calling
`store.Append`, overwriting any caller-supplied value. A client cannot attribute
an entry to another client.

### 4. Auth layer

New file `cmd/server/auth.go`:

```go
type Principal struct {
    ClientID string
    Name     string
    Role     string
}

type ClientSummary struct {
    ClientID  string
    Name      string
    Role      string
    CreatedAt time.Time
    Revoked   bool
}

type ClientStore interface {
    Authenticate(token string) (Principal, error)
    Register(name, role string) (clientID string, token string, err error)
    Rotate(clientID string) (token string, err error)
    Revoke(clientID string) error
    List() ([]ClientSummary, error)
}
```

`PostgresClientStore` is the only implementation.

`requireAuth(cs ClientStore, next http.HandlerFunc) http.HandlerFunc` resolves
the bearer token and stores the `Principal` in the request context under an
unexported context key. It composes with the existing `withMethod` helper.

The existing `Store` interface -- `Append`, `Verify`, `QueryLogs` -- **does not
change**. Only `LogRecord` and `LogQuery` gain a field, and the handlers
populate them. This avoids threading a client ID parameter through both storage
backends.

### 5. Endpoint behaviour

| Endpoint | Auth | Scoping |
|---|---|---|
| `GET /v1/health` | none | -- |
| `POST /v1/logs` | required | `clientId` stamped from the token |
| `GET /v1/logs` | required | filtered to the caller's `clientId` |
| `GET /v1/logs/search` | required | filtered to the caller's `clientId` |
| `GET /v1/verify` | required, any role | result stays chain-global |

`/v1/health` stays open because `deployment/deploy.sh:19` polls it as the
post-deploy gate and the systemd unit depends on it.

`/v1/verify` requires a token because its response leaks chain-global
information -- total entry count and the head hash. Any valid client may call
it; the result is inherently global because the chain is global.
`cmd/log-forwarder` already sends its token on this call, so nothing breaks.

**Admin role.** A principal with `role == "admin"` skips the client filter and
sees every entry, including the pre-authorization entries whose `clientId` is
empty. An admin may pass `?clientId=<id>` to scope down to one client. For a
non-admin the `clientId` query parameter is ignored, not honoured and not an
error -- the filter is always forced to the authenticated identity.

### 6. Query filtering

`LogQuery` gains `ClientID string`. Filtering reuses the pattern already
established for `app`:

- `PostgresStore.QueryLogs`: an additional clause
  `record_json::jsonb->>'clientId' = $n`, built through the same
  positional-argument accumulator, so it stays parameterised.
- `FileStore.matchesQuery`: an additional check. It uses **exact** comparison,
  not `strings.EqualFold` as `app` and `level` do, because client IDs are
  case-sensitive generated identifiers.

The client filter is evaluated before the free-text `q` match so that text
search cannot reach across tenants.

Because this predicate is now on every read path, it needs an index. The index
is specified in section 10, because it must be composite with `entry_index` to
serve cursor pagination as well -- a single-column index on `clientId` alone
would not.

### 7. Registration CLI

Admin commands are argv subcommands of the existing server binary, so
deployment continues to ship a single artifact and `deployment/deploy.sh` needs
no change to what it builds or copies.

```
audit clients register --name payments-api [--role admin]
audit clients list
audit clients rotate --id <clientId>
audit clients revoke --id <clientId>
```

Dispatch: if `os.Args[1] == "clients"`, run the admin path and exit; otherwise
start the HTTP server as today. The admin path requires `DATABASE_URL` and does
not start a listener.

`rotate` preserves `client_id` and replaces only `token_hash`, so entries the
client has already written stay attributed to it.

`register` and `rotate` print the full token to stdout exactly once, with a
warning that it cannot be retrieved again. `list` never prints tokens or
hashes.

Because a client row holds exactly one `token_hash`, rotation is a hard
cutover: the previous token stops authenticating the moment the new one is
issued. There is no overlap window. This is a deliberate simplification -- dual
active tokens would mean a second column and a second comparison on the hot
path -- and the operator documentation states the safe ordering rather than
implying a seamless rotation.

### 8. Configuration change

Because the registry is always PostgreSQL and authorization is always enforced,
**`DATABASE_URL` becomes mandatory for every `STORAGE_BACKEND`, including
`file`.** The server exits with a clear message if it is unset.

`docker-compose.yml`, `start_dev.sh` and the provisioned deployment already
supply it. A bare `go run ./cmd/server` with default environment will now fail
until one is set; this is intentional and documented.

Three new variables govern read sizing. They replace constants currently
hardcoded in `normalizeLogQuery`:

| Variable | Default | Meaning |
|---|---|---|
| `DEFAULT_QUERY_LIMIT` | `50` | Page size applied when the caller omits `limit`. |
| `MAX_QUERY_LIMIT` | `500` | Hard ceiling. A larger requested `limit` is clamped, not rejected, preserving today's behaviour. |
| `MAX_QUERY_OFFSET` | `10000` | Largest accepted `offset`. Beyond it the request is rejected and directed to the cursor. |

Each is parsed with the existing `getEnv` helper and falls back to its default
when unset, empty or unparseable, matching how `PORT` and `MAX_PAYLOAD_BYTES`
are already handled.

### 9. Errors

All authentication failures return `401` with body `{"error":"unauthorized"}`
and a `WWW-Authenticate: Bearer` header. Missing, malformed, unknown and
revoked tokens are deliberately indistinguishable, so the endpoint is not an
oracle for probing valid client IDs.

### 10. Pagination and query limits

**The actual bottleneck.** `PostgresStore.QueryLogs` runs
`SELECT COUNT(*) FROM audit_log_entries <where>` on every read to populate
`total`, before it reaches `LIMIT/OFFSET`. That count scans every matching row
regardless of which page was asked for, so it grows linearly with the log even
for page one. `FileStore.QueryLogs` has the same shape: it keeps scanning and
incrementing `matched` after the page is full, purely to produce the total.
Fixing `OFFSET` alone would leave the dominant cost untouched. Both are
addressed together.

Note that offset paging here does *not* suffer page drift: the log is
append-only and ordered ascending by `entry_index`, so concurrent writes land
past the end of the current page. The case for cursors is performance alone,
and the spec should not claim otherwise.

**Cursor.** Keyset pagination on `entry_index`, which is already a monotonic
`BIGINT PRIMARY KEY` on an append-only table -- an ideal cursor key.

The cursor is opaque to callers: base64url, unpadded, of `v1:<entry_index>`.
Opaque so the encoding can change later without breaking callers, and so a
cursor is not mistaken for an offset. The `v1:` prefix makes a future format
change detectable rather than silently misparsed.

- PostgreSQL: `WHERE entry_index > $cursor AND <filters> ORDER BY entry_index
  ASC LIMIT $limit + 1`.
- Fetching `limit + 1` rows is how "is there a next page" is answered without a
  second query. If `limit + 1` rows come back, the extra is discarded and
  `nextCursor` is the encoded index of the last *returned* row. Otherwise
  `nextCursor` is `null` and the caller stops.
- `FileStore`: skip lines whose `Index <= cursor` before doing any filter work,
  and terminate the scan as soon as `limit + 1` matches are collected. The early
  termination is a genuine improvement on today's behaviour, which always reads
  to end of file.

**Index.** Keyset alone is not sufficient once every read is client-scoped.
`entry_index > cursor` walks the primary key in order but must then discard
every row belonging to other clients, so a client holding a small share of a
large log would still scan far. The predicate and the sort key must live in one
index:

```sql
CREATE INDEX IF NOT EXISTS idx_audit_log_entries_client_index
    ON audit_log_entries ((record_json::jsonb->>'clientId'), entry_index);
```

This supersedes the single-column client index sketched earlier; create this
one only. With it, a client-scoped page is an index range scan proportional to
`limit`, not to table size. Admin reads carry no client predicate and fall back
to an ordered primary-key range scan, which is likewise proportional to `limit`.

The index deliberately keys on the expression over `record_json` rather than on
a denormalised `client_id` column. A denormalised column would index a little
more cheaply, but it would sit *outside* the hash chain, so a direct `UPDATE`
could make one client's entries readable by another with nothing to detect it.
Filtering on the hashed field keeps authorization reading from the authoritative
copy.

**Offset, retained and bounded.** `offset` continues to work so existing callers
keep functioning, but a value above `MAX_QUERY_OFFSET` is rejected with `400`
and a message naming the cursor as the alternative. `cursor` and `offset` in the
same request is `400`; the combination is ambiguous and silently preferring one
would hide a caller bug.

**Total, opt-in.** `total` is omitted from the response unless the request
carries `?count=true`, in which case the `COUNT(*)` runs within the caller's
scope. The expensive scan becomes something a caller asks for deliberately.

**Response shape.**

```json
{
  "items": [],
  "limit": 50,
  "nextCursor": "djE6MTQyNw"
}
```

`nextCursor` is `null` on the last page. `total` appears only with
`count=true`. `offset` is echoed only when the caller supplied one, so
offset-based callers see an unchanged shape apart from the new fields.

Two points that would otherwise be read either way:

- `total`, when requested, counts the entire matching set for the caller's
  scope and filters. It deliberately ignores `cursor`, `offset` and `limit`, so
  it is a set size and not a count of what remains.
- Omitting a field rather than sending a zero requires `Total` and `Offset` on
  `LogQueryResult` to become `*int` with `omitempty`. A plain `int` would
  serialise `"total": 0` on every uncounted response, which reads as an empty
  result set and is worse than saying nothing.

**Normalization moves to one place.** `normalizeLogQuery` currently hardcodes
`50` and `500` and is invoked from `parseLogQuery` *and* again inside both store
implementations. With the bounds now configurable, three copies of the limits is
a defect waiting to happen. `normalizeLogQuery` takes a `QueryLimits` value
carried on `Config`, and the stores stop calling it -- `parseLogQuery` becomes
the single normalization point.

**Validation.** Malformed or non-decoding `cursor` is `400`. Non-integer `limit`
or `offset` remains `400` as today. A `limit` above the ceiling is clamped
rather than rejected, preserving current behaviour.

**Honest limits.** The proportional-to-`limit` guarantee holds for client-scoped
reads on PostgreSQL. Two cases remain linear and are accepted:

- Free-text `q` search compiles to `ILIKE '%...%'`, which no index serves. It is
  bounded by the requesting client's own data, not by the global log.
- A highly selective secondary filter such as `level=ERROR` over a client with
  few matches walks that client's rows until the page fills. Again bounded by
  one client's data.
- The file backend stays linear in file size for the skip portion. It is the
  development default; production runs PostgreSQL, which is where the guarantee
  is needed.

## Incidental fix

`start_dev.sh:8` runs `go run cmd/server/main.go` -- a single named file. Adding
`auth.go` to `package main` in `cmd/server` breaks it. It must become
`go run ./cmd/server`. This is not optional cleanup; the change does not work
without it.

## Testing

`cmd/server` currently has no test coverage beyond `config_test.go`. Three
layers, test-first:

**Pure functions, no database:**

- Token generate, parse, hash round-trip.
- Malformed token rejection: wrong prefix, too few segments, empty secret.
- Constant-time comparison is used on the hash path.
- Legacy chain stability: take a hand-written pre-authorization entry, unmarshal
  into the new `LogRecord`, re-marshal, and assert byte equality plus an
  unchanged recomputed `entryHash`.

**Handlers, no database:** `httptest` against the real mux, wired with an
in-memory fake `ClientStore` and a temp-directory `FileStore`. This layer proves
the security properties:

- `401` on absent, malformed, unknown and revoked tokens.
- A write stamps the authenticated `clientId`.
- A write that supplies someone else's `clientId` in the body has it
  overwritten, not honoured.
- Client A cannot read client B's entries through `GET /v1/logs`, through
  `/v1/logs/search`, or through a `?clientId=` parameter.
- An admin token reads across clients and sees legacy entries.
- `/v1/health` answers without a token; `/v1/verify` does not.

**Pagination, no database:** cursor encode/decode round-trip; malformed cursor
rejected; `limit` defaulting from `DEFAULT_QUERY_LIMIT` when absent; clamping at
`MAX_QUERY_LIMIT`; `offset` past `MAX_QUERY_OFFSET` rejected; `cursor` plus
`offset` rejected; `total` absent without `count=true` and present with it.
Against `FileStore`, a seeded log paged end-to-end by cursor returns every entry
exactly once with no gap or repeat across page boundaries, and `nextCursor` is
`null` precisely on the last page -- including the boundary case where the entry
count is an exact multiple of the page size.

**PostgreSQL client store:** integration tests behind a `TEST_DATABASE_URL`
environment variable, skipped with `t.Skip` when unset so `make test` stays
green offline. Covers schema creation, register, authenticate, rotate
invalidating the previous token, revoke, and list. The same gated suite covers
cursor paging against real SQL -- including that the composite index exists and
that a client-scoped page returns identical results to the file backend for the
same seeded data.

## Documentation deliverables

Integration documentation is part of this work, not a follow-up.

**`docs/authorization.md`** -- the primary integration guide, written for an
engineer wiring up a new service:

- The model in a paragraph: client is the tenant, `app` is a free label.
- Getting a token: what the operator runs, what the requester receives, and the
  fact that it is shown once.
- Making authenticated calls: `curl` examples for write, read, search and
  verify, each with the `Authorization` header.
- What a client can and cannot see, stated plainly.
- Token rotation and revocation: that rotation is a hard cutover with no
  overlap window, and the ordering that keeps the gap to a minimum (schedule a
  brief window, rotate, update the consumer's config, restart it).
- The full error table, with what each status means and the usual cause.
- Migration notes for an existing unauthenticated caller.

**`docs/querying.md`** -- the read guide, written for someone paging the log:

- The default page size and where it comes from, plus the two ceilings.
- A worked cursor loop: first request, following `nextCursor`, stopping on
  `null` -- in `curl` and in JavaScript.
- Why `total` is opt-in and what `?count=true` costs.
- Migrating from `offset`, and the `MAX_QUERY_OFFSET` error a deep offset now
  returns.
- A short, honest performance note: what is proportional to page size and what
  is not.

**`README.md`** -- the API table gains an auth column; the Config section gains
the mandatory `DATABASE_URL` note and the three read-limit variables; a short
Authorization section links to `docs/authorization.md`. The query-parameter list
is rewritten for `cursor` and `count` and links to `docs/querying.md`.

**`clients/README.md`** -- producer examples updated to set the token. The Go
library already has `AuthToken`; document it. The Node library at
`clients/node-lib/index.mjs` has no auth support at all and gains an equivalent
option, documented alongside.

**`cmd/log-forwarder/README.md`** -- clarify that `auth_bearer_token` is now the
registered client token and where it comes from.

**`deployment/README.md`** -- an operations section: registering a client on the
server, listing clients, rotating a leaked token, revoking a decommissioned one.

**`postman/Audit-Logging-API.postman_collection.json`** -- a collection-level
bearer variable applied to every request except health. The existing
"List Logs (Paginated)" request is rewritten to page by `cursor` instead of
`offset`, with a test script capturing `nextCursor` into a collection variable
so the request can be re-sent to walk pages.

## Files touched

New:

- `cmd/server/auth.go`
- `cmd/server/clients_cli.go`
- `cmd/server/query.go` -- cursor encode/decode, `QueryLimits`, normalization
- `cmd/server/auth_test.go`
- `cmd/server/query_test.go`
- `cmd/server/handlers_test.go`
- `cmd/server/clientstore_postgres_test.go`
- `docs/authorization.md`
- `docs/querying.md`

Modified:

- `cmd/server/main.go` -- `LogRecord`, `LogQuery`, `LogQueryResult`, config
  validation and the new limit variables, handler wiring, argv dispatch, both
  `QueryLogs` implementations, `parseLogQuery`, `ensureSchema`
- `clients/node-lib/index.mjs` -- token support
- `start_dev.sh` -- `go run ./cmd/server`
- `README.md`, `clients/README.md`, `cmd/log-forwarder/README.md`,
  `deployment/README.md`
- `postman/Audit-Logging-API.postman_collection.json`
