# Authorization

Every call that writes or reads log entries needs a token. This page covers
getting one, using it, and what happens when it goes wrong.

## The model

A **client** is a tenant. It is the unit of ownership and the unit of access:

- Every entry a client writes is stamped with that client's id by the server.
- Every read a client makes returns only that client's entries.

`app` is *not* the boundary. It stays a free-text label you can use however you
like — one client may write under many app names, and two clients may use the
same one without seeing each other's entries.

The `clientId` is stored inside the hashed record, so it is covered by the
tamper-evident hash chain. Attribution cannot be altered after the fact without
`GET /v1/verify` failing.

## Getting a token

Registration is deliberately local-only: there is no HTTP endpoint for it. An
operator runs this on the server, where `DATABASE_URL` is already set:

```bash
audit clients register --name payments-api
```

```
client id: a1b2c3d4e5f60718
token:     alog_a1b2c3d4e5f60718_x7Qk...

Give this token to the client now. Only its hash is stored, so the
token is not recoverable. If it is lost, run: audit clients rotate
```

**The token is shown once.** The service stores only its SHA-256 hash, so
nobody — including the operator — can read it back. If it is lost, rotate.

For a client that needs to read across all tenants (an operations dashboard, a
compliance export), register it as an admin instead:

```bash
audit clients register --name ops-dashboard --role admin
```

Treat an admin token as far more sensitive than a client token: it can read
every entry in the system.

### CLI exit codes

The `audit clients` subcommands (`register`, `list`, `rotate`, `revoke`) use a
fixed exit-code contract. If you drive registration from a deployment script,
branch on these rather than parsing output:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | The operation failed — for example the database was unreachable, or `rotate`/`revoke` was given an id that does not exist. |
| `2` | Usage error — no subcommand, an unknown subcommand, or a missing required flag. This is detected before the database is touched, so a typo never surfaces as a database failure. |

## Making authenticated calls

Send the token as a bearer credential. The scheme is case-insensitive; the
token is not.

### Write an entry

```bash
curl -s -X POST http://localhost:8080/v1/logs \
  -H "authorization: Bearer $AUDIT_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "app": "payments-api",
    "level": "INFO",
    "message": "invoice created",
    "metadata": {"invoiceId": "inv_123"}
  }'
```

You do not send `clientId`. If you do, the server overwrites it with the
identity behind your token — attribution is not something a caller can set.

### Read your entries

```bash
curl -s "http://localhost:8080/v1/logs?limit=20" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

### Search your entries

```bash
curl -s "http://localhost:8080/v1/logs/search?q=timeout&limit=10" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

### Verify the chain

```bash
curl -s http://localhost:8080/v1/verify \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

`GET /v1/verify` is authenticated, but its result is **not** scoped to you.
Any valid token — client or admin — gets back the state of the whole chain:
the total entry count across every client, and the head hash. It needs a
token only because that information is otherwise free to read; it does not
mean the response is filtered to your entries.

### Health

`GET /v1/health` takes no token. It is the only endpoint that does not.

## What you can and cannot see

| You are | You see |
| --- | --- |
| A `client` | Only entries your own token wrote. |
| An `admin` | Every entry, including entries written before authorization existed. Add `?clientId=<id>` to narrow to one client. |

Passing `?clientId=` as a non-admin does nothing. It is ignored rather than
rejected, so the response cannot be used to work out which client ids exist.

Entries written before this feature shipped have no `clientId`. They remain in
the chain and still verify, but only an admin can read them, and only mixed in
with everything else: `clientId` empty or omitted means "everything", not
"only the unattributed entries." There is no filter value that selects just
the legacy rows — an admin auditing them has to read everything and pick them
out client-side (they are the entries whose `record.clientId` is absent).

## Language clients

Go — `clients/go-lib`:

```go
client := auditclient.New("http://localhost:8080/v1/logs", nil)
client.AuthToken = os.Getenv("AUDIT_TOKEN")
```

Node — `clients/node-lib`:

```javascript
const logger = new AuditLogger({
  endpoint: "http://localhost:8080/v1/logs",
  authToken: process.env.AUDIT_TOKEN
});
```

Log forwarder — set `auth_bearer_token` in the forwarder's config file to the
registered token. See `cmd/log-forwarder/README.md`.

Both libraries retry on `429` and `5xx` only. A `401` is returned to you
immediately, because a rejected token will not become valid on a retry.

## Rotation

```bash
audit clients rotate --id a1b2c3d4e5f60718
```

**Rotation is a hard cutover.** A client row holds exactly one token hash, so
the previous token stops working the instant the new one is issued. There is no
overlap window. The CLI says this explicitly in its output:

```
token: alog_a1b2c3d4e5f60718_newSecret...

This token is not recoverable: only its hash is stored. Save it now.
The previous token stopped working the moment this one was issued.
Update the client's configuration and restart it now.
```

The client id does not change, so entries the client has already written keep
their attribution.

To keep the gap small:

1. Schedule a brief window — writes during the gap will fail with `401`.
2. Run `rotate` and capture the new token.
3. Update the client's configuration.
4. Restart the client.

If the client buffers and retries on failure, the entries written during the gap
are not lost, but a `401` is not retried — they will land only if the client
re-sends after the restart. Check your producer's behaviour before assuming.

## Revocation

```bash
audit clients revoke --id a1b2c3d4e5f60718
```

The token stops working immediately. The client row is kept, so entries it
already wrote stay attributable to a named client. A revoked client cannot be
rotated back into service — register a new one.

## Errors

| Status | Body | What happened |
| --- | --- | --- |
| `401` | `{"error":"unauthorized"}` | No token, a malformed token, an unknown token, a wrong secret, or a revoked token. These are deliberately indistinguishable, so the endpoint cannot be used to probe for valid ids. |
| `400` | `{"error":"invalid cursor"}` | The `cursor` parameter was not one the server issued. See `docs/querying.md`. |
| `400` | `{"error":"offset exceeds maximum of N; use cursor for deep pagination"}` | Paging too deep with `offset`. See `docs/querying.md`. |
| `503` | `{"error":"authentication unavailable"}` | The client registry could not be reached. Your token is not the problem; the database is. Retry. |
| `409` | a `VerifyResult` with `"valid": false` | `/v1/verify` found a break in the chain. Escalate — this means entries were altered. |

A `401` always carries `WWW-Authenticate: Bearer`.

## Migrating an existing caller

Before this change every endpoint was open. To migrate a service that is
already writing:

1. Ask an operator to register it: `audit clients register --name <service>`.
2. Put the token in the service's secret store. Do not commit it.
3. Set `AuthToken` (Go), `authToken` (Node), or `auth_bearer_token` (forwarder).
4. Deploy. Writes now carry attribution.

Entries the service wrote *before* the migration keep an empty `clientId` and
will not appear in its reads. They are still in the chain and still verify, and
an admin can read them (mixed in with every other client's entries — see
"What you can and cannot see" above). They are not retroactively attributed;
rewriting them would break the hash chain, which is the whole point of the
chain.
