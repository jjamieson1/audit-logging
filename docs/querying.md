# Reading and paging the log

## Two endpoints, one contract

Reads are served by two paths:

| Path | Use |
| --- | --- |
| `GET /v1/logs` | Listing and filtering. |
| `GET /v1/logs/search` | Free-text search. |

**They are the same handler.** Both accept every parameter below — `limit`,
`cursor`, `count`, `offset`, `app`, `level`, `q`/`text`, and `clientId` for an
admin — return the identical response shape, and are scoped to your client the
same way. `/v1/logs/search` is not a separate or reduced API, and it is not
deprecated.

Which you use is a matter of taste: `q` works on `/v1/logs` too, so a client
may send everything to `/v1/logs`, or switch to `/v1/logs/search` when a search
box is non-empty. Both are supported and neither is going away.

## Page size

Every read is bounded. If you do not pass `limit`, the server applies its
configured default.

| Setting | Default | Effect |
| --- | --- | --- |
| `DEFAULT_QUERY_LIMIT` | `50` | Page size when you omit `limit`. |
| `MAX_QUERY_LIMIT` | `500` | Ceiling. A larger `limit` is silently clamped to this, not rejected. |
| `MAX_QUERY_OFFSET` | `10000` | Largest accepted `offset`. Past this you get a `400`. |

These are environment variables on the service, so the numbers above are
defaults, not guarantees — check with whoever operates your deployment.

## Paging with a cursor

Prefer `cursor` over `offset`. A cursor page costs the same whether it is the
first page or the ten-thousandth, because it is served by an index keyed on
your client id and entry position, not a table scan from the start.

The first request omits `cursor`:

```bash
curl -s "http://localhost:8090/v1/logs?limit=50" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

```json
{
  "items": [],
  "limit": 50,
  "nextCursor": "djE6MTQyNw"
}
```

Each subsequent request passes back the `nextCursor` you were given:

```bash
curl -s "http://localhost:8090/v1/logs?limit=50&cursor=djE6MTQyNw" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

**`nextCursor` is `null` on the last page.** That is the stop condition — do not
keep requesting until you get an empty `items` array, because the last full page
already tells you it is the last.

Treat the cursor as opaque. It encodes a position, but the encoding is versioned
and may change; construct one yourself and it will be rejected with `400
{"error":"invalid cursor"}`.

```javascript
async function* readAllLogs(token, { baseUrl = "http://localhost:8090", limit = 50 } = {}) {
  let cursor = null;

  for (;;) {
    const url = new URL(`${baseUrl}/v1/logs`);
    url.searchParams.set("limit", String(limit));
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

    const response = await fetch(url, {
      headers: { authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      throw new Error(`audit service returned ${response.status}`);
    }

    const page = await response.json();
    yield* page.items;

    // null means that was the last page.
    if (!page.nextCursor) {
      return;
    }
    cursor = page.nextCursor;
  }
}
```

## Counting

`total` is **not** returned by default. Ask for it explicitly:

```bash
curl -s "http://localhost:8090/v1/logs?limit=50&count=true" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

```json
{
  "items": [],
  "limit": 50,
  "nextCursor": "djE6MTQyNw",
  "total": 1427
}
```

`total` is the size of the whole matching set for your filters. It ignores
`cursor`, `offset` and `limit` entirely — the server counts every matching row
independently of the page you asked for — so it is not a count of what is left
to read, and it does not shrink as you page through.

It is opt-in because producing it means counting every matching row. On a large
log that is the most expensive thing a read can do. Ask for it on the first page
of a UI if you need a count; do not ask for it on every page of a bulk export.

## Filters

| Parameter | Effect |
| --- | --- |
| `app` | Exact match on the app label. |
| `level` | Exact match on the level. |
| `q` or `text` | Free-text search across message and metadata. Works on `/v1/logs` and on `/v1/logs/search` identically. |
| `clientId` | **Admin only.** Narrows to one client. Ignored for everyone else. |

Filters combine with `AND`, and always apply within what you are allowed to see.
For a non-admin that scope is fixed to your own client; for an admin who omits
`clientId`, that scope is everything, including entries with no `clientId` at
all (see `docs/authorization.md` for what those are and why there is no way to
select only them).

## If you are still using `offset`

`offset` still works, so nothing breaks today:

```bash
curl -s "http://localhost:8090/v1/logs?limit=50&offset=100" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

Two limits apply:

- Past `MAX_QUERY_OFFSET` you get `400 {"error":"offset exceeds maximum of
  10000; use cursor for deep pagination"}` (the number reflects your
  deployment's `MAX_QUERY_OFFSET`).
- `cursor` and `offset` together is a `400
  {"error":"cursor and offset cannot be combined"}`. Pick one.

When `offset` is used it is echoed back in the response, so an existing caller
sees the shape it expects plus the new fields.

## Performance, honestly

A cursor page scoped to your client is served by an index and costs about the
same regardless of how large the log has grown. Three things are not:

- **Free-text `q`** is a substring scan (`ILIKE '%...%'`) that no index serves.
  It is bounded by your own data, not the whole log, but it gets slower as your
  data grows.
- **A filter that matches almost nothing** — `level=ERROR` for a client with no
  errors — walks your entries looking for a full page before giving up, because
  `level` is not indexed.
- **`count=true`** counts every matching row, every time, whatever page you are
  on.

If a read feels slow, check for those three before assuming the cursor is at
fault.
