# Deployment

Deploys the audit logging service (`cmd/server`) to an Ubuntu 24.04 host over SSH.

The service runs under systemd as a dedicated `audit` user, stores entries in a
local PostgreSQL 16 database, and listens on `127.0.0.1:8090` only.

## Layout on the server

| Path | Contents |
| --- | --- |
| `/app/audit/audit` | The binary |
| `/app/audit/audit.prev` | Previous binary, kept for rollback |
| `/etc/audit/audit.env` | `DATABASE_URL` and runtime config, `root:audit` `0640` |
| `/etc/systemd/system/audit.service` | Unit file |

## First-time setup

```bash
./deployment/provision.sh muni-demo
```

This installs PostgreSQL and `ufw`, creates the `audit` system user, creates the
`audit` role and database, generates a random database password, writes
`/etc/audit/audit.env`, installs the unit, and enables it so the service starts
at boot. It leaves the service stopped because no binary is installed yet.

`provision.sh` is safe to re-run. An existing `/etc/audit/audit.env` is never
overwritten, so the database password survives repeat runs.

The firewall allows SSH only — port 8090 is never opened. Pass `SKIP_UFW=1` to
leave firewall configuration alone.

## Deploying

```bash
./deployment/deploy.sh muni-demo
```

Builds a static `linux/amd64` binary, copies it over, keeps the outgoing build
as `audit.prev`, restarts the service, and polls `/v1/health` on the server. If
the health check fails it prints the last 50 journal lines and exits non-zero.

## Reaching the API

The service binds to loopback, so use an SSH tunnel:

```bash
ssh -N -L 8090:127.0.0.1:8090 muni-demo
```

Then, from your machine:

```bash
curl -s http://localhost:8090/v1/health
curl -s http://localhost:8090/v1/verify -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8090/v1/logs?limit=20" -H "authorization: Bearer $AUDIT_TOKEN"
```

All but `/v1/health` need a bearer token — see "Managing clients" below to
mint one, and [../docs/authorization.md](../docs/authorization.md) for the
full model.

## Managing clients

Client registration runs on the server, against the local database. The admin
commands are subcommands of the same binary that runs the service, so there is
nothing extra to deploy.

```bash
ssh muni-demo
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) /app/audit/audit clients list
```

Register a new client and hand over the token:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients register --name payments-api
```

The token is printed once and only its hash is stored. Deliver it over a
channel you would use for any other credential — never over the same ticket or
chat thread you would use for its client id alone.

Rotate a leaked token:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients rotate --id <clientId>
```

Rotation is a hard cutover: the old token stops working immediately, so update
and restart the client promptly. The client id is unchanged, so entries it has
already written keep their attribution.

Decommission a client:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients revoke --id <clientId>
```

The row is kept so historical entries stay attributable. A revoked client
cannot be rotated back into service — register a new one.

An `admin`-role client can read every tenant's entries. Register one only when
something genuinely needs a cross-tenant view, and treat its token accordingly.

See [../docs/authorization.md](../docs/authorization.md) for the full
authorization model.

## Operations

```bash
ssh muni-demo "sudo systemctl status audit"
ssh muni-demo "sudo journalctl -u audit -f"
ssh muni-demo "sudo systemctl restart audit"
```

## Rollback

```bash
ssh muni-demo "sudo cp -a /app/audit/audit.prev /app/audit/audit && sudo systemctl restart audit"
```

## Rotating the database password

```bash
ssh muni-demo "sudo rm /etc/audit/audit.env"
./deployment/provision.sh muni-demo
ssh muni-demo "sudo systemctl restart audit"
```

`provision.sh` generates a new password, resets the role, and rewrites the env
file.

## Configuration

Both scripts read these from the environment, with the defaults shown:

| Variable | Default | Used by |
| --- | --- | --- |
| `APP_DIR` | `/app/audit` | both |
| `ENV_DIR` | `/etc/audit` | both |
| `SERVICE_NAME` | `audit` | both |
| `SERVICE_USER` | `audit` | both |
| `DB_NAME` / `DB_USER` | `audit` | `provision.sh` |
| `PORT` | `8090` | `provision.sh` |
| `BIND_ADDR` | `127.0.0.1` | `provision.sh` |
| `SKIP_UFW` | `0` | `provision.sh` |
| `HEALTH_URL` | `http://127.0.0.1:8090/v1/health` | `deploy.sh` |

To expose the service beyond loopback, set `BIND_ADDR=0.0.0.0` when provisioning
and open the port yourself — nothing here opens 8090.
