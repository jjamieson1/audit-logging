#!/usr/bin/env bash
#
# Build the audit server for linux/amd64 and deploy it to a provisioned host.
#
# Run ./provision.sh <ssh-host> once before the first deploy.
#
# Usage: ./deploy.sh <ssh-host>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_DIR="${APP_DIR:-/app/audit}"
ENV_DIR="${ENV_DIR:-/etc/audit}"
SERVICE_NAME="${SERVICE_NAME:-audit}"
SERVICE_USER="${SERVICE_USER:-audit}"
BINARY_NAME="${BINARY_NAME:-audit}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8090/v1/health}"
HEALTH_RETRIES="${HEALTH_RETRIES:-15}"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <ssh-host>" >&2
  echo "Example: $0 muni-demo" >&2
  exit 1
fi

REMOTE_HOST="$1"
BUILD_DIR="$REPO_ROOT/build"
BINARY_PATH="$BUILD_DIR/$BINARY_NAME"

echo "[1/5] Checking $REMOTE_HOST is provisioned"
if ! ssh -n "$REMOTE_HOST" "sudo test -f $ENV_DIR/audit.env"; then
  echo "$ENV_DIR/audit.env not found on $REMOTE_HOST." >&2
  echo "Run ./provision.sh $REMOTE_HOST first." >&2
  exit 1
fi

echo "[2/5] Building linux/amd64 binary"
mkdir -p "$BUILD_DIR"
(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BINARY_PATH" ./cmd/server)

echo "[3/5] Copying binary to $REMOTE_HOST"
scp -q "$BINARY_PATH" "$REMOTE_HOST:/tmp/$BINARY_NAME.new"

echo "[4/5] Installing binary and restarting $SERVICE_NAME"
ssh "$REMOTE_HOST" "sudo env \
  APP_DIR='$APP_DIR' \
  SERVICE_NAME='$SERVICE_NAME' \
  SERVICE_USER='$SERVICE_USER' \
  BINARY_NAME='$BINARY_NAME' \
  bash -s" <<'REMOTE'
set -euo pipefail

TARGET="$APP_DIR/$BINARY_NAME"

# Keep the outgoing build so a bad deploy can be rolled back in one command.
if [[ -f "$TARGET" ]]; then
  cp -a "$TARGET" "$TARGET.prev"
fi

install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "/tmp/$BINARY_NAME.new" "$TARGET"
rm -f "/tmp/$BINARY_NAME.new"

systemctl restart "$SERVICE_NAME"
REMOTE

echo "[5/5] Waiting for health check"
attempt=1
while true; do
  if ssh -n "$REMOTE_HOST" "curl -fsS --max-time 3 '$HEALTH_URL' >/dev/null 2>&1"; then
    echo "Health check passed on attempt $attempt"
    break
  fi

  if (( attempt >= HEALTH_RETRIES )); then
    echo
    echo "Health check failed after $HEALTH_RETRIES attempts. Recent logs:" >&2
    ssh -n "$REMOTE_HOST" "sudo journalctl -u $SERVICE_NAME -n 50 --no-pager" >&2 || true
    echo >&2
    echo "Roll back with:" >&2
    echo "  ssh $REMOTE_HOST \"sudo cp -a $APP_DIR/$BINARY_NAME.prev $APP_DIR/$BINARY_NAME && sudo systemctl restart $SERVICE_NAME\"" >&2
    exit 1
  fi

  attempt=$((attempt + 1))
  sleep 1
done

echo
echo "Deployment to $REMOTE_HOST complete."
ssh -n "$REMOTE_HOST" "systemctl status $SERVICE_NAME --no-pager --lines=0" || true
