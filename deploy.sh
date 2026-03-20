#!/usr/bin/env bash

# I had to run these to get the script to work
# sudo -u postgres psql -d audit -c "GRANT CREATE ON SCHEMA public TO mininghub_dbuser;"
# sudo -u postgres psql -d audit -c "GRANT USAGE ON SCHEMA public TO mininghub_dbuser;"
# sudo -u postgres psql -d audit -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO mininghub_dbuser;"
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <remote-server>"
	echo "Example: $0 mininghub-prod-audit"
	exit 1
fi

REMOTE_SERVER="$1"
APP_DIR="/app/audit"
SERVICE_NAME="audit"
BUILD_DIR="build"
BINARY_NAME="audit"
BINARY_PATH="$BUILD_DIR/$BINARY_NAME"
LOCAL_SERVICE_FILE="audit.service"
REMOTE_SERVICE_FILE="/etc/systemd/system/audit.service"
LOCAL_START_SCRIPT="start.sh"
LOCAL_STOP_SCRIPT="stop.sh"
LOCAL_RESTART_SCRIPT="restart.sh"

echo "[1/8] Stopping remote service: $SERVICE_NAME on $REMOTE_SERVER"
ssh "$REMOTE_SERVER" "sudo systemctl stop $SERVICE_NAME"


echo "[2/8] Removing remote files in $APP_DIR/*"
ssh "$REMOTE_SERVER" "sudo rm -rf $APP_DIR/*"

echo "[3/8] Building Linux amd64 binary: $BINARY_NAME"
mkdir -p "$BUILD_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -o "$BINARY_PATH" cmd/server/main.go

echo "[4/8] Copying binary to remote temp path and moving to $APP_DIR with sudo"
scp "$BINARY_PATH" "$REMOTE_SERVER:/tmp/$BINARY_NAME"
ssh "$REMOTE_SERVER" "sudo mkdir -p $APP_DIR && sudo mv /tmp/$BINARY_NAME $APP_DIR/$BINARY_NAME && sudo chmod 755 $APP_DIR/$BINARY_NAME"

echo "[5/8] Copying scripts to $REMOTE_SERVER:$APP_DIR"
for script in "$LOCAL_START_SCRIPT" "$LOCAL_STOP_SCRIPT" "$LOCAL_RESTART_SCRIPT"; do
	if [[ ! -f "$script" ]]; then
		echo "Required script not found: $script"
		exit 1
	fi
done
scp "$LOCAL_START_SCRIPT" "$LOCAL_STOP_SCRIPT" "$LOCAL_RESTART_SCRIPT" "$REMOTE_SERVER:/tmp/"
ssh "$REMOTE_SERVER" "sudo mv /tmp/start.sh $APP_DIR/start.sh && sudo mv /tmp/stop.sh $APP_DIR/stop.sh && sudo mv /tmp/restart.sh $APP_DIR/restart.sh && sudo chmod 755 $APP_DIR/start.sh $APP_DIR/stop.sh $APP_DIR/restart.sh"

echo "[6/8] setting ownership for $APP_DIR"

ssh "$REMOTE_SERVER" "sudo chown -R audit:audit $APP_DIR"

echo "[7/8] Starting remote service: $SERVICE_NAME on $REMOTE_SERVER"
ssh "$REMOTE_SERVER" "sudo systemctl start $SERVICE_NAME"

echo "[8/8] "Deployment completed successfully to $REMOTE_SERVER"