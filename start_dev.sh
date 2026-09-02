#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="audit"

SERVER_PKG="${SERVER_PKG:-./cmd/server}"
PID_FILE="${PID_FILE:-$ROOT_DIR/$APP_NAME.pid}"
RUNTIME_LOG="${RUNTIME_LOG:-$ROOT_DIR/log}"
DB_USERNAME="${DB_USERNAME:-audit}"
DB_PASSWORD="${DB_PASSWORD:-audit}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

export PORT="${PORT:-8090}"
export STORAGE_BACKEND="${STORAGE_BACKEND:-postgres}"
export DATABASE_URL="${DATABASE_URL:-postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/audit?sslmode=disable}"
if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(cat "$PID_FILE")"
  if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "$APP_NAME is already running with PID $existing_pid"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

echo "Starting $APP_NAME"
echo "- package:  $SERVER_PKG"
echo "- pid file: $PID_FILE"
echo "- output:   $RUNTIME_LOG"

cd "$ROOT_DIR"
nohup go run "$SERVER_PKG" >> "$RUNTIME_LOG" 2>&1 &
app_pid=$!
echo "$app_pid" > "$PID_FILE"

sleep 1
if kill -0 "$app_pid" 2>/dev/null; then
  echo "$APP_NAME started with PID $app_pid"
else
  echo "Failed to start $APP_NAME. Check $RUNTIME_LOG"
  rm -f "$PID_FILE"
  exit 1
fi
