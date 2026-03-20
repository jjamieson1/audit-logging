#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="audit"

BINARY_PATH="${BINARY_PATH:-$ROOT_DIR/$APP_NAME}"
PID_FILE="${PID_FILE:-$ROOT_DIR/$APP_NAME.pid}"
RUNTIME_LOG="${RUNTIME_LOG:-$ROOT_DIR/log}"
DB_PASSWORD="akabaka@1"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(cat "$PID_FILE")"
  if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "$APP_NAME is already running with PID $existing_pid"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

echo "Starting $APP_NAME"
echo "- binary:   $BINARY_PATH"
echo "- pid file: $PID_FILE"
echo "- output:   $RUNTIME_LOG"

cd "$ROOT_DIR"
nohup env STORAGE_BACKEND=postgres DATABASE_URL="postgres://mininghub_dbuser:${DB_PASSWORD}@localhost:5432/audit?sslmode=disable" "$BINARY_PATH" >> "$RUNTIME_LOG" 2>&1 &
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