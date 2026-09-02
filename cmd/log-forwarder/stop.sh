#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="log-forwarder"
PID_FILE="${PID_FILE:-$ROOT_DIR/$APP_NAME.pid}"
GRACEFUL_TIMEOUT_SECONDS="${GRACEFUL_TIMEOUT_SECONDS:-15}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "$APP_NAME is not running (pid file not found: $PID_FILE)"
  exit 0
fi

pid="$(cat "$PID_FILE")"
if [[ -z "$pid" ]]; then
  echo "Pid file is empty; cleaning up $PID_FILE"
  rm -f "$PID_FILE"
  exit 0
fi

if ! kill -0 "$pid" 2>/dev/null; then
  echo "Process $pid is not running; removing stale pid file"
  rm -f "$PID_FILE"
  exit 0
fi

echo "Stopping $APP_NAME (PID $pid)"
kill -TERM "$pid"

elapsed=0
while kill -0 "$pid" 2>/dev/null; do
  if (( elapsed >= GRACEFUL_TIMEOUT_SECONDS )); then
    echo "Graceful stop timed out after ${GRACEFUL_TIMEOUT_SECONDS}s; sending SIGKILL"
    kill -KILL "$pid" 2>/dev/null || true
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

rm -f "$PID_FILE"
echo "$APP_NAME stopped"
