#!/usr/bin/env bash
# Runs N backend replicas on this machine for multi-replica and scale testing.
#   scripts/replicas.sh up [N]     replica i listens on OpAMP :432i and API :808i (i from 0)
#   scripts/replicas.sh down
#   scripts/replicas.sh kill <i>   SIGKILL one replica, simulating a crash
# Logs and pid files go to ${OPAMP_RUN_DIR:-/tmp/opamp-replicas}. Needs `make deps-up` first.
set -euo pipefail
cd "$(dirname "$0")/.."

run_dir="${OPAMP_RUN_DIR:-/tmp/opamp-replicas}"
export JWT_SIGNING_KEY="${JWT_SIGNING_KEY:-dev-only-signing-key-do-not-use-in-prod}"
export LOCAL_ADMIN_PASSWORD="${LOCAL_ADMIN_PASSWORD:-admin}"
export DEV_MODE=true

stop() {
  for pid_file in "$run_dir"/*.pid; do
    [ -e "$pid_file" ] || continue
    pid="$(cat "$pid_file")"
    kill "$pid" &>/dev/null || true
    # Wait for the graceful shutdown so a restart never overlaps the old process.
    while kill -0 "$pid" &>/dev/null; do sleep 0.2; done
    rm -f "$pid_file"
  done
}

case "${1:-}" in
  up)
    count="${2:-3}"
    mkdir -p "$run_dir"
    stop
    go build -o bin/opamp-backend ./cmd/server
    for i in $(seq 0 $((count - 1))); do
      OPAMP_REPLICA_ID="replica-$i" OPAMP_LISTEN_ADDR=":432$i" API_LISTEN_ADDR=":808$i" \
        nohup bin/opamp-backend >"$run_dir/replica-$i.log" 2>&1 &
      echo $! >"$run_dir/replica-$i.pid"
    done
    echo "started $count replicas; logs in $run_dir"
    ;;
  down) stop ;;
  kill)
    kill -9 "$(cat "$run_dir/replica-$2.pid")"
    rm -f "$run_dir/replica-$2.pid"
    ;;
  *)
    sed -n '2,6p' "$0"
    exit 2
    ;;
esac
