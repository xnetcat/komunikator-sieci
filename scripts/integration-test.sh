#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

compose_files=(-f docker-compose.test.yml)

echo "[+] Building images and running test stack"
docker compose "${compose_files[@]}" up --build --abort-on-container-exit || true

echo "[+] Capturing exit codes"
get_code() {
  local name=$1
  local cid
  cid=$(docker compose "${compose_files[@]}" ps -a -q "$name")
  if [[ -z "$cid" ]]; then
    echo 1
    return
  fi
  docker inspect -f '{{.State.ExitCode}}' "$cid"
}

rc_a=$(get_code peer-a)
rc_b=$(get_code peer-b)
rc_c=$(get_code peer-c)

echo "peer-a exit: $rc_a"
echo "peer-b exit: $rc_b"
echo "peer-c exit: $rc_c"

if [[ "$rc_a" == "0" && "$rc_b" == "0" && "$rc_c" == "0" ]]; then
  echo "TESTS PASS"
  exit 0
else
  echo "TESTS FAIL"
  echo "--- peer-a logs ---"; docker compose "${compose_files[@]}" logs --no-color peer-a || true
  echo "--- peer-b logs ---"; docker compose "${compose_files[@]}" logs --no-color peer-b || true
  echo "--- peer-c logs ---"; docker compose "${compose_files[@]}" logs --no-color peer-c || true
  exit 1
fi


