#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <endpoint>" >&2
  exit 1
fi

endpoint="$1"

case "$endpoint" in
  queue|stats|nodes|processing|completed)
    ;;
  *)
    echo "Error: invalid endpoint '$endpoint'" >&2
    echo "Allowed endpoints: queue, stats, nodes, processing, completed" >&2
    exit 1
    ;;
esac

wget -q -O - "http://localhost:43301/${endpoint}" | jq .

