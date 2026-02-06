#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <job_id>" >&2
  exit 1
fi

job_id="$1"

# Validate integer
if ! [[ "$job_id" =~ ^[0-9]+$ ]]; then
  echo "Error: job_id must be an integer" >&2
  exit 1
fi

# Check for GIT_SECRET environment variable
if [[ -z "${GIT_SECRET:-}" ]]; then
  echo "Error: GIT_SECRET environment variable must be set" >&2
  exit 1
fi

# Compute SHA256(GIT_SECRET + job_id)
message="${GIT_SECRET}${job_id}"
sha256_hash=$(echo -n "$message" | sha256sum | awk '{print $1}')

# Format: sha256=<hex>:<job_id>
auth_param="sha256=${sha256_hash}:${job_id}"

# Make request and capture both response body and HTTP status code
response=$(curl -s -w "\n%{http_code}" "http://localhost:43301/rerun/${auth_param}")

# Split response into body and status code (last line)
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

# Display results
echo "$body"
echo "HTTP Status: $http_code"

# Exit with error if not 200
if [[ "$http_code" != "200" ]]; then
  exit 1
fi

