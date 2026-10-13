#!/usr/bin/env bash
# Build the client, then run it against an environment's .env file.
#   ./run.sh staging     -> loads .env.staging
#   ./run.sh production  -> loads .env.production
#   ./run.sh             -> loads .env
# Real environment variables override values from the file.
set -euo pipefail
if [[ $# -ge 1 && -n "${1:-}" ]]; then
  export ENV="$1"
fi
go build -o oidc_oauth2_client .
exec ./oidc_oauth2_client
