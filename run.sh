#!/usr/bin/env bash
# Run the client against an environment's .env file.
#   ./run.sh staging     -> loads .env.staging
#   ./run.sh production  -> loads .env.production
#   ./run.sh             -> loads .env
# Real environment variables override values from the file.
set -euo pipefail
if [[ $# -ge 1 && -n "${1:-}" ]]; then
  export ENV="$1"
fi
exec go run .
