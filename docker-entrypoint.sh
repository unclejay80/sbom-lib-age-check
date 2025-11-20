#!/usr/bin/env bash
set -euo pipefail

# Simple entrypoint to run sbom-check inside the container.
# Usage examples:
#  docker run --rm -v $(pwd):/work -w /work sbom-check:latest python3 sbom-check.py --sbom sbom.json --age 90 --check-updates --cache-file .sbom-check-cache.json

if [ "$#" -eq 0 ]; then
  echo "No arguments provided. Example usage:"
  echo "  python3 sbom-check.py --sbom sbom.json --age 90 --check-updates --cache-file .sbom-check-cache.json"
  exit 1
fi

exec "$@"
