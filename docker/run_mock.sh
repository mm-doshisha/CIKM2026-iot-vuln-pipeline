#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CVE_ID="${1:-CVE-2024-3273}"
SPEC_FILE="$PROJECT_ROOT/benchmarks/specs/$CVE_ID.json"

if [ ! -f "$SPEC_FILE" ]; then
    echo "Error: Spec file not found: $SPEC_FILE"
    exit 1
fi

docker build -t iot-mock -f "$SCRIPT_DIR/Dockerfile.mock" "$PROJECT_ROOT"

docker rm -f iot-mock-container 2>/dev/null || true

docker run -d \
    --name iot-mock-container \
    -p 8080:8080 \
    -v "$SPEC_FILE:/app/spec.json:ro" \
    iot-mock

echo "Mock service started for $CVE_ID on http://localhost:8080"
echo "To stop: docker rm -f iot-mock-container"
