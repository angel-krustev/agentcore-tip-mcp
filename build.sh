#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${PROJECT_DIR}/dist"

clean() {
    rm -rf "${DIST_DIR}" "${PROJECT_DIR}/build" "${PROJECT_DIR}/agentcore_tip_mcp.egg-info"
}

build_wheel() {
    cd "${PROJECT_DIR}"
    python -m pip install --upgrade build
    python -m build --wheel --outdir "${DIST_DIR}"
}

case "${1:-all}" in
    clean)
        clean
        ;;
    wheel)
        build_wheel
        ;;
    all)
        clean
        build_wheel
        ;;
    help|-h|--help)
        echo "Usage: ./build.sh [all|clean|wheel|help]"
        echo "Build a pure-Python wheel into dist/."
        ;;
    *)
        echo "Unknown command: $1" >&2
        echo "Usage: ./build.sh [all|clean|wheel|help]" >&2
        exit 2
        ;;
esac
