#!/bin/bash
# Run exploit for var_destroy UAF (non-ASAN build)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PHP="/php-src/sapi/cli/php"
IMAGE="php-8.5.5-non-asan"
DOCKERFILE_DIR="$(dirname "$SCRIPT_DIR")"

if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Image $IMAGE not found. Building..."
    docker build -t "$IMAGE" -f "$DOCKERFILE_DIR/Dockerfile" "$DOCKERFILE_DIR"
fi

docker run --rm -v "$SCRIPT_DIR:/work" "$IMAGE" $PHP /work/exp/exploit.php 2>&1 || true
