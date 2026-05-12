#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PHP="/php-src/sapi/cli/php"
IMAGE="php-7.2.1-non-asan"
DOCKERFILE_DIR="$(dirname "$SCRIPT_DIR")"

if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Image $IMAGE not found. Building..."
    docker build -t "$IMAGE" -f "$DOCKERFILE_DIR/Dockerfile" "$DOCKERFILE_DIR"
fi

docker run --rm -v "$SCRIPT_DIR:/work" "$IMAGE" $PHP /work/exp/exploit.php 2>&1 || true
