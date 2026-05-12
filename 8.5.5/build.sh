#!/bin/bash
set -e

cd "$(dirname "$0")"

build_if_missing() {
    local image=$1 dockerfile=$2
    if docker image inspect "$image" &>/dev/null; then
        echo "=== $image already exists, skipping ==="
    else
        echo "=== Building $image ==="
        docker build -t "$image" -f "$dockerfile" .
    fi
}

build_if_missing php-8.5.5-non-asan Dockerfile
build_if_missing php-8.5.5-asan Dockerfile.asan

echo ""
echo "Done. Images: php-8.5.5-non-asan, php-8.5.5-asan"
