#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=== Building php-8.5.5-non-asan ==="
docker build -t php-8.5.5-non-asan -f Dockerfile .

echo ""
echo "=== Building php-8.5.5-asan ==="
docker build -t php-8.5.5-asan -f Dockerfile.asan .

echo ""
echo "Done. Images: php-8.5.5-non-asan, php-8.5.5-asan"
