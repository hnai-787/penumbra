#!/usr/bin/env bash
# Configures and builds fwlint with CMake + MinGW g++, using the vcpkg
# instance at C:/vcpkg for nlohmann-json and Catch2 (see README.md
# "Building from source" for how those were installed).
set -euo pipefail

cd "$(dirname "$0")"

VCPKG_ROOT="${VCPKG_ROOT:-C:/vcpkg}"

cmake -S . -B build \
    -G "MinGW Makefiles" \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DVCPKG_HOST_TRIPLET=x64-mingw-static \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build --parallel

echo ""
echo "Built: build/fwlint.exe"
echo "Test binary: build/fwlint_tests.exe"
