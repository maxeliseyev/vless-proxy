#!/usr/bin/env bash
# Build RatatoskCore.xcframework (the vproxy core as a static library plus
# crates/ffi/include/ratatosk.h) for iPhone and the Apple Silicon simulator.
#
#   scripts/build-xcframework.sh [output dir]   # default: target/RatatoskCore.xcframework
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-target/RatatoskCore.xcframework}"
# C code (aws-lc) is compiled for this iOS version; keep it at or below the
# app's deployment target.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

targets=(aarch64-apple-ios aarch64-apple-ios-sim)
rustup target add "${targets[@]}" >/dev/null
args=()
for target in "${targets[@]}"; do
    cargo build -p vproxy-ffi --profile ios --target "$target"
    args+=(-library "target/$target/ios/libvproxy_ffi.a" -headers crates/ffi/include)
done

rm -rf "$out"
xcodebuild -create-xcframework "${args[@]}" -output "$out" >/dev/null
echo "$out"
du -sh "$out" | cut -f1
