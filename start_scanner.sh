#!/bin/bash
echo "🛡️ Starting Rust IoT Network Scanner Backend..."
cd "$(dirname "$0")/rust_scanner" || exit 1
if [ -f "./target/release/rust_scanner" ]; then
    ./target/release/rust_scanner
else
    cargo run --release
fi
