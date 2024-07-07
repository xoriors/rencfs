#!/bin/zsh

set -e

cargo build --workspace --all-targets --all-features
cargo build --release --workspace --all-targets --all-features
cargo fmt --workspace -- --check
cargo check --workspace
cargo clippy --all-targets
cargo test --release --all --all-features
cargo publish --dry-run --allow-dirty
