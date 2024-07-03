#!/bin/zsh

set -e

cargo build --all --all-features
cargo build --all --all-features --release
cargo fmt --all -- --check
cargo check --all
cargo clippy --all
cargo test --all --all-features --release
cargo publish --dry-run --allow-dirty
