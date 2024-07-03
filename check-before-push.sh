#!/bin/zsh

set -e

cargo build --all --all-features
cargo build --release --all --all-features
cargo fmt --all -- --check
cargo check --all
cargo clippy --all
cargo test --release --all --all-features
cargo publish --dry-run --allow-dirty
