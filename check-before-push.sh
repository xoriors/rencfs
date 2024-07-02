#!/bin/zsh

set -e

cargo build --all
cargo fmt --check --all
cargo check --all
cargo clippy --all
cargo test --all --all-features --release
