#!/bin/zsh

set -e

cargo build --all --all-features --target x86_64-unknown-linux-gnu
cargo build --release --all --all-features --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo check --all --target x86_64-unknown-linux-gnu
cargo clippy --all --target x86_64-unknown-linux-gnu
cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
cargo aur
cargo generate-rpm
