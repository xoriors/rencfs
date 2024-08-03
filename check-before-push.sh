#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

cargo fmt --all
cargo build --all --all-features --target x86_64-unknown-linux-gnu
cargo build --release --all --all-features --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo check --all --target x86_64-unknown-linux-gnu
cargo clippy --all --target x86_64-unknown-linux-gnu
cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
cargo doc --workspace --all-features --target x86_64-unknown-linux-gnu
cd examples
cargo doc --workspace --all-features --target x86_64-unknown-linux-gnu
cd ..
cd java-bridge
make
cd ..
cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
cargo aur
cargo generate-rpm
