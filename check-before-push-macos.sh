#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

cargo fmt --all

cargo build --all-targets --all-features
cargo build --release --all-targets --all-features
cargo clippy --release --all-targets --fix --allow-dirty
cargo fmt --all -- --check
cargo check --all
cargo clippy --all-targets --release -- \
    -A clippy::similar_names \
    -A clippy::too_many_arguments \
    -A clippy::significant_drop_tightening \
    -A clippy::redundant_closure \
    -A clippy::missing_errors_doc \
    -A clippy::type_complexity
cargo test --release --all --all-features
cargo doc --workspace --all-features --no-deps
cargo publish --dry-run --allow-dirty

cd java-bridge
cargo fmt --all
cargo build --all-targets --all-features
cargo build --release --all-targets --all-features
cargo clippy --release --all-targets --fix --allow-dirty
cargo fmt --all -- --check
cargo check --all
cargo clippy --all-targets --release -- \
    -A clippy::similar_names \
    -A clippy::too_many_arguments \
    -A clippy::significant_drop_tightening \
    -A clippy::redundant_closure \
    -A clippy::missing_errors_doc \
    -A clippy::type_complexity
cargo test --release --all --all-features
cargo doc --workspace --all-features --no-deps
cd ..
