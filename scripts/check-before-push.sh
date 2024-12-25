#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"
export RUST_TEST_THREADS=14
export CARGO_BUILD_JOBS=14

cargo fmt --all

cargo build --all-targets --all-features
cargo build --release --all-targets --all-features
cargo clippy --release --all-targets --fix --allow-dirty --allow-staged
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
cargo bench --workspace --all-targets --all-features -j 14
cargo doc --workspace --all-features --no-deps

# cargo publish --dry-run --allow-dirty

cargo aur
cargo generate-rpm

cd java-bridge
cargo fmt --all
cargo build --all-targets --all-features
cargo build --release --all-targets --all-features
cargo clippy --release --all-targets --fix --allow-dirty --allow-staged
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
cargo bench --workspace --all-targets --all-features -j 14
cargo doc --workspace --all-features --no-deps
cd ..
