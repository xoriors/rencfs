#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

cargo fmt --all

cargo build --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo build --release --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo clippy --release --all-targets --fix --allow-dirty --allow-staged --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo check --all --target x86_64-unknown-linux-gnu
cargo clippy --all-targets --release --target x86_64-unknown-linux-gnu -- \
    -A clippy::similar_names \
    -A clippy::too_many_arguments \
    -A clippy::significant_drop_tightening \
    -A clippy::redundant_closure \
    -A clippy::missing_errors_doc \
    -A clippy::type_complexity
cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
# cargo bench --workspace --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu

# cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu

cargo aur
cargo generate-rpm

cd java-bridge
cargo fmt --all
cargo build --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo build --release --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo clippy --release --all-targets --fix --allow-dirty --allow-staged --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo check --all --target x86_64-unknown-linux-gnu
cargo clippy --all-targets --release --target x86_64-unknown-linux-gnu -- \
    -A clippy::similar_names \
    -A clippy::too_many_arguments \
    -A clippy::significant_drop_tightening \
    -A clippy::redundant_closure \
    -A clippy::missing_errors_doc \
    -A clippy::type_complexity
cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
# cargo bench --workspace --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
cd ..
