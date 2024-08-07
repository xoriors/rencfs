#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

cargo fmt --all
cargo clippy --release --all-targets --fix --allow-dirty --target x86_64-unknown-linux-gnu

cargo build --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo build --release --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo check --all --target x86_64-unknown-linux-gnu
cargo clippy --all --release --default deny --allow similar_names --allow too_many_arguments --allow significant_drop_tightening --allow redundant_closure --allow missing_errors_doc --allow missing_panics_doc --target x86_64-unknown-linux-gnu
cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
cargo aur
cargo generate-rpm

cd java-bridge
cargo fmt --all
cargo clippy --release --all-targets --fix --allow-dirty
cargo build --release --all --all-features --target x86_64-unknown-linux-gnu
cargo clippy --all --release --default deny --allow similar_names --allow too_many_arguments --allow significant_drop_tightening --allow redundant_closure --allow missing_errors_doc --allow missing_panics_doc --target x86_64-unknown-linux-gnu
cargo fmt --all -- --check
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
cd ..
