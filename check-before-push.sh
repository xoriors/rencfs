#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

# Filepath to the Cargo.toml file
CARGO_FILE="Cargo.toml"
BACKUP_FILE="Cargo_backup.txt"

# Function to add -dryRun to the version
add_dryrun_to_version() {
    if [[ -f $CARGO_FILE ]]; then
        # Backup the original Cargo.toml before modification
        cp "$CARGO_FILE" "$BACKUP_FILE"
        
        # Extract the current version from the file
        ORIGINAL_VERSION=$(grep -oP '^version\s*=\s*"\K[^\"]+' "$CARGO_FILE")

        if [[ -n $ORIGINAL_VERSION ]]; then
            # Modify the version and write it back to the Cargo.toml file
            sed -i "s/version = \"$ORIGINAL_VERSION\"/version = \"$ORIGINAL_VERSION-dryRun\"/" "$CARGO_FILE"
            echo "Version modified to: $ORIGINAL_VERSION-dryRun"
        else
            echo "No version found in the file."
        fi
    else
        echo "Cargo.toml file not found!"
    fi
}

# Function to revert the version to its original state by restoring from backup
revert_version() {
    if [[ -f $BACKUP_FILE ]]; then
        # Restore the original Cargo.toml from the backup
        mv "$BACKUP_FILE" "$CARGO_FILE"
        echo "Cargo.toml reverted to the original version."
    else
        echo "Backup file not found! Cannot revert."
    fi
}

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
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu

add_dryrun_to_version
cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
revert_version

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
cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
cd ..
