# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rencfs** is an encrypted file system written in Rust that mounts with FUSE on Linux. It creates encrypted directories that can be safely backed up to untrusted servers or cloud storage services. The project is currently in active development and supports Linux only.

## Common Development Commands

### Building
- `cargo build` - Build for debug
- `cargo build --release` - Build for release
- `cargo build --all-targets --all-features` - Build all targets with all features

### Testing
- `cargo test --release --all --all-features` - Run all tests
- `cargo test --release` - Run tests in release mode
- `cargo bench --workspace --all-targets --all-features -j 14` - Run benchmarks

### Code Quality
- `cargo fmt --all` - Format code
- `cargo fmt --all -- --check` - Check formatting
- `cargo clippy --all-targets --release` - Run clippy linter
- `cargo check --all` - Check compilation

### Development Workflow
Use the comprehensive check script before committing:
```bash
./scripts/check-before-push.sh
```

This script runs formatting, building, linting, testing, and documentation generation.

### Documentation
- `cargo doc --workspace --all-features --no-deps` - Generate documentation

### Running the Application
- `cargo run --release -- mount --mount-point MOUNT_POINT --data-dir DATA_DIR`
- `RENCFS_PASSWORD=password cargo run --release -- mount -m MOUNT_POINT -d DATA_DIR` (dev mode)
- `cargo run --release -- --log-level DEBUG mount -m MOUNT_POINT -d DATA_DIR` (with debug logging)

## Code Architecture

### Core Components

- **src/encryptedfs.rs** - Main encrypted filesystem implementation (`EncryptedFs`)
- **src/crypto.rs** - Cryptographic operations and cipher implementations
- **src/mount.rs** - FUSE mounting functionality (Linux-specific)
- **src/main.rs** - CLI entry point (Linux-only, shows platform messages for others)
- **src/lib.rs** - Library API with comprehensive examples

### Key Modules

- **crypto/** - Encryption/decryption with read/write streams
- **encryptedfs/** - File system operations and metadata management
- **mount/** - FUSE integration and mount point management
- **keyring.rs** - OS keyring integration for password storage

### Supported Ciphers
- `ChaCha20Poly1305` (default)
- `Aes256Gcm` (hardware accelerated on most CPUs)

## Testing Strategy

### Unit Tests
Tests are located in:
- `src/crypto/read/test.rs`
- `src/crypto/write/test.rs`
- `src/encryptedfs/test.rs`
- `src/test_common.rs`

### Integration Tests
- `tests/rencfs_linux_itest.rs` - Linux-specific integration tests
- `tests/python/` - Python integration test scripts

### Benchmarks
- `benches/crypto_read.rs` - Crypto performance benchmarks

## Development Environment

### Platform Support
- **Linux**: Full support with FUSE mounting
- **macOS/Windows**: CLI shows "not yet ready" message
- **Other platforms**: Shows "not supported" message

### Dependencies
- FUSE3 required for Linux mounting functionality
- Ring crate for cryptographic primitives
- Tokio for async runtime
- Clap for CLI argument parsing

### Configuration Files
- `clippy.toml` - Clippy linting configuration
- `rust-toolchain.toml` - Rust toolchain specification
- `.devcontainer/` - Container development setup

## Security Considerations

This is a cryptographic filesystem with these security features:
- Uses audited cryptographic primitives from the `ring` crate
- Memory safety through `mlock(2)` and `zeroize`
- AEAD (Authenticated Encryption with Associated Data) ciphers
- Password-derived encryption keys using Argon2
- OS keyring integration for password storage

**Warning**: The project is under active development and hasn't been audited. Not recommended for sensitive data in production.

## Java Bridge

The `java-bridge/` directory contains JNI bindings for Java integration. It has its own Cargo.toml and follows similar build patterns.