# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rencfs** is an encrypted file system written in Rust that mounts with FUSE on Linux. It creates encrypted directories that can be safely backed up to untrusted servers or cloud storage services. The project is currently in active development and supports Linux only.

**Key differentiators**: Fast seek operations, parallel writes, memory-safe encryption key handling, modular design for library usage, and comprehensive security features including metadata encryption.

## Common Development Commands

### Building
- `cargo build` - Build for debug
- `cargo build --release` - Build for release
- `cargo build --all-targets --all-features` - Build all targets with all features

### Testing
- `cargo test --release --all --all-features` - Run all tests
- `cargo test --release` - Run tests in release mode
- `cargo bench --workspace --all-targets --all-features -j 14` - Run benchmarks
- **Python Integration Tests**: Use `tests/python/` for comprehensive file operation testing

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

This script runs formatting, building, linting, testing, benchmarking, and documentation generation for both main project and java-bridge.

### Documentation
- `cargo doc --workspace --all-features --no-deps` - Generate documentation

### Running the Application
- `cargo run --release -- mount --mount-point MOUNT_POINT --data-dir DATA_DIR`
- `RENCFS_PASSWORD=password cargo run --release -- mount -m MOUNT_POINT -d DATA_DIR` (dev mode)
- `cargo run --release -- --log-level DEBUG mount -m MOUNT_POINT -d DATA_DIR` (with debug logging)
- `cargo run --release -- passwd --data-dir DATA_DIR` - Change password

### Docker Usage
- **Quick try**: `docker pull xorio42/rencfs`
- **Development**: Use provided Dockerfiles for Alpine-based builds
- **Container setup**: Requires `--device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined`

## Code Architecture

### Technology Stack
- **Async Runtime**: Built on Tokio and fuse3 crate
- **Cryptography**: Ring crate for AEAD encryption, Argon2 for key derivation
- **Random Generation**: rand_chacha for secure randomness
- **Memory Safety**: shush-rs for secure key handling with mlock/mprotect/zeroize
- **Hashing**: Blake3 for fast cryptographic hashing
- **Password Storage**: OS keyring integration
- **Logging**: Tracing crate for structured logging

### Core Components

- **src/encryptedfs.rs** - Main encrypted filesystem implementation (`EncryptedFs`)
- **src/crypto.rs** - Cryptographic operations and cipher implementations
- **src/mount.rs** - FUSE mounting functionality (Linux-specific)
- **src/main.rs** - CLI entry point (Linux-only, shows platform messages for others)
- **src/lib.rs** - Library API with comprehensive examples

### Key Modules

- **crypto/** - Encryption/decryption with read/write streams supporting chunked operations
- **encryptedfs/** - File system operations and metadata management with inode-based structure
- **mount/** - FUSE integration and mount point management (Linux + dummy implementations)
- **keyring.rs** - OS keyring integration for password storage
- **async_util.rs** - Async utilities and helpers
- **fs_util.rs** - Filesystem utility functions
- **stream_util.rs** - Stream processing utilities
- **expire_value.rs** - Time-based value expiration for security

### Functional Design

**Data Storage Structure:**
- Encrypted data stored in dedicated directory with inode-based file structure
- All metadata, content, and filenames encrypted
- Master encryption key encrypted with password-derived key
- 256KB chunks for efficient seeking and parallel operations

**Security Features:**
- Password stored in OS keyring, cleared from memory on inactivity
- Encryption keys are mlock'd, mprotect'd, and zeroized when not in use
- Fast seek operations for instant video/media playback
- Multiple parallel writes to same file supported
- WAL (Write-Ahead Logging) for crash recovery [WIP]

**File Operations:**
- Fast seek on both reads and writes
- Chunk-based encryption (256KB chunks)
- Parallel write operations
- Instant file positioning for media files

### Supported Ciphers
- `ChaCha20Poly1305` (default) - Better for SIMD, constant-time software implementation
- `Aes256Gcm` - Hardware accelerated on most CPUs via AES-NI (1.28x faster when accelerated)

**Cipher Selection Guidelines:**
- Use AES-GCM with hardware acceleration for performance
- Use ChaCha20-Poly1305 for constant-time security without hardware acceleration
- Both are 256-bit security level with 96-bit nonces

## Testing Strategy

### Unit Tests
Tests are located in:
- `src/crypto/read/test.rs` - Crypto read operations
- `src/crypto/write/test.rs` - Crypto write operations  
- `src/encryptedfs/test.rs` - Filesystem operations
- `src/test_common.rs` - Shared testing utilities

### Integration Tests
- `tests/rencfs_linux_itest.rs` - Linux-specific integration tests
- `tests/python/` - Python integration test scripts for comprehensive file operations
  - File copying, moving, renaming operations
  - Video/image/document file integrity verification
  - Multi-format file handling tests

### Benchmarks
- `benches/crypto_read.rs` - Crypto performance benchmarks

### Testing Environment Setup
For comprehensive testing, use the provided test infrastructure:
- VSCode/Codespace testing setup documented in `docs/readme/Testing.md`
- Python test environment with pytest
- Container-based testing with FUSE support

## Sequence Flow Documentation

The project includes comprehensive UML sequence diagrams in `docs/uml/`:
- **mount.md** - FUSE mounting process flow
- **cli_usage.md** - CLI workflow patterns
- **lib_rencfs_usage.md** - Library usage patterns
- **create_file.md**, **open_file.md**, **read.md**, **write.md** - File operation flows
- **change_pass.md** - Password change workflow
- **overview.md** - Complete system architecture diagram

## Development Environment

### Platform Support
- **Linux**: Full support with FUSE mounting
- **macOS/Windows**: CLI shows "not yet ready" message
- **Other platforms**: Shows "not supported" message

### Dependencies
- **FUSE3** required for Linux mounting functionality
- **Ring crate** for cryptographic primitives
- **Tokio** for async runtime
- **Clap** for CLI argument parsing
- **Build tools**: Standard Rust toolchain + platform-specific FUSE libraries

### Configuration Files
- `clippy.toml` - Clippy linting configuration with comprehensive rules
- `rust-toolchain.toml` - Rust toolchain specification (nightly)
- `.devcontainer/` - Container development setup

## Security Considerations

This is a cryptographic filesystem with these security features:
- Uses audited cryptographic primitives from the `ring` crate
- Memory safety through `mlock(2)`, `mprotect`, and `zeroize`
- AEAD (Authenticated Encryption with Associated Data) ciphers
- Password-derived encryption keys using Argon2
- OS keyring integration for password storage
- Metadata encryption (filenames, sizes, timestamps, file counts)
- Cold boot attack mitigation through key memory management

**Security Warnings:**
- Project hasn't been security audited
- Not recommended for sensitive production data
- Phantom reads possible during crash scenarios
- Recommend encrypted disk storage as additional layer
- Disable OS-level memory dumps for enhanced security

**Memory Protection:**
- Encryption keys kept in memory only when needed
- Automatic key zeroing after inactivity period
- Memory locking prevents swap writes
- Memory protection when keys not in use

## Alternatives and Context

**Key Alternatives:** Cryptomator, gocryptfs, VeraCrypt, EncFS, CryFS, fscrypt, LUKS

**Unique Features:** Fast seek operations, parallel writes, memory-safe key handling, modular library design, comprehensive metadata encryption, and Rust memory safety.

## Java Bridge

The `java-bridge/` directory contains JNI bindings for Java integration. It has its own Cargo.toml and follows similar build patterns with the same quality checks.

## Container Development

Docker support includes:
- **Dockerfile** - Debian-based build for development
- **Dockerfile-deb** - Debian package build
- **Dockerfile_from_scratch** - Minimal Alpine-based runtime
- Published image: `xorio42/rencfs` on Docker Hub