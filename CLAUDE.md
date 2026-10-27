# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Detailed per-module guides live in `docs/claude/` — read the linked file when working in that area (they are plain links, not auto-loaded imports):

- [docs/claude/crypto.md](docs/claude/crypto.md) — ciphers, block-based encrypted streams, key derivation, hashing
- [docs/claude/encryptedfs.md](docs/claude/encryptedfs.md) — `EncryptedFs` core, data-dir layout, key management, caching/locking
- [docs/claude/mount.md](docs/claude/mount.md) — Linux FUSE and Windows WinFsp adapters and the platform-independent mount API
- [docs/readme/Windows.md](docs/readme/Windows.md) — native WinFsp setup, supported scope and validation
- [docs/claude/cli.md](docs/claude/cli.md) — binary entry point, clap CLI, password/keyring flow, logging
- [docs/claude/testing.md](docs/claude/testing.md) — test/bench layout, pre-push script, CI
- [java-bridge/CLAUDE.md](java-bridge/CLAUDE.md) — JNI bindings crate (auto-loaded when working in `java-bridge/`)

## Project Overview

**rencfs** is an encrypted filesystem written in Rust that mounts with FUSE on Linux and has an initial native WinFsp backend on Windows. It creates encrypted directories that can be safely backed up to untrusted servers or cloud storage. **Under active development — not audited, not recommended for sensitive production data.**

Key differentiators: fast seek on reads and writes (256 KB encrypted blocks), parallel writes to the same file, memory-safe key handling (`shush-rs`: mlock/mprotect/zeroize), full metadata + filename encryption, and a modular design usable as a library without FUSE.

Platform support: Linux uses FUSE. Windows has an initial native WinFsp backend;
see `docs/readme/Windows.md` and `WINDOWS_VALIDATION.md` for its limitations and
required native validation. Other platforms retain a dummy mount backend.

## Common Development Commands

The toolchain is **nightly** (`rust-toolchain.toml`); the crate uses nightly features (`#![feature(test)]`, `error_generic_member_access`, `seek_stream_len`). Release profile uses `panic = "abort"`, LTO, and `-Dwarnings`.

### Build / check / format / lint
- `cargo build` / `cargo build --release`
- `cargo build --all-targets --all-features`
- `cargo check --all`
- `cargo fmt --all` (check only: `cargo fmt --all -- --check`)
- `cargo clippy --all-targets --release`

### Test / bench / docs
- `cargo test --release --all --all-features`
- `cargo bench --workspace --all-targets --all-features -j 14`
- `cargo doc --workspace --all-features --no-deps`

### Before committing
```bash
./scripts/check-before-push.sh
```
zsh script; runs fmt, builds, clippy, tests, benches, and docs for the root crate **and** `java-bridge/`, plus `cargo aur` and `cargo generate-rpm` (those plugins must be installed). Details in [docs/claude/testing.md](docs/claude/testing.md).

### Running the application
- `cargo run --release -- mount --mount-point MOUNT_POINT --data-dir DATA_DIR`
- `RENCFS_PASSWORD=password cargo run --release -- mount -m MOUNT_POINT -d DATA_DIR` (dev only)
- `cargo run --release -- --log-level DEBUG mount -m MOUNT_POINT -d DATA_DIR`
- `cargo run --release -- passwd --data-dir DATA_DIR` — change password

Mount flags: `-u/--umount-on-start`, `-s/--allow-root`, `-o/--allow-other`, `-r/--read-only`.

### Docker
- Published image: `xorio42/rencfs` on Docker Hub
- `docker/Dockerfile` — Alpine/musl multi-stage build; `Dockerfile_from_scratch` — minimal `FROM scratch` runtime; `Dockerfile-deb` — Debian package build
- Containers need `--device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined`

## Code Architecture

### Technology stack
Tokio (async runtime) · fuse3 (FUSE, Linux-only dep) · ring (AEAD) · argon2 (KDF) · blake3 (hashing) · rand_chacha (RNG) · shush-rs (secret memory safety) · keyring (OS keyring) · clap (CLI) · tracing (logging) · bincode/serde (inode serialization) · bon (builders)

### Module map

| Path | Role | Guide |
|---|---|---|
| `src/lib.rs` | Library root with extensive rustdoc usage examples; exports `UID`/`GID`/`is_debug` | — |
| `src/crypto.rs` + `src/crypto/` | Ciphers, encrypted read/write streams, KDF, hashing | [crypto.md](docs/claude/crypto.md) |
| `src/encryptedfs.rs` + `src/encryptedfs/` | Core `EncryptedFs` (inode-based, FUSE-independent) | [encryptedfs.md](docs/claude/encryptedfs.md) |
| `src/mount.rs` + `src/mount/` | Mount API; `linux.rs` (fuse3), `windows.rs` (WinFsp), `dummy.rs` (other OS) | [mount.md](docs/claude/mount.md), [Windows.md](docs/readme/Windows.md) |
| `src/main.rs`, `src/run.rs`, `src/keyring.rs` | Binary only (not in the library): platform gate, CLI, OS keyring | [cli.md](docs/claude/cli.md) |
| `src/log.rs` | tracing init (`log_init` returns a guard that must be kept alive) | [cli.md](docs/claude/cli.md) |
| `java-bridge/` | Separate cdylib crate with JNI bindings | [java-bridge/CLAUDE.md](java-bridge/CLAUDE.md) |

Support modules (small, library-public): `arc_hashmap.rs` (ref-counted concurrent map used for per-inode locks), `expire_value.rs` (auto-expiring cached value behind a `ValueProvider`, used for the master key and caches), `stream_util.rs` (buffered copy/seek helpers), `fs_util.rs` (atomic writes, recursive dir move), `async_util.rs` (`call_async` sync→async bridge), `test_common.rs` (crate-private test helpers).

`examples/` contains runnable examples (mount, encryptedfs, crypto read/write, password change, WAL experiment).

### Functional design

- Encrypted data dir: `inodes/` (encrypted attrs), `contents/` (block-encrypted content; per-directory `ls/` + `hash/` entry indexes), `security/` (`key.enc` master key + `key.salt`). Root inode = 1.
- Master key is encrypted with an Argon2 password-derived key; changing the password only re-encrypts the master key. The in-memory key expires after 10 min of inactivity.
- Content is encrypted in 256 KB blocks (**100 bytes in `#[cfg(test)]` builds**) → fast seek and parallel writes.
- Only `Directory` and `RegularFile` file types are implemented (no symlinks yet).
- WAL crash recovery is **not integrated** — `okaywal` is only exercised in `examples/wal.rs` (WIP).

### Supported ciphers
- `ChaCha20Poly1305` (default) — constant-time software implementation, SIMD-friendly
- `Aes256Gcm` — faster where AES-NI hardware acceleration is available

Both 256-bit keys, 96-bit nonces.

## Testing

See [docs/claude/testing.md](docs/claude/testing.md) for the full layout. Quick orientation: unit tests in `src/crypto/{read,write}/test.rs` and `src/encryptedfs/test.rs`; Linux FUSE integration tests in `tests/rencfs_linux_itest.rs` (helpers in `tests/linux_mount_setup/`); Python end-to-end file-operation tests in `tests/python/`; benches in `benches/crypto_read.rs`, `src/crypto/write/bench.rs`, `src/encryptedfs/bench.rs`. Test-environment setup: `docs/readme/Testing.md`.

## Security Considerations

- Audited primitives (`ring`), AEAD ciphers, Argon2 KDF; secrets held in `shush_rs` types (mlock/mprotect/zeroize) and dropped after inactivity.
- Filenames, sizes, and metadata are encrypted.
- **Warnings:** no security audit yet; phantom reads possible in crash scenarios (WAL is WIP); recommend disk encryption underneath and disabling OS memory dumps.
- More detail: `docs/readme/Security.md`, `docs/readme/Considerations.md`.

## Human-facing docs

- `docs/readme/` — README sub-pages (Usage, Build_from_Source, Key_features, Cipher_comparison, Alternatives, ...)
- `docs/uml/` — sequence diagrams: `overview.md`, `mount.md`, `cli_usage.md`, `lib_rencfs_usage.md`, `lib_encryptedfs_usage.md`, `create_file.md`, `open_file.md`, `close_file.md`, `read.md`, `write.md`, `search_file.md`, `change_pass.md`
