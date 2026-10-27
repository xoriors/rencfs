# CLI (binary) — main.rs, run.rs, keyring.rs, log.rs

Files: `src/main.rs` (entry + platform gate), `src/run.rs` (clap CLI and mount/passwd flows), `src/keyring.rs` (OS keyring), `src/log.rs` (tracing setup)

`keyring` and `run` are **binary-only modules** declared in `main.rs` — they are not part of the library (`src/lib.rs`). `log` is a library module.

## Platform gate (`main.rs`)

- Linux/Windows → `run::run()`
- macOS → prints "not yet ready for this platform" and exits
- anything else → prints "not supported" and exits

## CLI shape (`run.rs::get_cli_args`)

Global flags:
- `--log-level` / `-l` (default `INFO`; TRACE/DEBUG/INFO/WARN/ERROR)
- `--cipher` / `-c` (default `ChaCha20Poly1305`; values from `Cipher` enum)

Subcommands:
- `mount` — flags: `--mount-point`/`-m` (required), `--data-dir`/`-d` (required), `--umount-on-start`/`-u`, `--allow-root`/`-s`, `--allow-other`/`-o`, `--read-only`/`-r`
- `passwd` — flag: `--data-dir`/`-d` (required); re-encrypts the master key with a new password

The subcommand name appears in two places that must stay in sync: the definition in `get_cli_args` and the string match in `async_main`. The compiler can't catch a mismatch (both are strings) — `tests/cli_passwd_itest.rs` guards this for `passwd`.

## Password flow (`run_mount`)

1. `RENCFS_PASSWORD` env var, if set (dev convenience — do not document as production usage).
2. Otherwise prompt on stdin (`rpassword`); on first run (empty/missing data dir) asks for confirmation.
3. Password is saved to the OS keyring (`keyring.rs`: service `"rencfs"`, user `"rencfs.<suffix>"`, suffix `password`); if no keyring is available it falls back to a mutex-protected secret in memory.
4. `PasswordProvider` given to the mount reads it back from keyring (or memory) on demand — the `EncryptedFs` key itself expires after 10 min of inactivity (see [encryptedfs.md](encryptedfs.md)).
5. A `ctrlc` handler sends a stop request. The owning runtime awaits unmount,
   removes the password, and returns. Unexpected host termination also ends the CLI.

## Logging (`log.rs`)

`log_init(level)` configures `tracing-subscriber` with an env-filter directive `rencfs=<level>` and a non-blocking appender; it returns a `WorkerGuard` that must be kept alive (and dropped before `process::exit`) to flush logs.

## Flow diagrams

`docs/uml/cli_usage.md`, `docs/uml/change_pass.md`.
