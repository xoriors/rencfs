# Local patch

This is `shush-rs` 0.1.11, licensed under MIT OR Apache-2.0. The local Windows-only patch reference-counts locked pages because Windows locks and unlocks whole pages. Multiple secret boxes can share one allocator page; unlocking once per box would otherwise unlock live secrets and make later drops panic with `ERROR_NOT_LOCKED`.

The upstream crate source and release history are at https://github.com/Eyob94/shush-rs. Unix behavior is unchanged.
