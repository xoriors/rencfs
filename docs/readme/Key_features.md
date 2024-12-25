## Key features

Some of these are still being worked on and marked with `[WIP]`.
- `Security` using well-known audited `AEAD` cryptography primitives;
- [WIP] [Data integrity, data is written with WAL to ensure integrity even on crash or power loss](https://github.com/radumarias/rencfs/issues/48)
- [WIP] [Hide all info for enhanced privacy; all metadata, content, file name, file size, *time fields, files count, and directory structure is encrypted](https://github.com/radumarias/rencfs/issues/53)
- `Safely` manage `credentials` in memory with `mlock(2)`, `mprotect`, `zeroize`, and `expiry` to mitigate cold boot attacks;
- `Memory safety`, `performance`, and `optimized` for `concurrency` with Rust;
- Simplicity;
- Encryption key generated from password;
- Password saved in OS's `keyring`;
- `Change password` without re-encrypting all data;
- [WIP] [Generate unique nonce in offline mode](https://github.com/radumarias/rencfs/issues/47)
- [WIP] [Add file inode and chunk index to AAD](https://github.com/radumarias/rencfs/issues/49) This prevents blocks from being copied between or within files by an attacker.
- `Fast seek` on both reads and writes;
- `Writes in parallel`;
- Exposed with `FUSE`;
- Fully `concurrent` for all operations;
- [WIP] [Handle long file names](https://github.com/radumarias/rencfs/issues/47)
- [WIP] [Abstraction layer for Rust File and fs API to use it as lib to switch to using encrypted files by just changing the use statements](https://github.com/radumarias/rencfs/issues/97)
- [WIP] [Abstraction layer to access the storage with implementations for desktop, Wasm, Android, and iOS and the ability to write your own implementation](https://github.com/radumarias/rencfs/issues/111)