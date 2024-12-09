# Stack

- it's fully async built upon [tokio](https://crates.io/crates/tokio) and [fuse3](https://crates.io/crates/fuse3)
- [ring](https://crates.io/crates/ring) for encryption and [argon2](https://crates.io/crates/argon2) for key derivation
  function (generating key from password used to encrypt the master encryption key)
- [rand_chacha](https://crates.io/crates/rand_chacha) for random generators
- [shush-rs](https://crates.io/crates/shush-rs) keeps pass and encryption keys safe in memory and zero them when
  not used. It keeps encryption keys in memory only while being used, and when not active, it will release and zeroing
  them in memory. It locks the memory page as well, preventing it from being written to swap.
- [blake3](https://crates.io/crates/blake3) for hashing
- password saved in OS keyring using [keyring](https://crates.io/crates/keyring)
- [tracing](https://crates.io/crates/tracing) for logs