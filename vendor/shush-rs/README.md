# shush-rs

[![crates.io](https://img.shields.io/crates/v/shush-rs.svg)](https://crates.io/crates/shush-rs)
[![Github](https://img.shields.io/badge/github-eyob94/shush-rs)](https://github.com/Eyob94/shush-rs)

A Rust crate designed to manage sensitive data securely by leveraging memory protection mechanisms. It extends the functionality of the [secrecy](https://crates.io/crates/secrecy) crate to provide enhanced security features using memory locking and protection techniques. Specifically, `shush-rs` ensures that secrets are kept safe from unauthorized access and are properly zeroized when no longer needed.

### Brief overview

- `mlock`: this is a system call that locks a specified range of memory into RAM, preventing it from being swapped out to disk.
- `mprotect`: is a system call that changes the access protections (read, write, execute) for a specified range of memory.

### Features

- Memory Locking: Uses mlock to lock the secret's memory page, preventing it from being swapped to disk.
- Memory Protection: Employs mprotect to initially set the memory page to non-readable/writable and then to readable/writable only when needed.
- Zeroization: Guarantees that secrets are securely zeroized before they are dropped, minimizing the risk of sensitive data lingering in memory.

### Key Components

- `SecretBox`: A secure container for sensitive data. It locks the memory of the contained secret and ensures it is zeroized on drop.
- `CloneableSecret`: A trait for secrets that can be cloned, while ensuring the original is zeroized after cloning.
- `ExposeSecret` and `ExposeSecretMut`: Traits that provide controlled access to secrets, allowing read-only or mutable access while maintaining security.

### Usage

```rust
fn protect_secret(){

  let secret = Box::new(String::from("Encrypted"));

  let mut secret_box = SecretBox::new(secret); // Secret's memory page is mlocked

  println!("Secret: {:?}", secret_box); // Prints "Secret: SecretBox<alloc::string::String>([REDACTED])"

  let exposed_secret = secret_box.expose_secret();

  println!("Exposed Secret:{:?}", exposed_secret); // Prints "ExposedSecret: SecretGuardMut { data: "Encrypted" }"
} // Memory page is munlocked when it's dropped

```
The rencfs tree carries a small local patch to this upstream crate. See PATCHES.md for the Windows page-lock reference counting fix.
