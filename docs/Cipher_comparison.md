# Cipher comparison

## AES-GCM vs. ChaCha20-Poly1305

- If you have hardware acceleration (e.g. `AES-NI`), then `AES-GCM` provides better performance. On my benchmarks, it was
  faster by a factor of **1.28** on average.  
  If you do not have hardware acceleration, `AES-GCM` is either slower than `ChaCha20-Poly1305`, or it leaks your
  encryption
  keys in cache timing.
- `AES-GCM` can target multiple security levels (`128-bit`, `192-bit`, `256-bit`), whereas `ChaCha20-Poly1305` is only defined at
  the `256-bit` security level.
- Nonce size:
    - `AES-GCM`: Varies, but the standard is `96-bit` (`12 bytes`).
      If you supply a longer nonce, this gets hashed down to `16 bytes`.
    - `ChaCha20-Poly1305`: The standardized version uses `96-bit` nonce (`12 bytes`), but the original used `64-bit`
      nonce (`8 bytes`).
- Wear-out of a single (key, nonce) pair:
    - `AES-GCM`: Messages must be less than `2^32 – 2` blocks (a.k.a. `2^36 – 32 bytes`, a.k.a. `2^39 – 256-bit`), that's
      roughly `64GB`.
      This also makes the security analysis of `AES-GCM` with long nonces complicated since the hashed nonce doesn’t
      start
      with the lower `4 bytes` set to `00 00 00 02`.
    - `ChaCha20-Poly1305`: `ChaCha` has an internal counter (`32-bit` in the standardized IETF variant, `64-bit` in the
      original design). Max message length is `2^39 - 256-bit`, about `256GB`
- Neither algorithm is **nonce misuse-resistant**.
- `ChaChaPoly1305` is better at `SIMD`

### Conclusion

Both are good options. `AES-GCM` can be faster with **hardware support**, but **pure-software** implementations of
`ChaCha20-Poly1305` are almost always **fast** and **constant-time**.