# rencfs Python bindings

Python bindings for [`EncryptedFs`](../src/encryptedfs.rs), built with [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs).

## Build and test

```bash
cd rencfs-python
python3 -m venv .venv
source .venv/bin/activate
pip install maturin pytest
maturin develop        # builds the extension and installs it in the venv
pytest tests
```

## Usage

```python
from rencfs import EncryptedFs, Cipher, CreateFileAttr, FileType

fs = EncryptedFs("/path/to/data_dir", "password", Cipher.ChaCha20Poly1305, False)

# the root directory has inode 1
handle, attr = fs.create(1, "hello.txt", CreateFileAttr(FileType.RegularFile, 0o644, 1000, 1000), False, True)
fs.write(attr.ino, 0, b"hello", handle)
fs.flush(handle)
fs.release(handle)

handle = fs.open(attr.ino, True, False)
assert fs.read(attr.ino, 0, 100, handle) == b"hello"
fs.release(handle)
```

Notes:

- `create()` returns `(handle, attr)`. The inode is `attr.ino`. The handle is `0` for directories and for files created with `read=False, write=False`; any other handle must be passed to `release()`.
- A file can have only one write handle open at a time.
- Timestamps are seconds since the Unix epoch.
