use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use shush_rs::{ExposeSecret, SecretString};
use tokio::runtime::Runtime;

use crate::types::{
    Cipher, CreateFileAttr, DirEntry, DirEntryPlus, FileAttr, PyFsError, SetFileAttr,
};
use rencfs::encryptedfs::{
    CopyFileRangeReq, EncryptedFs as RustEncryptedFs, FsResult, PasswordProvider,
};

/// One runtime shared by all `EncryptedFs` instances, same approach as `java-bridge`.
static RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("cannot create tokio runtime")
});

/// Runs `fut` to completion on the shared runtime with the GIL released,
/// so other Python threads keep running while we do crypto and I/O.
fn run<T, F>(py: Python<'_>, fut: F) -> PyResult<T>
where
    T: Send,
    F: Future<Output = FsResult<T>> + Send,
{
    py.detach(|| RT.block_on(fut))
        .map_err(|err| PyFsError(err).into())
}

fn secret(value: String) -> SecretString {
    SecretString::new(Box::new(value))
}

struct PyPasswordProvider {
    password: SecretString,
}

impl PasswordProvider for PyPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        Some(self.password.clone())
    }
}

#[pyclass(module = "rencfs")]
pub struct EncryptedFs {
    inner: Arc<RustEncryptedFs>,
}

#[pymethods]
impl EncryptedFs {
    #[new]
    fn new(
        py: Python<'_>,
        data_dir: PathBuf,
        password: String,
        cipher: Cipher,
        read_only: bool,
    ) -> PyResult<Self> {
        let provider = Box::new(PyPasswordProvider {
            password: secret(password),
        });
        let inner = run(
            py,
            RustEncryptedFs::new(data_dir, provider, cipher.into(), read_only),
        )?;
        Ok(Self { inner })
    }

    fn exists(&self, ino: u64) -> bool {
        self.inner.exists(ino)
    }

    fn is_dir(&self, ino: u64) -> bool {
        self.inner.is_dir(ino)
    }

    fn is_file(&self, ino: u64) -> bool {
        self.inner.is_file(ino)
    }

    fn len(&self, ino: u64) -> PyResult<usize> {
        self.inner.len(ino).map_err(|err| PyFsError(err).into())
    }

    fn exists_by_name(&self, parent: u64, name: String) -> PyResult<bool> {
        self.inner
            .exists_by_name(parent, &secret(name))
            .map_err(|err| PyFsError(err).into())
    }

    fn find_by_name(
        &self,
        py: Python<'_>,
        parent: u64,
        name: String,
    ) -> PyResult<Option<FileAttr>> {
        let name = secret(name);
        let attr = run(py, self.inner.find_by_name(parent, &name))?;
        Ok(attr.map(Into::into))
    }

    fn get_attr(&self, py: Python<'_>, ino: u64) -> PyResult<FileAttr> {
        Ok(run(py, self.inner.get_attr(ino))?.into())
    }

    fn set_attr(&self, py: Python<'_>, ino: u64, attr: SetFileAttr) -> PyResult<()> {
        run(py, self.inner.set_attr(ino, attr.into_rust()))
    }

    /// Creates a file or directory. Returns `(handle, attr)`; the inode is `attr.ino`.
    /// `handle` is `0` for directories and for files created with `read=False, write=False`.
    /// A non-zero handle must be passed to `release()` when no longer needed.
    fn create(
        &self,
        py: Python<'_>,
        parent: u64,
        name: String,
        attr: CreateFileAttr,
        read: bool,
        write: bool,
    ) -> PyResult<(u64, FileAttr)> {
        let name = secret(name);
        let (handle, attr) = run(
            py,
            self.inner.create(parent, &name, attr.into(), read, write),
        )?;
        Ok((handle, attr.into()))
    }

    fn open(&self, py: Python<'_>, ino: u64, read: bool, write: bool) -> PyResult<u64> {
        run(py, self.inner.open(ino, read, write))
    }

    /// Reads up to `size` bytes starting at `offset`. Returns fewer bytes at end of file.
    fn read<'py>(
        &self,
        py: Python<'py>,
        ino: u64,
        offset: u64,
        size: usize,
        handle: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let buf = run(py, async {
            // never allocate more than what the file can still provide
            let available = self.inner.get_attr(ino).await?.size.saturating_sub(offset);
            let size = size.min(usize::try_from(available).unwrap_or(usize::MAX));
            let mut buf = vec![0_u8; size];
            let len = self.inner.read(ino, offset, &mut buf, handle).await?;
            buf.truncate(len);
            Ok(buf)
        })?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Writes the whole buffer at `offset` and returns the number of bytes written.
    fn write(
        &self,
        py: Python<'_>,
        ino: u64,
        offset: u64,
        buf: &[u8],
        handle: u64,
    ) -> PyResult<usize> {
        run(py, async {
            // the core writes at most one block per call, so loop until everything is written
            let mut written = 0_usize;
            while written < buf.len() {
                let len = self
                    .inner
                    .write(ino, offset + written as u64, &buf[written..], handle)
                    .await?;
                if len == 0 {
                    break;
                }
                written += len;
            }
            Ok(written)
        })
    }

    fn flush(&self, py: Python<'_>, handle: u64) -> PyResult<()> {
        run(py, self.inner.flush(handle))
    }

    fn release(&self, py: Python<'_>, handle: u64) -> PyResult<()> {
        run(py, self.inner.release(handle))
    }

    fn is_read_handle(&self, py: Python<'_>, handle: u64) -> bool {
        py.detach(|| RT.block_on(self.inner.is_read_handle(handle)))
    }

    fn is_write_handle(&self, py: Python<'_>, handle: u64) -> bool {
        py.detach(|| RT.block_on(self.inner.is_write_handle(handle)))
    }

    fn copy_file_range(
        &self,
        py: Python<'_>,
        src_ino: u64,
        src_offset: u64,
        dest_ino: u64,
        dest_offset: u64,
        size: usize,
        src_fh: u64,
        dest_fh: u64,
    ) -> PyResult<usize> {
        let req = CopyFileRangeReq::builder()
            .src_ino(src_ino)
            .src_offset(src_offset)
            .dest_ino(dest_ino)
            .dest_offset(dest_offset)
            .src_fh(src_fh)
            .dest_fh(dest_fh)
            .build();
        run(py, self.inner.copy_file_range(&req, size))
    }

    fn rename(
        &self,
        py: Python<'_>,
        parent: u64,
        name: String,
        new_parent: u64,
        new_name: String,
    ) -> PyResult<()> {
        let name = secret(name);
        let new_name = secret(new_name);
        run(py, self.inner.rename(parent, &name, new_parent, &new_name))
    }

    fn remove_file(&self, py: Python<'_>, parent: u64, name: String) -> PyResult<()> {
        let name = secret(name);
        run(py, self.inner.remove_file(parent, &name))
    }

    fn remove_dir(&self, py: Python<'_>, parent: u64, name: String) -> PyResult<()> {
        let name = secret(name);
        run(py, self.inner.remove_dir(parent, &name))
    }

    fn set_len(&self, py: Python<'_>, ino: u64, size: u64) -> PyResult<()> {
        run(py, self.inner.set_len(ino, size))
    }

    fn read_dir(&self, py: Python<'_>, ino: u64) -> PyResult<Vec<DirEntry>> {
        run(py, async {
            let mut entries = Vec::new();
            for entry in self.inner.read_dir(ino).await? {
                let entry = entry?;
                let name = entry.name.expose_secret().to_string();
                entries.push(DirEntry::new(entry.ino, name, entry.kind.into()));
            }
            Ok(entries)
        })
    }

    fn read_dir_plus(&self, py: Python<'_>, ino: u64) -> PyResult<Vec<DirEntryPlus>> {
        run(py, async {
            let mut entries = Vec::new();
            for entry in self.inner.read_dir_plus(ino).await? {
                let entry = entry?;
                let name = entry.name.expose_secret().to_string();
                entries.push(DirEntryPlus::new(
                    entry.ino,
                    name,
                    entry.kind.into(),
                    entry.attr.into(),
                ));
            }
            Ok(entries)
        })
    }

    #[staticmethod]
    fn passwd(
        py: Python<'_>,
        data_dir: PathBuf,
        old_password: String,
        new_password: String,
        cipher: Cipher,
    ) -> PyResult<()> {
        run(py, async {
            RustEncryptedFs::passwd(
                &data_dir,
                secret(old_password),
                secret(new_password),
                cipher.into(),
            )
            .await
        })
    }
}
