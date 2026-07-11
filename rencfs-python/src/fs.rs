use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;

use crate::types::{
    Cipher, CreateFileAttr, DirEntry, DirEntryPlus, FileAttr, PyFsError, SetFileAttr,
};
use rencfs::encryptedfs::{
    CreateFileAttr as RustCreateFileAttr, EncryptedFs as RustEncryptedFs, PasswordProvider,
};
use shush_rs::{ExposeSecret, SecretString};

struct PyPasswordProvider {
    password: SecretString,
}

impl PasswordProvider for PyPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        Some(self.password.clone())
    }
}

#[pyclass]
pub struct EncryptedFs {
    inner: Arc<RustEncryptedFs>,
    rt: Runtime,
}

#[pymethods]
impl EncryptedFs {
    #[new]
    fn new(data_dir: String, password: String, cipher: Cipher, read_only: bool) -> PyResult<Self> {
        let rt =
            Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let provider = Box::new(PyPasswordProvider {
            password: SecretString::new(Box::new(password.into())),
        });

        let inner_result = rt.block_on(async {
            RustEncryptedFs::new(PathBuf::from(data_dir), provider, cipher.into(), read_only).await
        });

        match inner_result {
            Ok(inner) => Ok(EncryptedFs { inner, rt }),
            Err(e) => Err(PyFsError(e).into()),
        }
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
        let result = self.rt.block_on(async { self.inner.len(ino) });
        match result {
            Ok(len) => Ok(len),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn exists_by_name(&self, parent: u64, name: String) -> PyResult<bool> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let result = self
            .rt
            .block_on(async { self.inner.exists_by_name(parent, &secret_name) });
        match result {
            Ok(exists) => Ok(exists),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn find_by_name(&self, parent: u64, name: String) -> PyResult<Option<FileAttr>> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let result = self
            .rt
            .block_on(async { self.inner.find_by_name(parent, &secret_name).await });

        match result {
            Ok(opt) => match opt {
                Some(attr) => Ok(Some(attr.into())),
                None => Ok(None),
            },
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn get_attr(&self, ino: u64) -> PyResult<FileAttr> {
        let result = self.rt.block_on(async { self.inner.get_attr(ino).await });
        match result {
            Ok(attr) => Ok(attr.into()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn set_attr(&self, ino: u64, attr: SetFileAttr) -> PyResult<()> {
        let rust_attr = attr.into_rust();
        let result = self
            .rt
            .block_on(async { self.inner.set_attr(ino, rust_attr).await });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn create(
        &self,
        parent: u64,
        name: String,
        attr: CreateFileAttr,
        read: bool,
        write: bool,
    ) -> PyResult<(u64, FileAttr)> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let rust_attr: RustCreateFileAttr = attr.into();

        let result = self.rt.block_on(async {
            self.inner
                .create(parent, &secret_name, rust_attr, read, write)
                .await
        });

        match result {
            Ok((ino, returned_attr)) => Ok((ino, returned_attr.into())),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn open(&self, ino: u64, read: bool, write: bool) -> PyResult<u64> {
        let result = self
            .rt
            .block_on(async { self.inner.open(ino, read, write).await });
        match result {
            Ok(handle) => Ok(handle),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn read(&self, py: Python, ino: u64, offset: u64, size: usize, handle: u64) -> PyResult<PyObject> {
        // Get the file attributes to determine the available bytes from offset
        let attr = self.get_attr(ino)?;
        let available = attr.size.saturating_sub(offset);
        let size = size.min(available as usize);

        let mut buf = vec![0u8; size];
        let result = self
            .rt
            .block_on(async { self.inner.read(ino, offset, &mut buf, handle).await });
        match result {
            Ok(read_len) => {
                buf.truncate(read_len);
                let bytes = PyBytes::new(py, &buf);
                Ok(bytes.into())
            }
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn write(&self, ino: u64, offset: u64, buf: &[u8], handle: u64) -> PyResult<usize> {
        let result = self
            .rt
            .block_on(async { self.inner.write(ino, offset, buf, handle).await });
        match result {
            Ok(len) => Ok(len),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn flush(&self, handle: u64) -> PyResult<()> {
        let result = self.rt.block_on(async { self.inner.flush(handle).await });
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn release(&self, handle: u64) -> PyResult<()> {
        let result = self.rt.block_on(async { self.inner.release(handle).await });
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn rename(&self, parent: u64, name: String, new_parent: u64, new_name: String) -> PyResult<()> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let secret_new_name = SecretString::new(Box::new(new_name.into()));
        let result = self.rt.block_on(async {
            self.inner
                .rename(parent, &secret_name, new_parent, &secret_new_name)
                .await
        });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn remove_file(&self, parent: u64, name: String) -> PyResult<()> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let result = self
            .rt
            .block_on(async { self.inner.remove_file(parent, &secret_name).await });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn remove_dir(&self, parent: u64, name: String) -> PyResult<()> {
        let secret_name = SecretString::new(Box::new(name.into()));
        let result = self
            .rt
            .block_on(async { self.inner.remove_dir(parent, &secret_name).await });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn set_len(&self, ino: u64, size: u64) -> PyResult<()> {
        let result = self
            .rt
            .block_on(async { self.inner.set_len(ino, size).await });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn read_dir(&self, ino: u64) -> PyResult<Vec<DirEntry>> {
        let result = self.rt.block_on(async { self.inner.read_dir(ino).await });
        match result {
            Ok(iter) => {
                let mut entries = Vec::new();
                for entry_res in iter {
                    match entry_res {
                        Ok(entry) => {
                            let name = entry.name.expose_secret().to_string();
                            entries.push(DirEntry::new(entry.ino, name, entry.kind.into()));
                        }
                        Err(e) => return Err(PyFsError(e).into()),
                    }
                }
                Ok(entries)
            }
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    fn read_dir_plus(&self, ino: u64) -> PyResult<Vec<DirEntryPlus>> {
        let result = self
            .rt
            .block_on(async { self.inner.read_dir_plus(ino).await });
        match result {
            Ok(iter) => {
                let mut entries = Vec::new();
                for entry_res in iter {
                    match entry_res {
                        Ok(entry) => {
                            let name = entry.name.expose_secret().to_string();
                            entries.push(DirEntryPlus::new(
                                entry.ino,
                                name,
                                entry.kind.into(),
                                entry.attr.into(),
                            ));
                        }
                        Err(e) => return Err(PyFsError(e).into()),
                    }
                }
                Ok(entries)
            }
            Err(e) => Err(PyFsError(e).into()),
        }
    }

    #[staticmethod]
    fn passwd(
        data_dir: String,
        old_password: String,
        new_password: String,
        cipher: Cipher,
    ) -> PyResult<()> {
        let secret_old = SecretString::new(Box::new(old_password.into()));
        let secret_new = SecretString::new(Box::new(new_password.into()));
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let path = PathBuf::from(data_dir);

        let result = rt.block_on(async {
            rencfs::encryptedfs::EncryptedFs::passwd(&path, secret_old, secret_new, cipher.into())
                .await
        });

        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(PyFsError(e).into()),
        }
    }
}
