use shush_rs::{ExposeSecret, SecretString};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_ulonglong};
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use tokio::runtime::Runtime;

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, DirectoryEntryIterator, EncryptedFs, FileType, PasswordProvider, ROOT_INODE,
};

// Context structure to hold the runtime and fs instance
pub struct RencfsContext {
    rt: Runtime,
    fs: Arc<EncryptedFs>,
}

// Simple provider for password
struct SimplePass {
    p: SecretString,
}

impl PasswordProvider for SimplePass {
    fn get_password(&self) -> Option<SecretString> {
        Some(self.p.clone())
    }
}

/// # Safety
/// Pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_init(
    path: *const c_char,
    pass: *const c_char,
) -> *mut RencfsContext {
    if path.is_null() || pass.is_null() {
        return ptr::null_mut();
    }

    let c_path = CStr::from_ptr(path);
    let s_path = match c_path.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let path_buf = PathBuf::from(s_path);

    let c_pass = CStr::from_ptr(pass);
    let s_pass = match c_pass.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let secret = SecretString::new(Box::new(s_pass.to_string()));

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };

    // run init inside tokio runtime
    let res = rt.block_on(async {
        let prov = Box::new(SimplePass { p: secret });
        EncryptedFs::new(path_buf, prov, Cipher::ChaCha20Poly1305, false).await
    });

    match res {
        Ok(fs) => {
            let ctx = Box::new(RencfsContext { rt, fs });
            Box::into_raw(ctx)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// # Safety
/// ctx must be valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_free(ctx: *mut RencfsContext) {
    if !ctx.is_null() {
        let _ = Box::from_raw(ctx);
    }
}

/// # Safety
/// pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_create_file(
    ctx: *mut RencfsContext,
    fname: *const c_char,
    out_ino: *mut c_ulonglong,
    out_fh: *mut c_ulonglong,
) -> c_int {
    let c = &mut *ctx;
    let c_name = CStr::from_ptr(fname);
    let s_name = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret = SecretString::new(Box::new(s_name.to_string()));

    let attr = CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    };

    let res =
        c.rt.block_on(async { c.fs.create(ROOT_INODE, &secret, attr, true, true).await });

    match res {
        Ok((fh, fattr)) => {
            *out_ino = fattr.ino;
            *out_fh = fh;
            0
        }
        Err(_) => -1,
    }
}

/// # Safety
/// valid pointers required.
#[no_mangle]
pub unsafe extern "C" fn rencfs_write(
    ctx: *mut RencfsContext,
    ino: c_ulonglong,
    fh: c_ulonglong,
    buf: *const c_uchar,
    len: usize,
    off: c_ulonglong,
) -> c_int {
    let c = &mut *ctx;
    let data = std::slice::from_raw_parts(buf, len);

    let res =
        c.rt.block_on(async { c.fs.write(ino, off, data, fh).await });

    match res {
        Ok(n) => n as c_int,
        Err(_) => -1,
    }
}

/// # Safety
/// valid pointers required.
#[no_mangle]
pub unsafe extern "C" fn rencfs_read(
    ctx: *mut RencfsContext,
    ino: c_ulonglong,
    fh: c_ulonglong,
    buf: *mut c_uchar,
    len: usize,
    off: c_ulonglong,
) -> c_int {
    let c = &mut *ctx;
    let data = std::slice::from_raw_parts_mut(buf, len);

    let res = c.rt.block_on(async { c.fs.read(ino, off, data, fh).await });

    match res {
        Ok(n) => n as c_int,
        Err(_) => -1,
    }
}

/// # Safety
/// ctx valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_close(ctx: *mut RencfsContext, fh: c_ulonglong) -> c_int {
    let c = &mut *ctx;
    let res = c.rt.block_on(async { c.fs.release(fh).await });

    match res {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_mkdir(
    ctx: *mut RencfsContext,
    p_ino: c_ulonglong,
    fname: *const c_char,
    out_ino: *mut c_ulonglong,
) -> c_int {
    let c = &mut *ctx;
    let c_name = CStr::from_ptr(fname);
    let s_name = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret = SecretString::new(Box::new(s_name.to_string()));

    let attr = CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o755,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    };

    let res =
        c.rt.block_on(async { c.fs.create(p_ino, &secret, attr, false, false).await });

    match res {
        Ok((_, fattr)) => {
            *out_ino = fattr.ino;
            0
        }
        Err(_) => -1,
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_unlink(
    ctx: *mut RencfsContext,
    p_ino: c_ulonglong,
    fname: *const c_char,
) -> c_int {
    let c = &mut *ctx;
    let c_name = CStr::from_ptr(fname);
    let s_name = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret = SecretString::new(Box::new(s_name.to_string()));

    let res =
        c.rt.block_on(async { c.fs.remove_file(p_ino, &secret).await });

    match res {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_rmdir(
    ctx: *mut RencfsContext,
    p_ino: c_ulonglong,
    fname: *const c_char,
) -> c_int {
    let c = &mut *ctx;
    let c_name = CStr::from_ptr(fname);
    let s_name = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret = SecretString::new(Box::new(s_name.to_string()));

    let res =
        c.rt.block_on(async { c.fs.remove_dir(p_ino, &secret).await });

    match res {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_rename(
    ctx: *mut RencfsContext,
    parent: c_ulonglong,
    old: *const c_char,
    new_parent: c_ulonglong,
    new_n: *const c_char,
) -> c_int {
    let c = &mut *ctx;

    let c_old = CStr::from_ptr(old);
    let s_old = match c_old.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sec_old = SecretString::new(Box::new(s_old.to_string()));

    let c_new = CStr::from_ptr(new_n);
    let s_new = match c_new.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sec_new = SecretString::new(Box::new(s_new.to_string()));

    let res =
        c.rt.block_on(async { c.fs.rename(parent, &sec_old, new_parent, &sec_new).await });

    match res {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_change_password(
    path: *const c_char,
    old: *const c_char,
    new_p: *const c_char,
) -> c_int {
    if path.is_null() || old.is_null() || new_p.is_null() {
        return -1;
    }

    let c_path = CStr::from_ptr(path);
    let s_path = match c_path.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let p_buf = PathBuf::from(s_path);

    let c_old = CStr::from_ptr(old);
    let s_old = match c_old.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sec_old = SecretString::new(Box::new(s_old.to_string()));

    let c_new = CStr::from_ptr(new_p);
    let s_new = match c_new.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sec_new = SecretString::new(Box::new(s_new.to_string()));

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return -1,
    };

    let res = rt.block_on(async {
        EncryptedFs::passwd(&p_buf, sec_old, sec_new, Cipher::ChaCha20Poly1305).await
    });

    match res {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// Directory listing

pub struct RencfsDirIterator {
    iter: DirectoryEntryIterator,
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_opendir(
    ctx: *mut RencfsContext,
    ino: c_ulonglong,
) -> *mut RencfsDirIterator {
    let c = &mut *ctx;

    let res = c.rt.block_on(async { c.fs.read_dir(ino).await });

    match res {
        Ok(iter) => {
            let d = Box::new(RencfsDirIterator { iter });
            Box::into_raw(d)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// # Safety
/// pointers valid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_readdir(
    dir_ctx: *mut RencfsDirIterator,
    out_name: *mut c_char,
    n_len: usize,
    out_ino: *mut c_ulonglong,
    out_type: *mut c_uchar,
) -> c_int {
    if dir_ctx.is_null() {
        return -1;
    }
    let it = &mut *dir_ctx;

    match it.iter.next() {
        Some(res) => {
            match res {
                Ok(entry) => {
                    *out_ino = entry.ino;

                    // Aici era eroarea: am scos _ => 0
                    *out_type = match entry.kind {
                        FileType::Directory => 1,
                        FileType::RegularFile => 2,
                    };

                    let s = entry.name.expose_secret();
                    let b = s.as_bytes();

                    if b.len() >= n_len {
                        return -1;
                    }

                    ptr::copy_nonoverlapping(b.as_ptr(), out_name as *mut u8, b.len());
                    *out_name.add(b.len()) = 0;

                    1
                }
                Err(_) => -1,
            }
        }
        None => 0,
    }
}

/// # Safety
/// valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rencfs_closedir(d: *mut RencfsDirIterator) {
    if !d.is_null() {
        let _ = Box::from_raw(d);
    }
}
