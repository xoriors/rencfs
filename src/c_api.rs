use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_ulonglong};
use std::path::PathBuf;
use std::sync::Arc;
use std::ptr;
use tokio::runtime::Runtime;
use shush_rs::SecretString;

use crate::encryptedfs::{EncryptedFs, PasswordProvider, CreateFileAttr, FileType, ROOT_INODE};
use crate::crypto::Cipher;

// --- Structuri Ajutătoare ---

// Aceasta este structura opacă pe care o va ține C++ (void*)
pub struct RencfsContext {
    rt: Runtime,
    fs: Arc<EncryptedFs>,
}

// Avem nevoie de un provider simplu de parolă pentru init
struct SimplePasswordProvider {
    password: SecretString,
}

impl PasswordProvider for SimplePasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        Some(self.password.clone())
    }
}

// --- API-ul C (FFI) ---

/// Inițializează filesystem-ul.
/// Returnează un pointer către context (sau NULL dacă eșuează).
///
/// # Safety
/// Pointers `base_path` and `password` must be valid, null-terminated C strings.
/// The caller is responsible for freeing the returned pointer using `rencfs_free`.
#[no_mangle]
pub unsafe extern "C" fn rencfs_init(
    base_path: *const c_char,
    password: *const c_char,
) -> *mut RencfsContext {
    if base_path.is_null() || password.is_null() {
        return ptr::null_mut();
    }

    // Conversie C strings -> Rust
    let c_path = CStr::from_ptr(base_path);
    let path_str = match c_path.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let path_buf = PathBuf::from(path_str);

    let c_pass = CStr::from_ptr(password);
    let pass_str = match c_pass.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let secret_pass = SecretString::new(Box::new(pass_str.to_string()));

    // Pornim Runtime-ul Tokio
    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };

    // Inițializăm FS-ul (Async executat sincron)
    let fs_result = rt.block_on(async {
        let provider = Box::new(SimplePasswordProvider { password: secret_pass });
        // Folosim ChaCha20Poly1305 ca default
        EncryptedFs::new(path_buf, provider, Cipher::ChaCha20Poly1305, false).await
    });

    match fs_result {
        Ok(fs) => {
            let context = Box::new(RencfsContext { rt, fs });
            Box::into_raw(context)
        }
        Err(e) => {
            eprintln!("Eroare la init rencfs: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Eliberează memoria contextului.
///
/// # Safety
/// `ctx` must be a valid pointer created by `rencfs_init`.
/// After calling this, `ctx` becomes invalid.
#[no_mangle]
pub unsafe extern "C" fn rencfs_free(ctx: *mut RencfsContext) {
    if !ctx.is_null() {
        // Rust va face "drop" automat când pointerul revine în Box
        let _ = Box::from_raw(ctx);
        println!("Rencfs context eliberat.");
    }
}

/// Creează un fișier nou în root.
/// Returnează 0 la succes, -1 la eroare.
/// Completează out_ino și out_handle.
///
/// # Safety
/// `ctx` must be a valid pointer.
/// `filename` must be a valid null-terminated C string.
/// `out_ino` and `out_handle` must be valid pointers to writeable memory.
#[no_mangle]
pub unsafe extern "C" fn rencfs_create_file(
    ctx: *mut RencfsContext,
    filename: *const c_char,
    out_ino: *mut c_ulonglong,
    out_handle: *mut c_ulonglong,
) -> c_int {
    let context = &mut *ctx;
    let c_name = CStr::from_ptr(filename);
    let name_str = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_name = SecretString::new(Box::new(name_str.to_string()));

    // Configurare atribute default (RegularFile, permisiuni 644)
    let attr = CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    };

    let result = context.rt.block_on(async {
        context.fs.create(ROOT_INODE, &secret_name, attr, true, true).await
    });

    match result {
        Ok((handle, file_attr)) => {
            *out_ino = file_attr.ino;
            *out_handle = handle;
            0
        }
        Err(e) => {
            eprintln!("Eroare create file: {:?}", e);
            -1
        }
    }
}

/// Scrie date într-un fișier deschis.
/// Returnează numărul de bytes scriși sau -1 la eroare.
///
/// # Safety
/// `ctx` must be a valid pointer.
/// `buf` must be a valid pointer to a byte array of at least `len` size.
#[no_mangle]
pub unsafe extern "C" fn rencfs_write(
    ctx: *mut RencfsContext,
    ino: c_ulonglong,
    handle: c_ulonglong,
    buf: *const c_uchar,
    len: usize,
    offset: c_ulonglong,
) -> c_int {
    let context = &mut *ctx;
    let data_slice = std::slice::from_raw_parts(buf, len);

    let result = context.rt.block_on(async {
        context.fs.write(ino, offset, data_slice, handle).await
    });

    match result {
        Ok(bytes_written) => bytes_written as c_int,
        Err(e) => {
            eprintln!("Eroare write: {:?}", e);
            -1
        }
    }
}

/// Citește date dintr-un fișier.
/// Returnează numărul de bytes citiți sau -1 la eroare.
///
/// # Safety
/// `ctx` must be a valid pointer.
/// `buf` must be a valid pointer to a writeable buffer of at least `len` size.
#[no_mangle]
pub unsafe extern "C" fn rencfs_read(
    ctx: *mut RencfsContext,
    ino: c_ulonglong,
    handle: c_ulonglong,
    buf: *mut c_uchar,
    len: usize,
    offset: c_ulonglong,
) -> c_int {
    let context = &mut *ctx;
    let data_slice = std::slice::from_raw_parts_mut(buf, len);

    let result = context.rt.block_on(async {
        context.fs.read(ino, offset, data_slice, handle).await
    });

    match result {
        Ok(bytes_read) => bytes_read as c_int,
        Err(e) => {
            eprintln!("Eroare read: {:?}", e);
            -1
        }
    }
}

/// Închide un handle (release).
///
/// # Safety
/// `ctx` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rencfs_close(
    ctx: *mut RencfsContext,
    handle: c_ulonglong,
) -> c_int {
    let context = &mut *ctx;
    let result = context.rt.block_on(async {
        context.fs.release(handle).await
    });

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Eroare close: {:?}", e);
            -1
        }
    }
}

/// Creează un director nou.
///
/// # Safety
/// `ctx` must be valid.
/// `filename` must be a valid C string.
/// `out_ino` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rencfs_mkdir(
    ctx: *mut RencfsContext,
    parent_ino: c_ulonglong,
    filename: *const c_char,
    out_ino: *mut c_ulonglong,
) -> c_int {
    let context = &mut *ctx;
    let c_name = CStr::from_ptr(filename);
    let name_str = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_name = SecretString::new(Box::new(name_str.to_string()));

    // Atribute pentru folder (Directory, permisiuni 755)
    let attr = CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o755,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    };

    let result = context.rt.block_on(async {
        // create returneaza (handle, attr). Directoarele au handle 0.
        context.fs.create(parent_ino, &secret_name, attr, false, false).await
    });

    match result {
        Ok((_, file_attr)) => {
            *out_ino = file_attr.ino;
            0
        }
        Err(e) => {
            eprintln!("Eroare mkdir: {:?}", e);
            -1
        }
    }
}

/// Șterge un fișier.
///
/// # Safety
/// `ctx` must be valid.
/// `filename` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn rencfs_unlink(
    ctx: *mut RencfsContext,
    parent_ino: c_ulonglong,
    filename: *const c_char,
) -> c_int {
    let context = &mut *ctx;
    let c_name = CStr::from_ptr(filename);
    let name_str = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_name = SecretString::new(Box::new(name_str.to_string()));

    let result = context.rt.block_on(async {
        context.fs.remove_file(parent_ino, &secret_name).await
    });

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Eroare unlink: {:?}", e);
            -1
        }
    }
}

/// Șterge un director (trebuie să fie gol).
///
/// # Safety
/// `ctx` must be valid.
/// `filename` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn rencfs_rmdir(
    ctx: *mut RencfsContext,
    parent_ino: c_ulonglong,
    filename: *const c_char,
) -> c_int {
    let context = &mut *ctx;
    let c_name = CStr::from_ptr(filename);
    let name_str = match c_name.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_name = SecretString::new(Box::new(name_str.to_string()));

    let result = context.rt.block_on(async {
        context.fs.remove_dir(parent_ino, &secret_name).await
    });

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Eroare rmdir: {:?}", e);
            -1
        }
    }
}

/// Redenumește un fișier sau director.
///
/// # Safety
/// `ctx` must be valid.
/// `old_name` and `new_name` must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn rencfs_rename(
    ctx: *mut RencfsContext,
    parent: c_ulonglong,
    old_name: *const c_char,
    new_parent: c_ulonglong,
    new_name: *const c_char,
) -> c_int {
    let context = &mut *ctx;
    
    // Conversie old_name
    let c_old = CStr::from_ptr(old_name);
    let old_str = match c_old.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_old = SecretString::new(Box::new(old_str.to_string()));

    // Conversie new_name
    let c_new = CStr::from_ptr(new_name);
    let new_str = match c_new.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let secret_new = SecretString::new(Box::new(new_str.to_string()));

    let result = context.rt.block_on(async {
        context.fs.rename(parent, &secret_old, new_parent, &secret_new).await
    });

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Eroare rename: {:?}", e);
            -1
        }
    }
}
