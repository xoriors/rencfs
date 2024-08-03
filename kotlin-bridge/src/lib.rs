extern crate jni;
extern crate rencfs;
extern crate secrecy;
extern crate tokio;
extern crate tracing;

use crate::rencfs::mount::MountPoint;
use ctrlc::set_handler;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::PasswordProvider;
use rencfs::log::log_init;
use rencfs::mount::{create_mount_point, umount, MountHandle};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::ops::{Add, Deref};
use std::path::Path;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::{io, process};
use tokio::runtime::Runtime;
use tracing::{error, info, Level};
use tracing_appender::non_blocking::WorkerGuard;

fn hello(name: &str) -> String {
    format!("Hello {name} from Rust!")
}

/// Test function that takes a string and returns it with some additional one.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_hello(
    // Java environment.
    mut env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
    // The string which must be sorted
    name: JString,
) -> jstring {
    let name: String = env.get_string(&name).unwrap().into();

    let result = hello(&name);

    let output = env.new_string(result).unwrap();

    output.into_raw()
}

static RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

static HANDLES: LazyLock<Mutex<Option<BTreeMap<u32, (String, MountHandle)>>>> =
    LazyLock::new(|| Mutex::new(Some(BTreeMap::new())));

static NEXT_HANDLE_ID: LazyLock<u32> = LazyLock::new(|| 0);

static LOG_GUARD: LazyLock<WorkerGuard> = LazyLock::new(|| log_init(Level::INFO));

/// Mounts a filesystem at `mnt` with `data_dir` and `password`, returning the mount handle.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_mount(
    // Java environment.
    mut env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
    mnt: JString,
    data_dir: JString,
    password: JString,
) -> jint {
    let _guard = LOG_GUARD.deref();
    let mount_path: String = env.get_string(&mnt).unwrap().into();
    let data_dir_path: String = env.get_string(&data_dir).unwrap().into();
    let password: String = env.get_string(&password).unwrap().into();

    info!("mount_path: {}", mount_path);
    info!("data_dir_path: {}", data_dir_path);

    struct PasswordProviderImpl(String);
    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            Some(SecretString::from_str(&self.0).unwrap())
        }
    }
    let mount_point = create_mount_point(
        Path::new(&mount_path),
        Path::new(&data_dir_path),
        Box::new(PasswordProviderImpl(password)),
        Cipher::ChaCha20Poly1305,
        false,
        false,
        false,
        false,
    );
    let (tx, rx) = std::sync::mpsc::channel::<io::Result<MountHandle>>();
    RT.block_on(async {
        // cleanup on process kill
        set_handler(move || {
            // can't use tracing methods here as guard cannot be dropper to flush content before we exit
            eprintln!("Received signal to exit, umounting...");
            // create new tokio runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = rt
                .block_on(async {
                    for (_, (mnt, handle)) in HANDLES.lock().unwrap().take().unwrap().into_iter() {
                        let res = handle.umount().await;
                        if res.is_err() {
                            umount(&mnt)?;
                        }
                    }
                    Ok::<(), io::Error>(())
                })
                .map_err(|err| {
                    eprintln!("Error: {}", err);
                    process::exit(1);
                });
            eprintln!("Umounted");
            process::exit(0);
        })
        .unwrap();

        let handle = mount_point.mount().await;
        match handle {
            Ok(handle) => tx.send(Ok(handle)).unwrap(),
            Err(err) => tx
                .send(Err(io::Error::new(io::ErrorKind::Other, err)))
                .unwrap(),
        }
    });
    let handle = match rx.recv().unwrap() {
        Ok(handle) => handle,
        Err(err) => {
            error!("Cannot mount: {}", err);
            let _ = env.throw_new("java/io/IOException", format!("Cannot mount: {}", err));
            return -1;
        }
    };
    let next_handle = NEXT_HANDLE_ID.add(1);
    HANDLES
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(next_handle, (mount_path, handle));

    next_handle as jint
}

/// Unmounts the filesystem at `mount` handle returned by `mount`.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_umount(
    // Java environment.
    mut env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
    handle: jint,
) {
    let handle = handle as u32;
    let (mnt, handle) = HANDLES
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .remove(&handle)
        .unwrap();
    match RT.block_on(async {
        handle
            .umount()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }) {
        Ok(_) => {}
        Err(err) => {
            error!("Cannot umount, force: {}", err);
            match umount(&mnt) {
                Ok(_) => info!("Umounted"),
                Err(err) => {
                    error!("Cannot umount: {}", err);
                    let _ = env.throw_new("java/io/IOException", format!("Cannot umount: {}", err));
                }
            }
        }
    }
}
