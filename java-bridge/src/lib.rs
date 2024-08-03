extern crate jni;
extern crate rencfs;
extern crate secrecy;
extern crate tokio;
extern crate tracing;

use crate::rencfs::mount::MountPoint;
use ctrlc::set_handler;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
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
use std::sync::LazyLock;
use std::{io, process};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tracing::{error, info, warn, Level};
use tracing_appender::non_blocking::WorkerGuard;

#[derive(Debug, Default)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct State {
    dry_run: bool,
    simulate_mount_error: bool,
    simulate_umount_error: bool,
    simulate_umount_all_error: bool,
}

impl State {
    fn dry_run(mut self, dry_run: bool) -> State {
        self.dry_run = dry_run;
        self
    }

    fn simulate_mount_error(mut self, simulate_mount_error: bool) -> State {
        self.simulate_mount_error = simulate_mount_error;
        self
    }

    fn simulate_umount_error(mut self, simulate_umount_error: bool) -> State {
        self.simulate_umount_error = simulate_umount_error;
        self
    }

    fn simulate_umount_all_error(mut self, simulate_umount_all_error: bool) -> State {
        self.simulate_umount_all_error = simulate_umount_all_error;
        self
    }
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

static STATE: LazyLock<std::sync::Mutex<State>> =
    LazyLock::new(|| std::sync::Mutex::new(State::default()));

static CRL_C_INITIALIZED: LazyLock<std::sync::Mutex<bool>> =
    LazyLock::new(|| std::sync::Mutex::new(false));

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
    umount_first: jboolean,
) -> jint {
    let _guard = LOG_GUARD.deref();
    let mount_path: String = env.get_string(&mnt).unwrap().into();
    let data_dir_path: String = env.get_string(&data_dir).unwrap().into();
    let password: String = env.get_string(&password).unwrap().into();

    info!("mount_path: {}", mount_path);
    info!("data_dir_path: {}", data_dir_path);

    if STATE.lock().unwrap().dry_run {
        return 0;
    } else if STATE.lock().unwrap().simulate_mount_error {
        let _ = env.throw_new("java/io/IOException", "cannot mount".to_string());
        return -1;
    }

    if !*CRL_C_INITIALIZED.lock().unwrap() {
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
                        for (_, (mnt, handle)) in HANDLES.lock().await.take().unwrap().into_iter() {
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

            *CRL_C_INITIALIZED.lock().unwrap() = true;
        });
    }

    if umount_first == 1 {
        let _ = umount(mount_path.as_str()).map_err(|err| {
            warn!("Cannot umount, maybe it was not mounted: {err}");
            err
        });
    }

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

    let handle = match RT.block_on(async {
        match mount_point.mount().await {
            Ok(handle) => Ok(handle),
            Err(err) => Err(err),
        }
    }) {
        Ok(handle) => handle,
        Err(err) => {
            error!("Cannot mount: {}", err);
            let _ = env.throw_new("java/io/IOException", format!("cannot mount: {}", err));
            return -1;
        }
    };
    let next_handle = NEXT_HANDLE_ID.add(1);
    RT.block_on(async {
        HANDLES
            .lock()
            .await
            .as_mut()
            .unwrap()
            .insert(next_handle, (mount_path.clone(), handle));
    });

    info!("next_handle: {next_handle}");

    next_handle as jint
}

/// Unmounts the filesystem at `mount handle` returned by [mount].
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_umount(
    // Java environment.
    mut env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
    handle: jint,
) {
    if STATE.lock().unwrap().simulate_umount_error {
        let _ = env.throw_new("java/io/IOException", "cannot umount".to_string());
        return;
    }

    let handle = handle as u32;
    info!("handle: {handle}");

    match RT.block_on(async {
        let (mnt, handle) = HANDLES
            .lock()
            .await
            .as_mut()
            .unwrap()
            .remove(&handle)
            .unwrap();
        match handle
            .umount()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("Cannot umount, force: {}", err);
                match umount(&mnt) {
                    Ok(_) => {
                        info!("Umounted");
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }) {
        Ok(_) => {}
        Err(err) => {
            error!("Cannot umount: {}", err);
            let _ = env.throw_new("java/io/IOException", format!("cannot umount: {}", err));
        }
    }
}

/// Unmounts all mounted filesystems.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_umountAll(
    // Java environment.
    mut env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
) {
    if STATE.lock().unwrap().simulate_umount_all_error {
        let _ = env.throw_new("java/io/IOException", "cannot umount all".to_string());
        return;
    }

    match RT.block_on(async {
        for (_, (mnt, handle)) in HANDLES.lock().await.take().unwrap().into_iter() {
            let res = handle.umount().await;
            if res.is_err() {
                umount(&mnt)?;
            }
        }
        Ok::<(), io::Error>(())
    }) {
        Ok(_) => info!("Umounted"),
        Err(err) => {
            let _ = env.throw_new("java/io/IOException", format!("cannot umount: {}", err));
        }
    }
}

/// Set state.
///
/// Helpful to simulate various errors and `dry-run`.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_RustLibrary_state(
    // Java environment.
    _env: JNIEnv,
    // Static class which owns this method.
    _class: JClass,
    dry_run: bool,
    simulate_mount_error: bool,
    simulate_umount_error: bool,
    simulate_umount_all_error: bool,
) {
    *STATE.lock().unwrap() = State::default()
        .dry_run(dry_run)
        .simulate_mount_error(simulate_mount_error)
        .simulate_umount_error(simulate_umount_error)
        .simulate_umount_all_error(simulate_umount_all_error);
}
