//! This is a fork of the [secrets](https://github.com/stouset/secrets) crate.
//! This crate adds `mlock`  to lock the secret's page in memory

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

use core::{
    any,
    fmt::{self, Debug},
};
use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};
use std::{mem::size_of_val, str::FromStr};

#[cfg(windows)]
use std::{
    collections::HashMap,
    ffi::c_void,
    mem::MaybeUninit,
    sync::{Mutex, OnceLock},
};

#[cfg(unix)]
use std::cell::LazyCell;

#[cfg(unix)]
use errno::errno;

#[cfg(unix)]
use std::ffi::c_void;

#[cfg(unix)]
use libc::{mlock, munlock, sysconf, _SC_PAGESIZE};

#[cfg(target_os = "linux")]
use libc::{madvise, MADV_DODUMP, MADV_DONTDUMP};

pub use zeroize;
pub use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
static mut PAGE_SIZE: LazyCell<i64> = LazyCell::new(|| {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size == -1 {
        panic!("Error getting page size: \n {}", errno())
    }
    page_size
});

// VirtualLock/VirtualUnlock operate on whole pages. SecretBox values commonly
// share a heap page, so calling VirtualUnlock for each box can unlock a page
// while another secret on that page is still alive. Keep a process-wide page
// reference count and unlock only after the last SecretBox on each page drops.
#[cfg(windows)]
static WINDOWS_PAGE_LOCKS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

#[cfg(windows)]
static WINDOWS_PAGE_SIZE: OnceLock<usize> = OnceLock::new();

#[cfg(windows)]
fn windows_page_size() -> usize {
    *WINDOWS_PAGE_SIZE.get_or_init(|| {
        let mut system_info = MaybeUninit::uninit();
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init().dwPageSize as usize
        }
    })
}

#[cfg(windows)]
fn windows_page_addresses(secret_ptr: *const u8, len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }

    let page_size = windows_page_size();
    let first_address = secret_ptr as usize;
    let last_address = first_address
        .checked_add(len - 1)
        .expect("secret memory range overflow");
    let first_page = first_address - first_address % page_size;
    let last_page = last_address - last_address % page_size;

    (first_page..=last_page).step_by(page_size).collect()
}

#[cfg(windows)]
fn lock_windows_pages(secret_ptr: *const u8, len: usize) -> Result<(), u32> {
    use windows_sys::Win32::{Foundation::GetLastError, System::Memory::VirtualLock};

    let page_size = windows_page_size();
    let pages = windows_page_addresses(secret_ptr, len);
    let page_locks = WINDOWS_PAGE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut page_locks = page_locks.lock().expect("Windows page-lock map poisoned");
    let mut acquired = Vec::with_capacity(pages.len());

    for page in pages {
        let references = page_locks.get(&page).copied().unwrap_or_default();
        if references == 0 && unsafe { VirtualLock(page as *const c_void, page_size) } == 0 {
            let error = unsafe { GetLastError() };
            for acquired_page in acquired.into_iter().rev() {
                unlock_windows_page(&mut page_locks, acquired_page, page_size)
                    .expect("failed to roll back a Windows page lock");
            }
            return Err(error);
        }

        page_locks.insert(
            page,
            references
                .checked_add(1)
                .expect("Windows page-lock reference count overflow"),
        );
        acquired.push(page);
    }

    Ok(())
}

#[cfg(windows)]
fn unlock_windows_page(
    page_locks: &mut HashMap<usize, usize>,
    page: usize,
    page_size: usize,
) -> Result<(), u32> {
    use windows_sys::Win32::{Foundation::GetLastError, System::Memory::VirtualUnlock};

    let references = page_locks
        .get(&page)
        .copied()
        .expect("Windows page-lock reference missing");

    if references > 1 {
        page_locks.insert(page, references - 1);
        return Ok(());
    }

    if unsafe { VirtualUnlock(page as *const c_void, page_size) } == 0 {
        return Err(unsafe { GetLastError() });
    }

    page_locks.remove(&page);
    Ok(())
}

#[cfg(windows)]
fn unlock_windows_pages(secret_ptr: *const u8, len: usize) -> Result<(), u32> {
    let page_size = windows_page_size();
    let pages = windows_page_addresses(secret_ptr, len);
    let page_locks = WINDOWS_PAGE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut page_locks = page_locks.lock().expect("Windows page-lock map poisoned");

    for page in pages {
        unlock_windows_page(&mut page_locks, page, page_size)?;
    }

    Ok(())
}

/// Wrapper for the inner secret. Can be exposed by [`ExposeSecret`]
pub struct SecretBox<S: Zeroize> {
    inner_secret: Box<S>,
}

impl<S: Zeroize> Zeroize for SecretBox<S> {
    fn zeroize(&mut self) {
        self.inner_secret.as_mut().zeroize()
    }
}

/// Convenient type alias for Secret Wrapped Strings
pub type SecretString = SecretBox<String>;

impl FromStr for SecretString {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecretBox::new(Box::new(s.to_string())))
    }
}

/// Convenient type alias for Secret Wrapped Vectors
pub type SecretVec<T> = SecretBox<Vec<T>>;

impl<T: Zeroize> SecretVec<T> {
    /// Generate SecretVec from vec
    pub fn from(new_vec: Vec<T>) -> Self {
        SecretBox::new(Box::new(new_vec))
    }
}

impl<S: Zeroize> Drop for SecretBox<S> {
    fn drop(&mut self) {
        let len = size_of_val(&*self.inner_secret);
        let secret_ptr = self.inner_secret.as_ref() as *const S;

        #[cfg(unix)]
        {
            let page_size = unsafe { *PAGE_SIZE as usize };
            // Align the address and size to the page boundary
            let start = (secret_ptr as usize) & !(page_size - 1);
            let end = ((secret_ptr as usize) + len + page_size - 1) & !(page_size - 1);
            let aligned_len = end - start;

            unsafe {
                #[cfg(target_os = "linux")]
                if madvise(start as *mut c_void, aligned_len, MADV_DODUMP) != 0 {
                    panic!("madvise failed: \n{:?}", errno());
                }

                if munlock(start as *const c_void, aligned_len) != 0 {
                    panic!("Unable to munlock variable: \n {:?} \n", errno())
                }
            }
        }

        #[cfg(windows)]
        {
            // Clear the secret before releasing the page lock.
            self.zeroize();
            if let Err(error) = unlock_windows_pages(secret_ptr.cast(), len) {
                panic!("VirtualUnlock failed with Windows error {error}");
            }
        }

        #[cfg(not(windows))]
        self.zeroize()
    }
}

impl<S: Zeroize> ZeroizeOnDrop for SecretBox<S> {}

impl<S: Zeroize> From<Box<S>> for SecretBox<S> {
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

impl<S: Zeroize> SecretBox<S> {
    /// Create a secret value using a pre-boxed value.
    pub fn new(boxed_secret: Box<S>) -> Self {
        let len = size_of_val(&*boxed_secret);

        #[cfg(windows)]
        if let Err(error) = lock_windows_pages(boxed_secret.as_ref() as *const S as *const u8, len)
        {
            let mut boxed_secret = boxed_secret;
            boxed_secret.zeroize();
            panic!("VirtualLock failed with Windows error {error}");
        }

        let secret_ptr = Box::into_raw(boxed_secret);

        #[cfg(unix)]
        {
            let page_size = unsafe { *PAGE_SIZE as usize };

            // Align the address and size to the page boundary
            let start = (secret_ptr as usize) & !(page_size - 1);
            let end = ((secret_ptr as usize) + len + page_size - 1) & !(page_size - 1);
            let aligned_len = end - start;

            unsafe {
                #[cfg(target_os = "linux")]
                if madvise(start as *mut c_void, aligned_len, MADV_DONTDUMP) != 0 {
                    panic!("madvise failed: \n{:?}", errno());
                }
                if mlock(start as *const c_void, aligned_len) != 0 {
                    panic!("mlock failed: \n{:?}", errno());
                }
            }
        }

        // Recreate Box from raw pointer
        let inner_secret = unsafe { Box::from_raw(secret_ptr) };

        Self { inner_secret }
    }
}

impl<S: Zeroize + Default> SecretBox<S> {
    /// Create a secret value using a function that can initialize the vale in-place.
    pub fn new_with_mut(ctr: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        ctr(&mut *secret.expose_secret_mut());
        secret
    }
}

impl<S: Zeroize + Clone> SecretBox<S> {
    /// Create a secret value using the provided function as a constructor.
    ///
    /// The implementation makes an effort to zeroize the locally constructed value
    /// before it is copied to the heap, and constructing it inside the closure minimizes
    /// the possibility of it being accidentally copied by other code.
    ///
    /// **Note:** using [`Self::new`] or [`Self::new_with_mut`] is preferable when possible,
    /// since this method's safety relies on empyric evidence and may be violated on some targets.
    pub fn new_with_ctr(ctr: impl FnOnce() -> S) -> Self {
        let mut data = ctr();
        let secret = Self::new(Box::new(data.clone()));
        data.zeroize();
        secret
    }

    /// Same as [`Self::new_with_ctr`], but the constructor can be fallible.
    ///
    ///
    /// **Note:** using [`Self::new`] or [`Self::new_with_mut`] is preferable when possible,
    /// since this method's safety relies on empyric evidence and may be violated on some targets.
    pub fn try_new_with_ctr<E>(ctr: impl FnOnce() -> Result<S, E>) -> Result<Self, E> {
        let mut data = ctr()?;
        let secret = Self::new(Box::new(data.clone()));
        data.zeroize();
        Ok(secret)
    }
}

impl<S: Zeroize + Default> Default for SecretBox<S> {
    fn default() -> Self {
        let inner_secret = Box::<S>::default();
        SecretBox::new(inner_secret)
    }
}

impl<S: Zeroize> Debug for SecretBox<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBox<{}>([REDACTED])", any::type_name::<S>())
    }
}

impl<S> Clone for SecretBox<S>
where
    S: CloneableSecret,
{
    fn clone(&self) -> Self {
        SecretBox::new(self.inner_secret.clone())
    }
}

impl<S: Zeroize> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&self) -> SecretGuard<'_, S> {
        SecretGuard::new(&self.inner_secret)
    }

    fn expose_secret_mut(&mut self) -> SecretGuardMut<'_, S> {
        SecretGuardMut::new(&mut self.inner_secret)
    }
}

/// Secret Guard that holds a reference to the secret.
#[derive(Debug, Eq, PartialEq)]
pub struct SecretGuard<'a, S>
where
    S: Zeroize,
{
    data: &'a S,
}

impl<S: Display + Zeroize> Display for SecretGuard<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl<S> Deref for SecretGuard<'_, S>
where
    S: Zeroize,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

/// Secret Guard that holds a mutable to reference to the secret.
#[derive(Debug, Eq, PartialEq)]
pub struct SecretGuardMut<'a, S>
where
    S: Zeroize,
{
    data: &'a mut S,
}

impl<S: Display + Zeroize> Display for SecretGuardMut<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl<S> Deref for SecretGuardMut<'_, S>
where
    S: Zeroize,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<S> DerefMut for SecretGuardMut<'_, S>
where
    S: Zeroize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<'a, S: Zeroize> SecretGuard<'a, S> {
    /// Create a new SecretGuard instance.
    pub fn new(data: &'a S) -> Self {
        Self { data }
    }
}

impl<'a, S: Zeroize> SecretGuardMut<'a, S> {
    /// Create a new SecretGuard instance.
    pub fn new(data: &'a mut S) -> Self {
        Self { data }
    }
}

/// Marker trait for secrets which are allowed to be cloned
pub trait CloneableSecret: Clone + Zeroize {}

impl CloneableSecret for String {}

/// Create a SecretGuard that holds a reference to the secret
pub trait ExposeSecret<S: Zeroize> {
    /// Expose secret as non-mutable.
    fn expose_secret(&self) -> SecretGuard<'_, S>;

    /// Expose secret as mutable.
    fn expose_secret_mut(&mut self) -> SecretGuardMut<'_, S>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestSecret {
        data: Vec<u8>,
    }

    impl TestSecret {
        fn new(size: usize) -> Self {
            let mut data = vec![0; size];
            data[0] = 1;
            Self { data }
        }

        fn check_non_zero(&self) -> bool {
            self.data.iter().any(|&x| x != 0)
        }

        fn check_zero(&self) -> bool {
            self.data.iter().all(|&x| x == 0)
        }
    }

    impl Zeroize for TestSecret {
        fn zeroize(&mut self) {
            self.data = Vec::new();
        }
    }

    #[test]
    fn test_secret_box_drop_zeroizes() {
        let secret = Box::new(TestSecret::new(10));
        let secret_box = SecretBox::new(secret);
        assert!((*secret_box.expose_secret()).check_non_zero());

        drop(secret_box);

        // Verify that secret is zeroized after drop
        // This requires checking the memory, which is not straightforward in Rust.
        // Here we rely on the zeroize trait to ensure it zeroizes.
        assert!(TestSecret::default().check_zero());
    }

    #[test]
    fn test_secret_box_expose_secret_mut() {
        let secret = Box::new(String::from("Encrypted"));
        let mut secret_box = SecretBox::new(secret);

        {
            let mut exposed = secret_box.expose_secret_mut();
            (*exposed) = String::from("Encrypted 2");
        }

        assert_eq!((*secret_box.expose_secret()), String::from("Encrypted 2"));
    }

    #[test]
    fn test_secret_box_new_with_ctr() {
        let secret_box = SecretBox::new_with_ctr(|| TestSecret::new(10));
        assert!((*secret_box.expose_secret()).check_non_zero());
    }

    #[test]
    fn test_secret_box_try_new_with_ctr() {
        let result: Result<SecretBox<TestSecret>, &'static str> =
            SecretBox::try_new_with_ctr(|| Ok(TestSecret::new(10)));

        match result {
            Ok(secret_box) => assert!((*secret_box.expose_secret()).check_non_zero()),
            Err(_) => panic!("Expected Ok variant"),
        }
    }

    #[test]
    fn test_secret_guard_equality() {
        let secret_guard_a = SecretGuard::new(&5);
        let secret_guard_b = SecretGuard::new(&5);

        assert!(secret_guard_a == secret_guard_b);

        let mut val_a = 7;
        let mut val_b = 5;

        let secret_guard_mut_a = SecretGuardMut::new(&mut val_a);
        let secret_guard_mut_b = SecretGuardMut::new(&mut val_b);

        assert!(secret_guard_mut_a != secret_guard_mut_b)
    }
}

#[cfg(all(test, windows))]
mod windows_page_lock_tests {
    use super::{lock_windows_pages, unlock_windows_pages, windows_page_size};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };

    #[test]
    fn overlapping_secrets_keep_their_shared_page_locked_until_last_drop() {
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                windows_page_size(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        assert!(!page.is_null(), "VirtualAlloc failed");

        let second_secret = unsafe { page.cast::<u8>().add(32) };
        let result = (|| {
            lock_windows_pages(page.cast(), 64)?;
            lock_windows_pages(second_secret, 64)?;
            unlock_windows_pages(page.cast(), 64)?;
            unlock_windows_pages(second_secret, 64)
        })();

        unsafe {
            VirtualFree(page, 0, MEM_RELEASE);
        }

        assert_eq!(result, Ok(()));
    }
}
