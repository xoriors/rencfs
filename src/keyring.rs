use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};

const KEYRING_SERVICE: &'static str = "rencfs";
const KEYRING_USER: &'static str = "encrypted_fs";

pub(crate) fn save(password: SecretString, suffix: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("{KEYRING_USER}.{suffix}"))?;
    entry.set_password(password.expose_secret())
}

pub(crate) fn delete(suffix: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("{KEYRING_USER}.{suffix}"))?;
    entry.delete_password()
}

pub(crate) fn get(suffix: &str) -> Result<SecretString, keyring::Error> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("{KEYRING_USER}.{suffix}"))?;
    Ok(SecretString::new(entry.get_password()?))
}
