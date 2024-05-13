use std::env::args;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::{fs, io};

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rencfs::crypto;
use rencfs::crypto::writer::CryptoWriter;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::FsError;

#[tokio::main]
async fn main() -> Result<()> {
    let cipher = Cipher::ChaCha20;
    let key = Arc::new(get_key(cipher)?);

    let mut args = args();
    let _ = args.next(); // skip the program name
    let path_in = args.next().expect("path_in is missing");
    let path_out = format!(
        "/tmp/{}.enc",
        Path::new(&path_in).file_name().unwrap().to_str().unwrap()
    );
    let out = Path::new(&path_out).to_path_buf();
    if out.exists() {
        fs::remove_file(&out)?;
    }

    // copy
    let mut file_in = File::open(path_in)?;
    let file_out = File::create(path_out.clone())?;
    let mut writer = crypto::create_writer(file_out, cipher, key.clone());
    io::copy(&mut file_in, &mut writer)?;
    writer.flush()?;
    writer.finish()?;

    // check hash
    let mut reader = crypto::create_reader(File::open(path_out).unwrap(), cipher, key.clone());
    file_in.seek(io::SeekFrom::Start(0))?;
    let hash1 = crypto::hash_reader(&mut file_in)?;
    let hash2 = crypto::hash_reader(&mut reader)?;
    assert_eq!(hash1, hash2);

    Ok(())
}

fn get_key(cipher: Cipher) -> io::Result<SecretVec<u8>> {
    let password = SecretString::new("pass42".to_string());
    let salt = crypto::hash_secret_string(&password);

    // get key from location, useful to debug in existing data dir
    let derived_key = crypto::derive_key(&password, cipher, salt).unwrap();
    let reader = crypto::create_reader(
        File::open("/home/gnome/rencfs_data/security/key.enc").unwrap(),
        cipher,
        Arc::new(derived_key),
    );
    let key_store: KeyStore = bincode::deserialize_from(reader).unwrap();
    // check hash
    if key_store.hash != crypto::hash(key_store.key.expose_secret()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid password",
        ));
    }
    Ok(key_store.key)
}

fn key_serialize<S>(key: &SecretVec<u8>, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.collect_seq(key.expose_secret())
}

fn key_unserialize<'de, D>(deserializer: D) -> std::result::Result<SecretVec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::deserialize(deserializer)?;
    Ok(SecretVec::new(vec))
}

#[derive(Serialize, Deserialize)]
struct KeyStore {
    #[serde(serialize_with = "key_serialize")]
    #[serde(deserialize_with = "key_unserialize")]
    key: SecretVec<u8>,
    hash: [u8; 32],
}
